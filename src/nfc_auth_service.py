"""Windows service that monitors the RC-S300 and serves one-time tap tokens."""

import logging
import threading
import time
from pathlib import Path

import win32service
import win32serviceutil

from nfc_common import find_libusb, log_idm, next_backoff_delay, setup_logging
from nfc_pipe import PipeServer, PresenceGate, TapState
from nfc_store import (
    ensure_data_dir,
    find_card,
    idm_mac,
    load_cards,
    load_key,
    load_settings,
)
from rcs300 import RCS300, ReaderError


BASE_DIR = Path(__file__).resolve().parent.parent
STOP_JOIN_INTERVAL_SEC = 1
STOP_JOIN_TIMEOUT_SEC = 35
STOP_WAIT_HINT_MS = 10000


class NfcAuthService(win32serviceutil.ServiceFramework):
    """LocalSystem service providing the NFC tap factor to the CP pipe."""

    _svc_name_ = 'NfcAuthService'
    _svc_display_name_ = 'NFC Auth Service'
    _svc_description_ = 'Monitors a Sony RC-S300 reader for registered NFC cards.'
    _svc_start_type_ = win32service.SERVICE_AUTO_START
    # pywin32's default service account is LocalSystem.
    _svc_account_ = None

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = threading.Event()
        self.tap_state = TapState()
        self.pipe_server = None
        self.reader = None
        self.reader_thread = None
        self.reader_thread_lock = threading.Lock()
        self.logger = logging.getLogger(__name__)

    def SvcStop(self):
        checkpoint = 1
        self.ReportServiceStatus(
            win32service.SERVICE_STOP_PENDING,
            waitHint=STOP_WAIT_HINT_MS,
            checkPoint=checkpoint,
        )
        self.stop_event.set()
        if self.pipe_server is not None:
            self.pipe_server.stop()

        with self.reader_thread_lock:
            reader_thread = self.reader_thread
        if reader_thread is None or not reader_thread.is_alive():
            return

        deadline = time.monotonic() + STOP_JOIN_TIMEOUT_SEC
        while reader_thread.is_alive():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.logger.warning('Reader thread did not stop before the deadline')
                return
            reader_thread.join(timeout=min(STOP_JOIN_INTERVAL_SEC, remaining))
            if reader_thread.is_alive():
                checkpoint += 1
                self.ReportServiceStatus(
                    win32service.SERVICE_STOP_PENDING,
                    waitHint=STOP_WAIT_HINT_MS,
                    checkPoint=checkpoint,
                )

    def SvcDoRun(self):
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        with self.reader_thread_lock:
            if self.stop_event.is_set():
                return
            self.reader_thread = threading.Thread(
                target=self.run_service,
                name='NfcAuthReader',
                daemon=True,
            )
            reader_thread = self.reader_thread
            reader_thread.start()
        reader_thread.join()

    def run_service(self):
        """Run the reader reconnect loop and the independent named-pipe listener."""
        if self.stop_event.is_set():
            return
        data_dir = ensure_data_dir()
        self.logger = setup_logging('nfc_auth_service', data_dir / 'service.log')
        key = load_key()
        settings = load_settings()
        cards = load_cards()
        if not cards:
            self.logger.error('No cards registered')
            return

        libusb_path = find_libusb(settings, BASE_DIR)
        if not libusb_path:
            self.logger.error('libusb not found')
            return

        ttl_sec = settings['tap_ttl_sec']
        poll_interval = max(0.02, settings.get('poll_interval_ms', 100) / 1000.0)
        self.tap_state = TapState()
        self.pipe_server = PipeServer(self.tap_state, logger=self.logger)
        self.pipe_server.start()
        self.reader = RCS300(libusb_path)
        presence_gate = PresenceGate()
        self.logger.info('Registered cards: %d', len(cards))
        self.logger.info('Monitoring for NFC cards')

        session_active = False
        reconnect_delay = None

        def reconnect(error):
            nonlocal session_active, reconnect_delay
            self.logger.error('Reader error: %s', error)
            session_active = False
            if not self.stop_event.is_set():
                try:
                    self.reader.close()
                except Exception as close_error:
                    self.logger.warning('Failed to close RC-S300: %s', close_error)
            reconnect_delay = next_backoff_delay(reconnect_delay)
            self.logger.warning(
                'Reconnecting to RC-S300 in %.1f seconds', reconnect_delay
            )
            self.stop_event.wait(reconnect_delay)

        try:
            while not self.stop_event.is_set():
                try:
                    if self.reader.dev is None:
                        self.reader.open()
                        self.logger.info('RC-S300 opened')
                        if self.stop_event.is_set():
                            break

                    if not session_active:
                        self.reader.start_session()
                        session_active = True
                        if self.stop_event.is_set():
                            break

                    result = self.reader.poll_express_card(timeout_ms=100)
                    if self.stop_event.is_set():
                        break
                    reconnect_delay = None
                    now = time.monotonic()
                    should_arm = presence_gate.observe(result is not None, now=now)
                    if result:
                        idm, _pmm = result
                        mac = idm_mac(idm, key)
                        card = find_card(mac)
                        if card:
                            if (
                                should_arm
                                and not self.tap_state.cooldown_active(now=now)
                            ):
                                self.tap_state.set_tap(
                                    card.get('windows_user'), ttl_sec, now=now
                                )
                                log_idm(
                                    self.logger,
                                    logging.INFO,
                                    'Registered card tap',
                                    idm,
                                )
                        else:
                            log_idm(
                                self.logger,
                                logging.WARNING,
                                'Unknown card',
                                idm,
                            )

                    self.stop_event.wait(poll_interval)
                except ReaderError as error:
                    reconnect(error)
                except Exception as error:
                    self.logger.exception('Unexpected error in reader loop')
                    reconnect(error)
        finally:
            try:
                if session_active and not self.stop_event.is_set():
                    try:
                        self.reader.end_session()
                    except Exception as error:
                        self.logger.warning('Failed to end reader session: %s', error)
            finally:
                if self.reader is not None:
                    self.reader.close()
                if self.pipe_server is not None:
                    self.pipe_server.stop()
                    self.pipe_server.join(timeout=2)
                    if self.pipe_server.is_alive():
                        self.logger.warning('Named pipe server did not stop promptly')
            self.logger.info('NFC Auth Service stopped')


if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(NfcAuthService)
