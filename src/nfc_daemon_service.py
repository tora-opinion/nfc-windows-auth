"""
NFC Daemon for Credential Provider
===================================

Runs as a background service, monitoring for NFC cards.
When a registered card is detected, writes a signal file
that the Credential Provider reads to trigger login.

Author: Generated with Claude Code
License: MIT
"""

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nfc_common import (
    find_libusb,
    hash_idm,
    load_config,
    log_idm,
    next_backoff_delay,
    setup_logging,
)
from rcs300 import RCS300

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = BASE_DIR / 'config.json'
SIGNAL_FILE = BASE_DIR / '.nfc_auth_signal'
logger = setup_logging(__name__, BASE_DIR / 'nfc_daemon_service.log')


class NFCDaemonService:
    """NFC monitoring daemon for Credential Provider integration."""

    def __init__(self):
        self.config = load_config(CONFIG_FILE)
        self.reader = None
        self.running = False

    def _write_signal(self):
        """Write signal file for Credential Provider."""
        SIGNAL_FILE.write_text(f"authenticated:{time.time()}")
        logger.info("Signal written: %s", SIGNAL_FILE)

    def _clear_signal(self):
        """Clear signal file."""
        if SIGNAL_FILE.exists():
            SIGNAL_FILE.unlink()

    def run(self):
        """Main daemon loop."""
        logger.info("NFC Daemon Service starting...")

        self.config.setdefault('registered_cards', {})
        libusb = find_libusb(self.config, BASE_DIR)
        if not libusb:
            logger.error("libusb not found!")
            return

        if not self.config.get('registered_cards'):
            logger.error("No cards registered!")
            return

        self.reader = RCS300(libusb)
        logger.info("Registered cards: %d", len(self.config['registered_cards']))
        logger.info("Monitoring for NFC cards...")

        self.running = True
        session_active = False
        last_auth_time = 0
        cooldown = self.config.get('cooldown_sec', 5)  # seconds
        poll_interval = self.config.get('poll_interval_ms', 100) / 1000.0
        reconnect_delay = None

        try:
            while self.running:
                try:
                    if self.reader.dev is None:
                        self.reader.open()
                        logger.info("RC-S300 opened")

                    if not session_active:
                        self.reader.start_session()
                        session_active = True

                    result = self.reader.poll_express_card(timeout_ms=100)
                    reconnect_delay = None

                    if result:
                        idm, pmm = result
                        idm_hash = hash_idm(idm)

                        if idm_hash in self.config.get('registered_cards', {}):
                            current_time = time.time()
                            if current_time - last_auth_time > cooldown:
                                log_idm(logger, 20, 'Authenticated', idm)
                                self._write_signal()
                                last_auth_time = current_time
                        else:
                            log_idm(logger, 30, 'Unknown card', idm)

                    time.sleep(poll_interval)

                except KeyboardInterrupt:
                    break
                except Exception as error:
                    logger.error("Reader error: %s", error)
                    session_active = False
                    self.reader.close()
                    reconnect_delay = next_backoff_delay(reconnect_delay)
                    logger.warning(
                        "Reconnecting to RC-S300 in %.1f seconds", reconnect_delay
                    )
                    # The loop head reopens the reader; a failed open comes back here and backs off further
                    time.sleep(reconnect_delay)

        finally:
            try:
                if session_active:
                    self.reader.end_session()
            finally:
                self.reader.close()
            logger.info("Daemon stopped")

    def stop(self):
        self.running = False


def main():
    import argparse

    parser = argparse.ArgumentParser(description='NFC Daemon Service')
    parser.add_argument('command', choices=['run', 'install', 'uninstall', 'status'],
                        nargs='?', default='run')

    args = parser.parse_args()

    if args.command == 'run':
        daemon = NFCDaemonService()
        daemon.run()

    elif args.command == 'install':
        # Install as Windows service (requires pywin32 or nssm)
        print("Installing as Windows service...")
        print("Use NSSM or sc.exe to create a service:")
        print(f'  nssm install NFCDaemon "{sys.executable}" "{__file__}" run')

    elif args.command == 'status':
        print(f"Signal file exists: {SIGNAL_FILE.exists()}")
        print(f"Config file exists: {CONFIG_FILE.exists()}")


if __name__ == '__main__':
    main()
