"""
NFC Authentication - Lock Screen Only
======================================
Only runs when workstation is locked.
Polls for NFC card, writes signal file, then exits.
Triggered by Task Scheduler on lock event.
"""

import sys
import time
from pathlib import Path

# Add src to path so this also works from a Scheduled Task.
src_path = Path(__file__).resolve().parent / 'src'
sys.path.insert(0, str(src_path))

from nfc_common import (
    find_libusb,
    hash_idm,
    load_config,
    log_idm,
    next_backoff_delay,
    setup_logging,
)
from rcs300 import RCS300, ReaderError

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / 'config.json'
SIGNAL_FILE = BASE_DIR / '.nfc_auth_signal'
logger = setup_logging('nfc_on_lock', BASE_DIR / 'nfc_on_lock.log')


def is_workstation_locked():
    """Check if workstation is still locked."""
    import ctypes
    user32 = ctypes.windll.user32
    # If desktop is not visible, we're likely locked.
    h_desktop = user32.OpenDesktopW("Default", 0, False, 0x0001)
    if h_desktop:
        user32.CloseDesktop(h_desktop)
        return False
    return True


def main():
    logger.info("NFC Lock Screen Auth starting...")

    config = load_config(CONFIG_FILE)
    if not config.get('registered_cards'):
        logger.error("No cards registered!")
        return

    libusb = find_libusb(config, BASE_DIR)
    if not libusb:
        logger.error("libusb not found!")
        return

    reader = RCS300(libusb)
    session_active = False
    reconnect_delay = None
    try:
        timeout = config.get('lock_timeout_sec', config.get('timeout_sec', 60))
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                if reader.dev is None:
                    reader.open()
                    logger.info("RC-S300 ready. Waiting for NFC card...")
                if not session_active:
                    reader.start_session()
                    session_active = True
                result = reader.poll_express_card(timeout_ms=500)
                reconnect_delay = None
            except ReaderError as error:
                # This task fires once per lock event, so retry until the timeout
                logger.warning("Reader error: %s", error)
                session_active = False
                reader.close()
                reconnect_delay = next_backoff_delay(reconnect_delay)
                remaining = timeout - (time.time() - start_time)
                time.sleep(max(0, min(reconnect_delay, remaining)))
                continue

            if result:
                idm, pmm = result
                idm_hash = hash_idm(idm)

                if idm_hash in config.get('registered_cards', {}):
                    log_idm(logger, 20, 'Authenticated', idm)
                    SIGNAL_FILE.write_text(f"authenticated:{time.time()}")
                    logger.info("Signal file written. Login should proceed.")
                    break
                else:
                    log_idm(logger, 30, 'Unknown card', idm)

            time.sleep(0.3)
    except Exception as error:
        logger.error("Unexpected error: %s", error)
    finally:
        try:
            if session_active:
                reader.end_session()
        except ReaderError as error:
            logger.warning("Failed to end session: %s", error)
        finally:
            reader.close()
            logger.info("Done.")


if __name__ == '__main__':
    main()
