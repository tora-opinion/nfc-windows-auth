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

from nfc_common import find_libusb, hash_idm, load_config, log_idm, setup_logging
from rcs300 import RCS300

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
    try:
        reader.open()
    except Exception as error:
        logger.error("Failed to open RC-S300: %s", error)
        return

    logger.info("RC-S300 ready. Waiting for NFC card...")

    session_active = False
    try:
        reader.start_session()
        session_active = True
        timeout = config.get('lock_timeout_sec', config.get('timeout_sec', 60))
        start_time = time.time()

        while time.time() - start_time < timeout:
            result = reader.poll_express_card(timeout_ms=500)

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
        logger.error("Reader error: %s", error)
    finally:
        try:
            if session_active:
                reader.end_session()
        finally:
            reader.close()
            logger.info("Done.")


if __name__ == '__main__':
    main()
