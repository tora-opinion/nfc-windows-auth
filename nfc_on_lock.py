"""
NFC Authentication - Lock Screen Only
======================================
Only runs when workstation is locked.
Polls for NFC card, writes signal file, then exits.
Triggered by Task Scheduler on lock event.
"""

import os
import sys
import time
import json
import hashlib
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Add src to path
src_path = Path(__file__).parent / 'src'
sys.path.insert(0, str(src_path))

from rcs300 import RCS300

BASE_DIR = Path(__file__).parent
CONFIG_FILE = BASE_DIR / 'config.json'
SIGNAL_FILE = BASE_DIR / '.nfc_auth_signal'

def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {'registered_cards': {}}

def hash_idm(idm: bytes) -> str:
    return hashlib.sha256(idm).hexdigest()

def find_libusb():
    # Use absolute path for reliability
    return 'C:/Users/suger.G-GEAR/nfc-windows-auth/libusb/VS2022/MS64/dll/libusb-1.0.dll'

def is_workstation_locked():
    """Check if workstation is still locked"""
    import ctypes
    user32 = ctypes.windll.user32
    # If desktop is not visible, we're likely locked
    hDesktop = user32.OpenDesktopW("Default", 0, False, 0x0001)
    if hDesktop:
        user32.CloseDesktop(hDesktop)
        return False
    return True

def main():
    print("NFC Lock Screen Auth starting...")

    config = load_config()
    if not config.get('registered_cards'):
        print("No cards registered!")
        return

    libusb = find_libusb()
    if not libusb:
        print("libusb not found!")
        return

    reader = RCS300(libusb)
    if not reader.open():
        print("Failed to open RC-S300")
        return

    print("RC-S300 ready. Waiting for NFC card...")

    try:
        reader.start_session()
        timeout = 60  # Max 60 seconds polling
        start_time = time.time()

        while time.time() - start_time < timeout:
            # Check if still locked (optional - exit early if unlocked)
            result = reader.poll_express_card(timeout_ms=500)

            if result:
                idm, pmm = result
                idm_hash = hash_idm(idm)

                if idm_hash in config.get('registered_cards', {}):
                    print(f"Authenticated: {idm.hex().upper()}")
                    SIGNAL_FILE.write_text(f"authenticated:{time.time()}")
                    print("Signal file written. Login should proceed.")
                    break
                else:
                    print(f"Unknown card: {idm.hex().upper()}")

            time.sleep(0.3)

        reader.end_session()
    finally:
        reader.close()
        print("Done.")

if __name__ == '__main__':
    main()
