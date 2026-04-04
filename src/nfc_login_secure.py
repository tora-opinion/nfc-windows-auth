"""
NFC Login - Secure Version
==========================

- Uses Windows DPAPI for credential encryption (OS-level security)
- Runs with elevated privileges for lock screen input
- Fully automatic: just place iPhone and unlock!

Author: Generated with Claude Code
License: MIT
"""

import os
import sys
import time
import json
import ctypes
import ctypes.wintypes as wintypes
import hashlib
from pathlib import Path
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rcs300 import RCS300

# Windows DPAPI
crypt32 = ctypes.windll.crypt32
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32

# Paths
BASE_DIR = Path(__file__).parent.parent
CONFIG_FILE = BASE_DIR / 'config.json'
CRED_FILE = BASE_DIR / '.credentials.dpapi'


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', ctypes.POINTER(ctypes.c_char))
    ]


class NFCLoginSecure:
    """Secure NFC Login with DPAPI encryption"""

    def __init__(self):
        self.config = self._load_config()
        self.password = self._load_password_dpapi()

    def _load_config(self) -> dict:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        return {'registered_cards': {}}

    def _save_config(self):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=2)

    def _encrypt_dpapi(self, data: bytes) -> bytes:
        """Encrypt using Windows DPAPI (user-level)"""
        blob_in = DATA_BLOB()
        blob_in.cbData = len(data)
        blob_in.pbData = ctypes.cast(ctypes.create_string_buffer(data, len(data)),
                                      ctypes.POINTER(ctypes.c_char))

        blob_out = DATA_BLOB()

        if crypt32.CryptProtectData(ctypes.byref(blob_in), None, None, None, None, 0,
                                     ctypes.byref(blob_out)):
            encrypted = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            kernel32.LocalFree(blob_out.pbData)
            return encrypted
        return b''

    def _decrypt_dpapi(self, data: bytes) -> bytes:
        """Decrypt using Windows DPAPI"""
        blob_in = DATA_BLOB()
        blob_in.cbData = len(data)
        blob_in.pbData = ctypes.cast(ctypes.create_string_buffer(data, len(data)),
                                      ctypes.POINTER(ctypes.c_char))

        blob_out = DATA_BLOB()

        if crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 0,
                                       ctypes.byref(blob_out)):
            decrypted = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            kernel32.LocalFree(blob_out.pbData)
            return decrypted
        return b''

    def _load_password_dpapi(self) -> Optional[str]:
        """Load password encrypted with DPAPI"""
        if CRED_FILE.exists():
            try:
                with open(CRED_FILE, 'rb') as f:
                    encrypted = f.read()
                decrypted = self._decrypt_dpapi(encrypted)
                if decrypted:
                    return decrypted.decode('utf-8')
            except Exception as e:
                print(f"Failed to load credential: {e}")
        return None

    def _save_password_dpapi(self, password: str):
        """Save password encrypted with DPAPI"""
        encrypted = self._encrypt_dpapi(password.encode('utf-8'))
        if encrypted:
            with open(CRED_FILE, 'wb') as f:
                f.write(encrypted)
            print("Password saved securely with Windows DPAPI")
        else:
            print("Failed to encrypt password!")

    def _hash_idm(self, idm: bytes) -> str:
        return hashlib.sha256(idm).hexdigest()

    def _find_libusb(self) -> Optional[str]:
        paths = [
            BASE_DIR / 'daemon' / 'libusb-1.0.dll',
            BASE_DIR / 'src' / 'libusb-1.0.dll',
        ]
        for p in paths:
            if p.exists():
                return str(p)
        return None

    def _send_input(self, vk: int, scan: int = 0, flags: int = 0):
        """Send keyboard input"""
        INPUT_KEYBOARD = 1

        class KEYBDINPUT(ctypes.Structure):
            _fields_ = [
                ("wVk", wintypes.WORD),
                ("wScan", wintypes.WORD),
                ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD),
                ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))
            ]

        class INPUT(ctypes.Structure):
            _fields_ = [
                ("type", wintypes.DWORD),
                ("ki", KEYBDINPUT),
                ("padding", ctypes.c_ubyte * 8)
            ]

        inputs = (INPUT * 2)()

        # Key down
        inputs[0].type = INPUT_KEYBOARD
        inputs[0].ki.wVk = vk
        inputs[0].ki.wScan = scan
        inputs[0].ki.dwFlags = flags

        # Key up
        inputs[1].type = INPUT_KEYBOARD
        inputs[1].ki.wVk = vk
        inputs[1].ki.wScan = scan
        inputs[1].ki.dwFlags = flags | 0x0002

        user32.SendInput(2, ctypes.byref(inputs), ctypes.sizeof(INPUT))

    def _type_unicode(self, char: str):
        """Type a unicode character"""
        INPUT_KEYBOARD = 1
        KEYEVENTF_UNICODE = 0x0004

        class KEYBDINPUT(ctypes.Structure):
            _fields_ = [
                ("wVk", wintypes.WORD),
                ("wScan", wintypes.WORD),
                ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD),
                ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))
            ]

        class INPUT(ctypes.Structure):
            _fields_ = [
                ("type", wintypes.DWORD),
                ("ki", KEYBDINPUT),
                ("padding", ctypes.c_ubyte * 8)
            ]

        inputs = (INPUT * 2)()

        inputs[0].type = INPUT_KEYBOARD
        inputs[0].ki.wVk = 0
        inputs[0].ki.wScan = ord(char)
        inputs[0].ki.dwFlags = KEYEVENTF_UNICODE

        inputs[1].type = INPUT_KEYBOARD
        inputs[1].ki.wVk = 0
        inputs[1].ki.wScan = ord(char)
        inputs[1].ki.dwFlags = KEYEVENTF_UNICODE | 0x0002

        user32.SendInput(2, ctypes.byref(inputs), ctypes.sizeof(INPUT))

    def unlock(self):
        """Unlock workstation by typing password"""
        if not self.password:
            print("No password stored!")
            return False

        print("Unlocking...")

        # Wake screen
        user32.mouse_event(0x0001, 1, 1, 0, 0)
        time.sleep(0.5)

        # Dismiss lock screen
        self._send_input(0x20)  # Space
        time.sleep(0.5)

        # Type password
        for char in self.password:
            self._type_unicode(char)
            time.sleep(0.02)

        time.sleep(0.1)

        # Press Enter
        self._send_input(0x0D)  # Enter

        print("Unlock complete!")
        return True

    def setup(self):
        """Interactive setup"""
        import getpass

        print("=== NFC Login Secure Setup ===")
        print()
        print("Using Windows DPAPI for secure credential storage.")
        print()

        # 1. Store password
        password = getpass.getpass("Enter Windows password: ")
        confirm = getpass.getpass("Confirm password: ")

        if password != confirm:
            print("Passwords don't match!")
            return False

        self._save_password_dpapi(password)
        self.password = password
        print()

        # 2. Register card
        print("Place iPhone on RC-S300...")

        libusb = self._find_libusb()
        if not libusb:
            print("libusb-1.0.dll not found!")
            return False

        reader = RCS300(libusb)
        if not reader.open():
            print("Failed to open RC-S300")
            return False

        try:
            reader.start_session()

            for i in range(50):
                result = reader.poll_express_card(timeout_ms=100)
                if result:
                    idm, pmm = result
                    idm_hash = self._hash_idm(idm)

                    self.config['registered_cards'][idm_hash] = {
                        'name': 'iPhone',
                        'idm_preview': idm.hex().upper()[:8] + '...',
                    }
                    self._save_config()

                    print(f"\nCard registered: {idm.hex().upper()}")
                    break
                print(".", end="", flush=True)
            else:
                print("\nTimeout")
                return False

        finally:
            reader.end_session()
            reader.close()

        print()
        print("Setup complete!")
        return True

    def run(self):
        """Wait for card and unlock"""
        if not self.password:
            print("No password! Run setup first.")
            return

        if not self.config.get('registered_cards'):
            print("No cards registered! Run setup first.")
            return

        libusb = self._find_libusb()
        if not libusb:
            print("libusb not found!")
            return

        reader = RCS300(libusb)
        if not reader.open():
            print("Failed to open reader")
            return

        print("Waiting for iPhone...")

        try:
            reader.start_session()

            while True:
                result = reader.poll_express_card(timeout_ms=100)
                if result:
                    idm, pmm = result
                    idm_hash = self._hash_idm(idm)

                    if idm_hash in self.config.get('registered_cards', {}):
                        print(f"Authenticated!")
                        time.sleep(0.3)
                        self.unlock()
                        break
                    else:
                        print(f"Unknown card")

                time.sleep(0.1)

        finally:
            reader.end_session()
            reader.close()


def is_admin():
    """Check if running as administrator"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_as_admin():
    """Re-run this script as administrator"""
    if is_admin():
        return True

    script = sys.argv[0]
    params = ' '.join(sys.argv[1:])

    print("Requesting administrator privileges...")
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{script}" {params}', None, 1
    )
    sys.exit(0)


def main():
    import argparse

    parser = argparse.ArgumentParser(description='NFC Login Secure')
    parser.add_argument('command', choices=['setup', 'run', 'test'],
                        nargs='?', default='run')
    parser.add_argument('--no-admin', action='store_true',
                        help='Skip admin elevation')

    args = parser.parse_args()

    # Require admin for run (lock screen input needs it)
    if args.command == 'run' and not args.no_admin and not is_admin():
        run_as_admin()

    login = NFCLoginSecure()

    if args.command == 'setup':
        login.setup()
    elif args.command == 'run':
        login.run()
    elif args.command == 'test':
        print(f"Admin: {is_admin()}")
        print(f"Password: {'Yes' if login.password else 'No'}")
        print(f"Cards: {len(login.config.get('registered_cards', {}))}")


if __name__ == '__main__':
    main()
