"""
NFC Login - Simple Startup Unlock
=================================

Runs at Windows startup/login screen.
Waits for registered iPhone Express Card, then unlocks.
Exits after successful authentication.

Usage:
  1. python nfc_login.py setup     - Store password and register card
  2. python nfc_login.py install   - Add to Windows startup
  3. Reboot and place iPhone on reader to login!

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
import getpass
import subprocess
from pathlib import Path
from typing import Optional

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nfc_common import idm_preview, next_backoff_delay
from rcs300 import RCS300, ReaderError

# Paths
BASE_DIR = Path(__file__).parent.parent
CONFIG_FILE = BASE_DIR / 'config.json'
CRED_FILE = BASE_DIR / '.credentials.enc'


class NFCLogin:
    """Simple NFC Login for Windows"""

    def __init__(self):
        self.config = self._load_config()
        self.password = self._load_password()

    def _load_config(self) -> dict:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        return {'registered_cards': {}}

    def _save_config(self):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=2)

    def _load_password(self) -> Optional[str]:
        if CRED_FILE.exists():
            try:
                with open(CRED_FILE, 'rb') as f:
                    data = f.read()
                key = b'nfc-auth-2024-key'
                return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))]).decode('utf-8')
            except:
                pass
        return None

    def _save_password(self, password: str):
        key = b'nfc-auth-2024-key'
        encoded = bytes([ord(password[i]) ^ key[i % len(key)] for i in range(len(password))])
        with open(CRED_FILE, 'wb') as f:
            f.write(encoded)

    def _hash_idm(self, idm: bytes) -> str:
        return hashlib.sha256(idm).hexdigest()

    def _copy_to_clipboard(self, text: str):
        """Copy text to clipboard"""
        CF_UNICODETEXT = 13
        kernel32 = ctypes.windll.kernel32
        user32 = ctypes.windll.user32

        user32.OpenClipboard(0)
        user32.EmptyClipboard()

        # Allocate global memory
        text_bytes = (text + '\0').encode('utf-16-le')
        h_mem = kernel32.GlobalAlloc(0x0042, len(text_bytes))  # GMEM_MOVEABLE | GMEM_ZEROINIT
        p_mem = kernel32.GlobalLock(h_mem)
        ctypes.memmove(p_mem, text_bytes, len(text_bytes))
        kernel32.GlobalUnlock(h_mem)

        user32.SetClipboardData(CF_UNICODETEXT, h_mem)
        user32.CloseClipboard()

    def _find_libusb(self) -> Optional[str]:
        paths = [
            BASE_DIR / 'daemon' / 'libusb-1.0.dll',
            BASE_DIR / 'src' / 'libusb-1.0.dll',
        ]
        for p in paths:
            if p.exists():
                return str(p)
        return None

    def _type_string(self, text: str):
        """Type string using SendInput"""
        INPUT_KEYBOARD = 1
        KEYEVENTF_UNICODE = 0x0004
        KEYEVENTF_KEYUP = 0x0002

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

        user32 = ctypes.windll.user32

        for char in text:
            inputs = (INPUT * 2)()

            # Key down
            inputs[0].type = INPUT_KEYBOARD
            inputs[0].ki.wVk = 0
            inputs[0].ki.wScan = ord(char)
            inputs[0].ki.dwFlags = KEYEVENTF_UNICODE
            inputs[0].ki.time = 0
            inputs[0].ki.dwExtraInfo = None

            # Key up
            inputs[1].type = INPUT_KEYBOARD
            inputs[1].ki.wVk = 0
            inputs[1].ki.wScan = ord(char)
            inputs[1].ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP
            inputs[1].ki.time = 0
            inputs[1].ki.dwExtraInfo = None

            user32.SendInput(2, ctypes.byref(inputs), ctypes.sizeof(INPUT))
            time.sleep(0.01)

    def _press_enter(self):
        """Press Enter key"""
        INPUT_KEYBOARD = 1
        KEYEVENTF_KEYUP = 0x0002
        VK_RETURN = 0x0D

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

        user32 = ctypes.windll.user32
        inputs = (INPUT * 2)()

        inputs[0].type = INPUT_KEYBOARD
        inputs[0].ki.wVk = VK_RETURN
        inputs[0].ki.dwFlags = 0

        inputs[1].type = INPUT_KEYBOARD
        inputs[1].ki.wVk = VK_RETURN
        inputs[1].ki.dwFlags = KEYEVENTF_KEYUP

        user32.SendInput(2, ctypes.byref(inputs), ctypes.sizeof(INPUT))

    def _play_sound(self):
        """Play notification sound"""
        import winsound
        # Play system asterisk sound
        winsound.PlaySound("SystemAsterisk", winsound.SND_ALIAS | winsound.SND_ASYNC)

    def unlock(self):
        """Copy password to clipboard and notify user"""
        if not self.password:
            print("No password stored!")
            return False

        print("NFC Authenticated!")

        # Copy password to clipboard
        self._copy_to_clipboard(self.password)

        # Play sound to notify
        self._play_sound()

        print("=" * 40)
        print("Password copied to clipboard!")
        print("On lock screen: Ctrl+V → Enter")
        print("=" * 40)

        return True

    def setup(self):
        """Interactive setup"""
        print("=== NFC Login Setup ===")
        print()

        # 1. Store password
        print("Step 1: Store your Windows password")
        password = getpass.getpass("Enter password: ")
        confirm = getpass.getpass("Confirm password: ")

        if password != confirm:
            print("Passwords don't match!")
            return False

        self._save_password(password)
        self.password = password
        print("Password stored!")
        print()

        # 2. Register card
        print("Step 2: Register your iPhone")
        print("Place iPhone on RC-S300...")

        libusb = self._find_libusb()
        if not libusb:
            print("libusb-1.0.dll not found!")
            return False

        reader = RCS300(libusb)
        try:
            reader.open()
        except ReaderError as error:
            print(f"Failed to open RC-S300: {error}")
            return False

        session_active = False
        try:
            reader.start_session()
            session_active = True

            for i in range(50):
                result = reader.poll_express_card(timeout_ms=100)
                if result:
                    idm, pmm = result
                    idm_hash = self._hash_idm(idm)
                    idm_hex = idm.hex().upper()

                    self.config['registered_cards'][idm_hash] = {
                        'name': 'iPhone',
                        'idm_preview': idm_hex[:8] + '...',
                    }
                    self._save_config()

                    print(f"\nCard registered!")
                    print(f"  IDm: {idm_hex}")
                    break
                print(".", end="", flush=True)
                time.sleep(0.1)
            else:
                print("\nTimeout - no card detected")
                return False

        except ReaderError as error:
            print(f"\nReader error: {error}")
            return False

        finally:
            try:
                if session_active:
                    reader.end_session()
            except ReaderError:
                pass
            reader.close()

        print()
        print("Setup complete!")
        print("Run 'python nfc_login.py install' to add to startup")
        return True

    def install_startup(self):
        """Add to Windows startup"""
        startup_folder = Path(os.environ['APPDATA']) / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup'

        # Create VBS wrapper (runs hidden)
        vbs_path = startup_folder / 'nfc_login.vbs'
        script_path = Path(__file__).absolute()
        python_path = sys.executable

        vbs_content = f'''Set WshShell = CreateObject("WScript.Shell")
WshShell.Run """{python_path}"" ""{script_path}"" run", 0, False
'''
        with open(vbs_path, 'w') as f:
            f.write(vbs_content)

        print(f"Installed to: {vbs_path}")
        print("NFC Login will run at startup!")

    def uninstall_startup(self):
        """Remove from Windows startup"""
        startup_folder = Path(os.environ['APPDATA']) / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup'
        vbs_path = startup_folder / 'nfc_login.vbs'

        if vbs_path.exists():
            vbs_path.unlink()
            print("Removed from startup")
        else:
            print("Not installed")

    def run(self):
        """Wait for card and unlock (run once)"""
        if not self.password:
            print("No password stored! Run 'setup' first.")
            return

        if not self.config.get('registered_cards'):
            print("No cards registered! Run 'setup' first.")
            return

        libusb = self._find_libusb()
        if not libusb:
            print("libusb-1.0.dll not found!")
            return

        reader = RCS300(libusb)
        try:
            reader.open()
        except ReaderError as error:
            print(f"Failed to open RC-S300: {error}")
            return

        print("Waiting for iPhone...")

        session_active = False
        reconnect_delay = None

        try:
            while True:
                try:
                    if reader.dev is None:
                        reader.open()
                    if not session_active:
                        reader.start_session()
                        session_active = True
                    result = reader.poll_express_card(timeout_ms=100)
                    reconnect_delay = None
                except ReaderError as error:
                    # Keep the long-running loop alive across USB hiccups / unplug
                    print(f"Reader error: {error}")
                    session_active = False
                    reader.close()
                    reconnect_delay = next_backoff_delay(reconnect_delay)
                    time.sleep(reconnect_delay)
                    continue

                if result:
                    idm, pmm = result
                    idm_hash = self._hash_idm(idm)

                    if idm_hash in self.config.get('registered_cards', {}):
                        print(f"Authenticated (IDm SHA-256: {idm_preview(idm)})")

                        # Wait a moment for lock screen to be ready
                        time.sleep(0.5)

                        # Unlock!
                        self.unlock()

                        # Exit after unlock
                        break
                    else:
                        print(f"Unknown card (IDm SHA-256: {idm_preview(idm)})")

                time.sleep(0.1)

        finally:
            try:
                if session_active:
                    reader.end_session()
            except ReaderError:
                pass
            reader.close()

        print("Done!")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='NFC Login for Windows')
    parser.add_argument('command', choices=['setup', 'install', 'uninstall', 'run', 'test'],
                        nargs='?', default='run',
                        help='Command (default: run)')

    args = parser.parse_args()

    login = NFCLogin()

    if args.command == 'setup':
        login.setup()
    elif args.command == 'install':
        login.install_startup()
    elif args.command == 'uninstall':
        login.uninstall_startup()
    elif args.command == 'run':
        login.run()
    elif args.command == 'test':
        print(f"Password stored: {login.password is not None}")
        print(f"Cards registered: {len(login.config.get('registered_cards', {}))}")

        if login.password:
            confirm = input("Test unlock now? (y/n): ").lower()
            if confirm == 'y':
                print("Unlocking in 3 seconds...")
                time.sleep(3)
                login.unlock()


if __name__ == '__main__':
    main()
