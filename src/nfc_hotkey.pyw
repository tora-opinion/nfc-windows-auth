"""
NFC Login with Hotkey Trigger
=============================

Runs in system tray (invisible).
Press Ctrl+Alt+N to trigger NFC login.
Very lightweight - only activates on hotkey.

Author: Generated with Claude Code
License: MIT
"""

import os
import sys
import ctypes
import ctypes.wintypes as wintypes
import threading
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nfc_login import NFCLogin

# Hotkey constants
MOD_ALT = 0x0001
MOD_CONTROL = 0x0002
MOD_NOREPEAT = 0x4000
VK_N = 0x4E
HOTKEY_ID = 1

user32 = ctypes.windll.user32


def run_nfc_login():
    """Run NFC login in separate thread"""
    try:
        login = NFCLogin()
        if login.password and login.config.get('registered_cards'):
            print("Waiting for iPhone...")
            login.run()
    except Exception as e:
        print(f"Error: {e}")


def main():
    # Register hotkey: Ctrl+Alt+N
    if not user32.RegisterHotKey(None, HOTKEY_ID, MOD_CONTROL | MOD_ALT | MOD_NOREPEAT, VK_N):
        print("Failed to register hotkey (already running?)")
        return

    print("NFC Login Hotkey Active")
    print("Press Ctrl+Alt+N to trigger NFC login")
    print("Press Ctrl+C to exit")

    try:
        msg = wintypes.MSG()
        while True:
            # Check for hotkey message
            if user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):  # PM_REMOVE
                if msg.message == 0x0312:  # WM_HOTKEY
                    print("\nHotkey pressed! Starting NFC login...")
                    # Run in thread so hotkey keeps working
                    t = threading.Thread(target=run_nfc_login, daemon=True)
                    t.start()
            time.sleep(0.1)

    except KeyboardInterrupt:
        pass
    finally:
        user32.UnregisterHotKey(None, HOTKEY_ID)
        print("\nHotkey unregistered")


if __name__ == '__main__':
    main()
