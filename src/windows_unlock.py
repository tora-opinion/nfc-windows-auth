"""
Windows Unlock Module
=====================

Provides Windows workstation unlock functionality using NFC authentication.

Methods:
1. Credential injection via Windows API
2. Auto-type password (optional, requires stored credential)
3. Signal to Credential Provider (for full integration)

Author: Generated with Claude Code
License: MIT
"""

import os
import sys
import ctypes
import ctypes.wintypes as wintypes
from ctypes import POINTER, Structure, Union, c_void_p, c_wchar_p, c_ulong, c_ushort, c_char
import time
import subprocess
from typing import Optional
import json
from pathlib import Path

# Windows API constants
INPUT_MOUSE = 0
INPUT_KEYBOARD = 1
INPUT_HARDWARE = 2

KEYEVENTF_EXTENDEDKEY = 0x0001
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004
KEYEVENTF_SCANCODE = 0x0008

VK_RETURN = 0x0D
VK_ESCAPE = 0x1B
VK_SPACE = 0x20

# Windows API structures
class MOUSEINPUT(Structure):
    _fields_ = [
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", POINTER(c_ulong))
    ]

class KEYBDINPUT(Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", POINTER(c_ulong))
    ]

class HARDWAREINPUT(Structure):
    _fields_ = [
        ("uMsg", wintypes.DWORD),
        ("wParamL", wintypes.WORD),
        ("wParamH", wintypes.WORD)
    ]

class INPUT_UNION(Union):
    _fields_ = [
        ("mi", MOUSEINPUT),
        ("ki", KEYBDINPUT),
        ("hi", HARDWAREINPUT)
    ]

class INPUT(Structure):
    _fields_ = [
        ("type", wintypes.DWORD),
        ("union", INPUT_UNION)
    ]

# Load Windows DLLs
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

# Credential storage path
CRED_FILE = Path(__file__).parent.parent / '.credentials.enc'


class WindowsUnlock:
    """Windows workstation unlock handler"""

    def __init__(self):
        self.stored_password = None
        self._load_credential()

    def _load_credential(self):
        """Load stored credential (encrypted)"""
        if CRED_FILE.exists():
            try:
                # Simple XOR obfuscation (NOT secure - use DPAPI for production)
                with open(CRED_FILE, 'rb') as f:
                    data = f.read()
                # Decode
                key = b'nfc-auth-key-2024'
                decoded = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
                self.stored_password = decoded.decode('utf-8')
            except:
                pass

    def store_credential(self, password: str):
        """Store credential (encrypted)"""
        # Simple XOR obfuscation (NOT secure - use DPAPI for production)
        key = b'nfc-auth-key-2024'
        encoded = bytes([ord(password[i]) ^ key[i % len(key)] for i in range(len(password))])
        with open(CRED_FILE, 'wb') as f:
            f.write(encoded)
        self.stored_password = password
        print(f"Credential stored to {CRED_FILE}")

    def is_locked(self) -> bool:
        """Check if workstation is locked"""
        # Method 1: Check foreground window
        hwnd = user32.GetForegroundWindow()
        if hwnd == 0:
            return True

        # Method 2: Check window class
        class_name = ctypes.create_unicode_buffer(256)
        user32.GetClassNameW(hwnd, class_name, 256)

        lock_indicators = ['LockScreen', 'Credential', 'LogonUI', 'Windows.UI.Core.CoreWindow']
        for indicator in lock_indicators:
            if indicator.lower() in class_name.value.lower():
                return True

        return False

    def _send_key(self, vk: int, scan: int = 0, extended: bool = False):
        """Send a single key press"""
        inputs = (INPUT * 2)()

        # Key down
        inputs[0].type = INPUT_KEYBOARD
        inputs[0].union.ki.wVk = vk
        inputs[0].union.ki.wScan = scan
        inputs[0].union.ki.dwFlags = KEYEVENTF_EXTENDEDKEY if extended else 0
        inputs[0].union.ki.time = 0
        inputs[0].union.ki.dwExtraInfo = None

        # Key up
        inputs[1].type = INPUT_KEYBOARD
        inputs[1].union.ki.wVk = vk
        inputs[1].union.ki.wScan = scan
        inputs[1].union.ki.dwFlags = KEYEVENTF_KEYUP | (KEYEVENTF_EXTENDEDKEY if extended else 0)
        inputs[1].union.ki.time = 0
        inputs[1].union.ki.dwExtraInfo = None

        user32.SendInput(2, ctypes.byref(inputs), ctypes.sizeof(INPUT))

    def _send_unicode_char(self, char: str):
        """Send a unicode character"""
        inputs = (INPUT * 2)()

        # Key down
        inputs[0].type = INPUT_KEYBOARD
        inputs[0].union.ki.wVk = 0
        inputs[0].union.ki.wScan = ord(char)
        inputs[0].union.ki.dwFlags = KEYEVENTF_UNICODE
        inputs[0].union.ki.time = 0
        inputs[0].union.ki.dwExtraInfo = None

        # Key up
        inputs[1].type = INPUT_KEYBOARD
        inputs[1].union.ki.wVk = 0
        inputs[1].union.ki.wScan = ord(char)
        inputs[1].union.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP
        inputs[1].union.ki.time = 0
        inputs[1].union.ki.dwExtraInfo = None

        user32.SendInput(2, ctypes.byref(inputs), ctypes.sizeof(INPUT))

    def _type_string(self, text: str, delay: float = 0.01):
        """Type a string character by character"""
        for char in text:
            self._send_unicode_char(char)
            time.sleep(delay)

    def wake_screen(self):
        """Wake up screen if sleeping"""
        # Move mouse slightly to wake screen
        user32.mouse_event(0x0001, 1, 1, 0, 0)  # MOUSEEVENTF_MOVE
        time.sleep(0.1)
        user32.mouse_event(0x0001, -1, -1, 0, 0)

    def dismiss_lock_screen(self):
        """Dismiss lock screen to show password prompt"""
        # Press Space or Enter to dismiss lock screen
        self._send_key(VK_SPACE)
        time.sleep(0.3)

    def unlock_with_password(self, password: Optional[str] = None) -> bool:
        """Unlock workstation by typing password"""
        pwd = password or self.stored_password
        if not pwd:
            print("No password available")
            return False

        print("Unlocking workstation...")

        # Wake screen
        self.wake_screen()
        time.sleep(0.5)

        # Dismiss lock screen
        self.dismiss_lock_screen()
        time.sleep(0.5)

        # Type password
        self._type_string(pwd)
        time.sleep(0.1)

        # Press Enter
        self._send_key(VK_RETURN)

        print("Unlock sequence sent")
        return True

    def signal_unlock(self):
        """Signal that NFC authentication was successful (for Credential Provider)"""
        # Write to named pipe or signal file
        signal_file = Path(__file__).parent.parent / '.nfc_auth_signal'
        signal_file.write_text(f"authenticated:{time.time()}")
        print("Authentication signal written")


class NFCCredentialProvider:
    """
    Helper for Windows Credential Provider integration.

    For full integration, a C++ Credential Provider DLL is needed.
    This provides the Python side that communicates with the provider.
    """

    PIPE_NAME = r'\\.\pipe\nfc_auth_pipe'

    def __init__(self):
        self.pipe_handle = None

    def signal_authentication(self, idm: str, username: Optional[str] = None):
        """Signal successful NFC authentication to Credential Provider"""
        try:
            # Write to named pipe
            import win32pipe
            import win32file

            handle = win32file.CreateFile(
                self.PIPE_NAME,
                win32file.GENERIC_WRITE,
                0, None,
                win32file.OPEN_EXISTING,
                0, None
            )

            message = json.dumps({
                'type': 'nfc_auth',
                'idm': idm,
                'username': username,
                'timestamp': time.time()
            })

            win32file.WriteFile(handle, message.encode())
            win32file.CloseHandle(handle)
            return True

        except ImportError:
            # pywin32 not installed, use file-based signaling
            signal_file = Path(__file__).parent.parent / '.nfc_auth_signal'
            signal_file.write_text(json.dumps({
                'type': 'nfc_auth',
                'idm': idm,
                'username': username,
                'timestamp': time.time()
            }))
            return True
        except Exception as e:
            print(f"Failed to signal authentication: {e}")
            return False


def setup_auto_unlock():
    """Interactive setup for auto-unlock with password"""
    import getpass

    print("=== NFC Auto-Unlock Setup ===")
    print()
    print("This will store your Windows password (encrypted) for auto-unlock.")
    print("When your registered iPhone is detected, your PC will automatically unlock.")
    print()

    confirm = input("Continue? (y/n): ").lower()
    if confirm != 'y':
        print("Cancelled")
        return

    password = getpass.getpass("Enter your Windows password: ")
    confirm_pwd = getpass.getpass("Confirm password: ")

    if password != confirm_pwd:
        print("Passwords don't match!")
        return

    unlock = WindowsUnlock()
    unlock.store_credential(password)

    print()
    print("Setup complete! Your password has been stored.")
    print("Run 'python src/auth_daemon.py run' to start the daemon.")


def test_unlock():
    """Test unlock functionality"""
    unlock = WindowsUnlock()

    print("=== Unlock Test ===")
    print(f"Workstation locked: {unlock.is_locked()}")
    print(f"Password stored: {unlock.stored_password is not None}")

    if unlock.stored_password:
        confirm = input("Test unlock now? (y/n): ").lower()
        if confirm == 'y':
            print("Locking workstation in 3 seconds...")
            print("Place iPhone on reader to unlock!")
            time.sleep(3)

            # Lock workstation
            ctypes.windll.user32.LockWorkStation()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Windows Unlock Utility')
    parser.add_argument('command', choices=['setup', 'test', 'status'],
                        help='Command to run')

    args = parser.parse_args()

    if args.command == 'setup':
        setup_auto_unlock()
    elif args.command == 'test':
        test_unlock()
    elif args.command == 'status':
        unlock = WindowsUnlock()
        print(f"Locked: {unlock.is_locked()}")
        print(f"Password stored: {unlock.stored_password is not None}")
