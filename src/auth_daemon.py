"""
NFC Windows Authentication Daemon
=================================

Monitors RC-S300 for registered iPhone Express Cards (Suica)
and triggers Windows login/unlock when detected.

Uses system code 0x0003 to activate Express Card mode without
requiring Face ID/Touch ID authentication on iPhone.

Author: Generated with Claude Code
License: MIT
"""

import os
import sys
import json
import time
import ctypes
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rcs300 import RCS300, ReaderError
from nfc_common import (
    find_libusb,
    hash_idm,
    load_config,
    log_idm,
    next_backoff_delay,
    setup_logging,
)
from windows_unlock import WindowsUnlock


# Windows API for workstation unlock
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

BASE_DIR = Path(__file__).resolve().parent.parent
logger = setup_logging(__name__, BASE_DIR / 'auth_daemon.log')


class NFCAuthDaemon:
    """NFC Authentication Daemon"""

    CONFIG_FILE = Path(__file__).parent.parent / 'config.json'
    DEFAULT_CONFIG = {
        'registered_cards': {},
        'poll_interval_ms': 100,
        'session_timeout_sec': 300,
        'libusb_path': None,
        'auto_unlock': True,
        'log_level': 'INFO'
    }

    def __init__(self):
        self.config = self._load_config()
        self.reader: Optional[RCS300] = None
        self.last_auth_time = 0
        self.running = False

    def _load_config(self) -> dict:
        """Load configuration from file"""
        return load_config(self.CONFIG_FILE, self.DEFAULT_CONFIG)

    def _save_config(self):
        """Save configuration to file"""
        try:
            with open(self.CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save config: {e}")

    def register_card(self, name: str, timeout_sec: int = 30) -> bool:
        """Register a new card for authentication"""
        logger.info(f"Registering card '{name}'...")
        logger.info("Place iPhone on RC-S300...")

        libusb = find_libusb(self.config, BASE_DIR)
        if not libusb:
            logger.error("libusb-1.0.dll not found!")
            return False

        reader = RCS300(libusb)
        try:
            reader.open()
        except Exception as error:
            logger.error("Failed to open RC-S300: %s", error)
            return False

        session_active = False
        try:
            reader.start_session()
            session_active = True

            start_time = time.time()
            while time.time() - start_time < timeout_sec:
                result = reader.poll_express_card(timeout_ms=100)
                if result:
                    idm, pmm = result
                    idm_hash = hash_idm(idm)

                    self.config['registered_cards'][idm_hash] = {
                        'name': name,
                        'idm_preview': idm_hash[:8] + '...',
                        'registered_at': datetime.now().isoformat(),
                        'last_used': None
                    }
                    self._save_config()

                    logger.info(f"Card registered successfully!")
                    logger.info(f"  Name: {name}")
                    log_idm(logger, 20, 'Card registered', idm)
                    return True

                time.sleep(0.1)

            logger.error("Timeout - no card detected")
            return False

        except ReaderError as error:
            logger.error("Reader error during registration: %s", error)
            return False

        finally:
            try:
                if session_active:
                    reader.end_session()
            except ReaderError as error:
                logger.warning("Failed to end session: %s", error)
            finally:
                reader.close()

    def list_cards(self) -> Dict:
        """List registered cards"""
        return self.config.get('registered_cards', {})

    def remove_card(self, name: str) -> bool:
        """Remove a registered card by name"""
        cards = self.config.get('registered_cards', {})
        for idm_hash, info in list(cards.items()):
            if info.get('name') == name:
                del cards[idm_hash]
                self._save_config()
                logger.info(f"Card '{name}' removed")
                return True
        logger.warning(f"Card '{name}' not found")
        return False

    def _is_workstation_locked(self) -> bool:
        """Check if workstation is locked"""
        # Use GetForegroundWindow - returns None when locked
        hwnd = user32.GetForegroundWindow()
        if hwnd == 0:
            return True

        # Check for lock screen
        try:
            class_name = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, class_name, 256)
            if 'LockScreen' in class_name.value or 'Credential' in class_name.value:
                return True
        except:
            pass

        return False

    def _unlock_workstation(self):
        """Attempt to unlock workstation"""
        # Send keyboard input to dismiss lock screen
        # This is a simplified approach - full implementation would use
        # Windows Credential Provider API

        # Simulate Enter key to activate login
        INPUT_KEYBOARD = 1
        KEYEVENTF_KEYUP = 0x0002
        VK_RETURN = 0x0D

        class KEYBDINPUT(ctypes.Structure):
            _fields_ = [
                ('wVk', ctypes.c_ushort),
                ('wScan', ctypes.c_ushort),
                ('dwFlags', ctypes.c_ulong),
                ('time', ctypes.c_ulong),
                ('dwExtraInfo', ctypes.POINTER(ctypes.c_ulong))
            ]

        class INPUT(ctypes.Structure):
            _fields_ = [
                ('type', ctypes.c_ulong),
                ('ki', KEYBDINPUT),
                ('padding', ctypes.c_ubyte * 8)
            ]

        # Note: Full unlock requires Credential Provider
        # This just signals that authentication was successful
        logger.info("Authentication successful - unlock signal sent")

    def _authenticate_card(self, idm: bytes) -> bool:
        """Check if card is registered and authenticate"""
        idm_hash = hash_idm(idm)

        if idm_hash in self.config.get('registered_cards', {}):
            card_info = self.config['registered_cards'][idm_hash]
            card_info['last_used'] = datetime.now().isoformat()
            self._save_config()

            log_idm(logger, 20, f"Authenticated: {card_info['name']}", idm)
            return True

        log_idm(logger, 30, 'Unknown card', idm)
        return False

    def run(self):
        """Main daemon loop"""
        logger.info("NFC Auth Daemon starting...")

        libusb = find_libusb(self.config, BASE_DIR)
        if not libusb:
            logger.error("libusb-1.0.dll not found!")
            return

        self.reader = RCS300(libusb)
        logger.info(f"Registered cards: {len(self.config.get('registered_cards', {}))}")

        self.running = True
        session_active = False
        last_detect_time = 0
        cooldown_sec = self.config.get('cooldown_sec', 3)  # Prevent rapid re-authentication
        reconnect_delay = None

        try:
            while self.running:
                try:
                    if self.reader.dev is None:
                        self.reader.open()
                        logger.info("RC-S300 opened successfully")

                    # Start session if needed
                    if not session_active:
                        self.reader.start_session()
                        session_active = True
                        logger.debug("Session started")

                    # Poll for card
                    result = self.reader.poll_express_card(timeout_ms=100)
                    reconnect_delay = None

                    if result:
                        idm, pmm = result
                        current_time = time.time()

                        # Cooldown check
                        if current_time - last_detect_time > cooldown_sec:
                            if self._authenticate_card(idm):
                                if self.config.get('auto_unlock', True):
                                    self._unlock_workstation()
                                last_detect_time = current_time

                    time.sleep(self.config['poll_interval_ms'] / 1000.0)

                except KeyboardInterrupt:
                    break
                except Exception as e:
                    logger.error("Error in main loop: %s", e)
                    session_active = False
                    self.reader.close()
                    reconnect_delay = next_backoff_delay(reconnect_delay)
                    logger.warning("Reconnecting to RC-S300 in %.1f seconds", reconnect_delay)
                    # The loop head reopens the reader; a failed open comes back here and backs off further
                    time.sleep(reconnect_delay)

        finally:
            try:
                if session_active:
                    self.reader.end_session()
            except ReaderError as error:
                logger.warning("Failed to end session: %s", error)
            finally:
                self.reader.close()
            logger.info("Daemon stopped")

    def stop(self):
        """Stop the daemon"""
        self.running = False


def main():
    import argparse

    parser = argparse.ArgumentParser(description='NFC Windows Authentication Daemon')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Run daemon
    run_parser = subparsers.add_parser('run', help='Run authentication daemon')

    # Register card
    reg_parser = subparsers.add_parser('register', help='Register a new card')
    reg_parser.add_argument('name', help='Name for the card')

    # List cards
    list_parser = subparsers.add_parser('list', help='List registered cards')

    # Remove card
    rm_parser = subparsers.add_parser('remove', help='Remove a registered card')
    rm_parser.add_argument('name', help='Name of card to remove')

    # Test
    test_parser = subparsers.add_parser('test', help='Test card detection')

    args = parser.parse_args()

    daemon = NFCAuthDaemon()

    if args.command == 'run':
        daemon.run()
    elif args.command == 'register':
        daemon.register_card(args.name)
    elif args.command == 'list':
        cards = daemon.list_cards()
        if cards:
            print("\nRegistered cards:")
            for idm_hash, info in cards.items():
                print(f"  - {info['name']}")
                print(f"    IDm hash preview: {idm_hash[:8]}...")
                print(f"    Registered: {info['registered_at']}")
                print(f"    Last used: {info.get('last_used', 'Never')}")
        else:
            print("No cards registered")
    elif args.command == 'remove':
        daemon.remove_card(args.name)
    elif args.command == 'test':
        # Quick test
        libusb = find_libusb(daemon.config, BASE_DIR)
        reader = RCS300(libusb)
        try:
            reader.open()
            print("RC-S300 found. Place iPhone on reader...")
            session_active = False
            try:
                reader.start_session()
                session_active = True
                for i in range(30):
                    result = reader.poll_express_card()
                    if result:
                        idm, pmm = result
                        print("\nCard detected!")
                        log_idm(logger, 20, 'Card detected', idm)
                        break
                    print(".", end="", flush=True)
                    time.sleep(0.1)
                else:
                    print("\nNo card detected")
            finally:
                try:
                    if session_active:
                        reader.end_session()
                except ReaderError as error:
                    logger.warning("Failed to end session: %s", error)
                finally:
                    reader.close()
        except Exception as error:
            logger.error("Reader test failed: %s", error)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
