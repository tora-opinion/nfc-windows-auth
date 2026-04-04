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
import json
import hashlib
from pathlib import Path
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rcs300 import RCS300

# Paths
BASE_DIR = Path(__file__).parent.parent
CONFIG_FILE = BASE_DIR / 'config.json'
SIGNAL_FILE = BASE_DIR / '.nfc_auth_signal'


class NFCDaemonService:
    """NFC monitoring daemon for Credential Provider integration"""

    def __init__(self):
        self.config = self._load_config()
        self.reader = None
        self.running = False

    def _load_config(self) -> dict:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        return {'registered_cards': {}}

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

    def _write_signal(self):
        """Write signal file for Credential Provider"""
        SIGNAL_FILE.write_text(f"authenticated:{time.time()}")
        print(f"Signal written: {SIGNAL_FILE}")

    def _clear_signal(self):
        """Clear signal file"""
        if SIGNAL_FILE.exists():
            SIGNAL_FILE.unlink()

    def run(self):
        """Main daemon loop"""
        print("NFC Daemon Service starting...")

        libusb = self._find_libusb()
        if not libusb:
            print("ERROR: libusb not found!")
            return

        if not self.config.get('registered_cards'):
            print("ERROR: No cards registered!")
            return

        self.reader = RCS300(libusb)
        if not self.reader.open():
            print("ERROR: Failed to open RC-S300")
            return

        print("RC-S300 opened")
        print(f"Registered cards: {len(self.config['registered_cards'])}")
        print("Monitoring for NFC cards...")

        self.running = True
        session_active = False
        last_auth_time = 0
        cooldown = 5  # seconds

        try:
            while self.running:
                try:
                    if not session_active:
                        self.reader.start_session()
                        session_active = True

                    result = self.reader.poll_express_card(timeout_ms=100)

                    if result:
                        idm, pmm = result
                        idm_hash = self._hash_idm(idm)

                        if idm_hash in self.config.get('registered_cards', {}):
                            current_time = time.time()
                            if current_time - last_auth_time > cooldown:
                                print(f"Authenticated: {idm.hex().upper()}")
                                self._write_signal()
                                last_auth_time = current_time
                        else:
                            print(f"Unknown card: {idm.hex().upper()}")

                    time.sleep(0.1)

                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"Error: {e}")
                    session_active = False
                    time.sleep(1)

        finally:
            if session_active:
                self.reader.end_session()
            self.reader.close()
            print("Daemon stopped")

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
