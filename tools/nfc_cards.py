"""Administrator CLI for registering and managing NFC cards."""

import argparse
import ctypes
import sys
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / 'src'
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from nfc_common import find_libusb
from nfc_store import (
    add_card,
    idm_mac,
    load_cards,
    load_key,
    load_settings,
    remove_card,
)
from rcs300 import RCS300, ReaderError


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _require_admin():
    if not _is_admin():
        raise PermissionError('Run this command from an elevated prompt')


def _register(name: str, windows_user, timeout_sec: float):
    if timeout_sec <= 0:
        raise ValueError('--timeout must be greater than zero')

    settings = load_settings()
    libusb_path = find_libusb(settings, REPO_ROOT)
    if not libusb_path:
        raise RuntimeError('libusb was not found')
    key = load_key()
    reader = RCS300(libusb_path)
    session_active = False
    deadline = time.monotonic() + timeout_sec
    try:
        reader.open()
        reader.start_session()
        session_active = True
        while time.monotonic() < deadline:
            result = reader.poll_express_card(timeout_ms=250)
            if result:
                idm, _pmm = result
                mac = idm_mac(idm, key)
                add_card(mac, name, windows_user)
                return mac
            time.sleep(0.05)
        raise TimeoutError('No card was detected before the timeout')
    finally:
        if session_active:
            try:
                reader.end_session()
            except ReaderError:
                pass
        reader.close()


def _print_cards():
    cards = load_cards()

    def sort_key(item):
        card = item[1]
        return str(card.get('name', '')).casefold() if isinstance(card, dict) else ''

    for mac, card in sorted(cards.items(), key=sort_key):
        if not isinstance(card, dict):
            continue
        name = str(card.get('name', ''))
        user = card.get('windows_user') or ''
        registered_at = card.get('registered_at') or ''
        print(f'{name}\t{user}\t{registered_at}\t{mac[:8]}')


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Manage NFC card registrations')
    subparsers = parser.add_subparsers(dest='command', required=True)

    register_parser = subparsers.add_parser('register')
    register_parser.add_argument('--name', required=True)
    register_parser.add_argument('--windows-user')
    register_parser.add_argument('--timeout', type=float, default=30)

    subparsers.add_parser('list')

    remove_parser = subparsers.add_parser('remove')
    remove_parser.add_argument('--name', required=True)

    args = parser.parse_args(argv)
    try:
        _require_admin()
        if args.command == 'register':
            mac = _register(args.name, args.windows_user, args.timeout)
            print(f'{args.name}\t{mac[:8]}')
        elif args.command == 'list':
            _print_cards()
        elif args.command == 'remove':
            if remove_card(args.name):
                print(args.name)
            else:
                print(f'Not found: {args.name}', file=sys.stderr)
                return 1
        return 0
    except (PermissionError, ReaderError, RuntimeError, TimeoutError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
