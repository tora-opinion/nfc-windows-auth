"""Administrator CLI for registering and managing NFC cards."""

import argparse
import contextlib
import ctypes
import getpass
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
    clear_credential,
    idm_mac,
    load_cards,
    load_credential_user,
    load_key,
    load_settings,
    remove_card,
    save_credential,
)
from rcs300 import RCS300, ReaderError


SERVICE_NAME = 'NfcAuthService'
SERVICE_STOP_TIMEOUT_SEC = 45
SERVICE_POLL_SEC = 0.25


def _service_state():
    """Return the service's current state, or None when it is not installed."""
    try:
        import win32serviceutil
    except ImportError:
        return None
    try:
        return win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1]
    except Exception:
        return None


def _wait_for_service_state(target, timeout_sec: float) -> bool:
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        if _service_state() == target:
            return True
        time.sleep(SERVICE_POLL_SEC)
    return _service_state() == target


@contextlib.contextmanager
def _reader_released():
    """Stop the service for the duration so the reader can be opened here.

    WinUSB lets only one application talk to the device at a time, and the
    service holds interface 1 open for its whole polling loop, so enrolling a
    card while it runs would simply fail.
    """
    import win32service
    import win32serviceutil

    was_running = _service_state() == win32service.SERVICE_RUNNING
    if was_running:
        print(f'Stopping {SERVICE_NAME} to free the reader...')
        win32serviceutil.StopService(SERVICE_NAME)
        if not _wait_for_service_state(
            win32service.SERVICE_STOPPED, SERVICE_STOP_TIMEOUT_SEC
        ):
            raise RuntimeError(
                f'{SERVICE_NAME} did not stop; stop it manually and try again'
            )
    try:
        yield
    finally:
        if was_running:
            try:
                win32serviceutil.StartService(SERVICE_NAME)
                print(f'Restarted {SERVICE_NAME}.')
            except Exception as error:
                # Never let a restart failure hide a successful enrolment, but
                # do not leave the user guessing why taps stopped working.
                print(
                    f'WARNING: {SERVICE_NAME} could not be restarted: {error}',
                    file=sys.stderr,
                )
                print(
                    f'         Start it with: sc start {SERVICE_NAME}',
                    file=sys.stderr,
                )


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


def _set_credential(windows_user: str) -> str:
    """Store the password that lets a tap sign in without typing anything."""
    user = (windows_user or '').strip()
    if not user:
        raise ValueError('--windows-user must not be empty')

    print('This password is stored on this machine, encrypted with DPAPI under')
    print('the machine key, readable by SYSTEM and local administrators.')
    print('Anyone who gains administrator rights on this PC can recover it.')
    print('Leave it unset to keep the tap as a first factor and type the')
    print('password at sign-in instead.')
    print()
    password = getpass.getpass(f'Windows password for {user}: ')
    if not password:
        raise ValueError('The password must not be empty')
    if password != getpass.getpass('Confirm password: '):
        raise ValueError('The passwords did not match')

    save_credential(user, password)
    return user


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Manage NFC card registrations')
    subparsers = parser.add_subparsers(dest='command', required=True)

    register_parser = subparsers.add_parser('register')
    register_parser.add_argument('--name', required=True)
    register_parser.add_argument('--windows-user')
    register_parser.add_argument('--timeout', type=float, default=30)

    subparsers.add_parser('list')

    credential_parser = subparsers.add_parser(
        'set-credential',
        help='store the password used for hands-free sign-in after a tap',
    )
    credential_parser.add_argument('--windows-user', required=True)

    subparsers.add_parser(
        'clear-credential',
        help='remove the stored password and return to typing it at sign-in',
    )

    remove_parser = subparsers.add_parser('remove')
    remove_parser.add_argument('--name', required=True)

    args = parser.parse_args(argv)
    try:
        _require_admin()
        if args.command == 'register':
            with _reader_released():
                mac = _register(args.name, args.windows_user, args.timeout)
            print(f'{args.name}\t{mac[:8]}')
        elif args.command == 'list':
            _print_cards()
            stored = load_credential_user()
            print(f'auto sign-in: {stored}' if stored else 'auto sign-in: not configured')
        elif args.command == 'set-credential':
            print(_set_credential(args.windows_user))
        elif args.command == 'clear-credential':
            print('removed' if clear_credential() else 'nothing to remove')
        elif args.command == 'remove':
            if remove_card(args.name):
                print(args.name)
            else:
                print(f'Not found: {args.name}', file=sys.stderr)
                return 1
        return 0
    except (OSError, PermissionError, ReaderError, RuntimeError,
            TimeoutError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
