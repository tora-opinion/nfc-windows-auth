"""Secure on-disk state for the NFC authentication service."""

import hashlib
import hmac
import json
import os
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from nfc_common import load_config


DEFAULT_DATA_DIR = r'C:\ProgramData\NfcAuth'
DEFAULT_CONFIG = {
    'registered_cards': {},
    'tap_ttl_sec': 30,
    'libusb_path': None,
}
_FILE_SDDL = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
_DIRECTORY_SDDL = 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'


def get_data_dir() -> Path:
    """Return the service data directory, honoring the test/deployment override."""
    return Path(os.environ.get('NFCAUTH_DATA_DIR') or DEFAULT_DATA_DIR)


def _apply_protected_acl(path: Path, directory: bool = False):
    """Restrict a data path to LocalSystem and the local Administrators group."""
    import win32security

    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        _DIRECTORY_SDDL if directory else _FILE_SDDL,
        win32security.SDDL_REVISION_1,
    )
    security_information = (
        win32security.DACL_SECURITY_INFORMATION
        | win32security.PROTECTED_DACL_SECURITY_INFORMATION
    )
    win32security.SetFileSecurity(str(path), security_information, descriptor)


def ensure_data_dir(apply_acl: bool = True) -> Path:
    """Create the data directory and optionally apply its protected DACL."""
    path = get_data_dir()
    path.mkdir(parents=True, exist_ok=True)
    if apply_acl:
        _apply_protected_acl(path, directory=True)
    return path


def _config_path() -> Path:
    return get_data_dir() / 'config.json'


def _load_config() -> Dict:
    defaults = dict(DEFAULT_CONFIG)
    defaults['registered_cards'] = {}
    config = load_config(_config_path(), defaults)
    if not isinstance(config.get('registered_cards'), dict):
        config['registered_cards'] = {}
    config.setdefault('libusb_path', None)
    return config


def _write_config(config: Dict):
    directory = ensure_data_dir()
    target = directory / 'config.json'
    temp_path = directory / f'.config.json.{uuid.uuid4().hex}.tmp'
    payload = json.dumps(config, ensure_ascii=False, indent=2) + '\n'

    try:
        with temp_path.open('x', encoding='utf-8', newline='\n') as config_file:
            # The directory has an inheritable restricted DACL; set the explicit
            # protected file DACL before any configuration contents are written.
            _apply_protected_acl(temp_path)
            config_file.write(payload)
            config_file.flush()
            os.fsync(config_file.fileno())
        os.replace(temp_path, target)
    except Exception:
        try:
            temp_path.unlink()
        except OSError:
            pass
        raise


def load_key() -> bytes:
    """Load the 32-byte HMAC key, creating it securely on first use."""
    directory = ensure_data_dir()
    key_path = directory / 'hmac.key'

    def read_existing_key() -> bytes:
        _apply_protected_acl(key_path)
        key = key_path.read_bytes()
        if len(key) != 32:
            raise ValueError('hmac.key must contain exactly 32 bytes')
        return key

    if key_path.exists():
        return read_existing_key()

    temp_path = directory / f'.hmac.key.{uuid.uuid4().hex}.tmp'
    key = secrets.token_bytes(32)
    descriptor = os.open(
        str(temp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    try:
        with os.fdopen(descriptor, 'wb') as key_file:
            # Protect the temporary inode before writing any key material.
            _apply_protected_acl(temp_path)
            key_file.write(key)
            key_file.flush()
            os.fsync(key_file.fileno())
        try:
            # Hard-link creation is atomic and fails rather than replacing a winner.
            os.link(temp_path, key_path)
        except FileExistsError:
            return read_existing_key()
        return key
    finally:
        try:
            temp_path.unlink()
        except OSError:
            pass


def idm_mac(idm: bytes, key: bytes) -> str:
    """Return the keyed, lowercase HMAC-SHA256 identifier for an IDm."""
    return hmac.new(key, idm, hashlib.sha256).hexdigest()


def load_cards() -> Dict[str, dict]:
    """Return registered card records keyed by their HMAC identifier."""
    cards = _load_config().get('registered_cards', {})
    return dict(cards) if isinstance(cards, dict) else {}


def _clamp_ttl(value) -> int:
    try:
        seconds = int(value)
    except (TypeError, ValueError, OverflowError):
        seconds = DEFAULT_CONFIG['tap_ttl_sec']
    return max(5, min(120, seconds))


def load_settings() -> Dict:
    """Return persisted settings with the tap lifetime restricted to 5..120 sec."""
    settings = _load_config()
    settings['tap_ttl_sec'] = _clamp_ttl(settings.get('tap_ttl_sec', 30))
    return settings


def add_card(mac: str, name: str, windows_user: Optional[str]):
    """Add or replace a card registration and atomically persist the config."""
    if not isinstance(mac, str) or len(mac) != 64:
        raise ValueError('mac must be a 64-character HMAC-SHA256 hex string')
    try:
        bytes.fromhex(mac)
    except ValueError as error:
        raise ValueError('mac must be a 64-character HMAC-SHA256 hex string') from error
    if not isinstance(name, str) or not name.strip():
        raise ValueError('name must not be empty')

    name = name.strip()
    windows_user = windows_user.strip() if isinstance(windows_user, str) else None
    if not windows_user:
        windows_user = None

    config = _load_config()
    cards = config['registered_cards']
    if any(
        isinstance(existing, dict)
        and existing.get('name') == name
        and existing_mac != mac.lower()
        for existing_mac, existing in cards.items()
    ):
        raise ValueError(f'card name is already registered: {name}')

    card = {
        'name': name,
        'windows_user': windows_user,
        'registered_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
    }
    cards[mac.lower()] = card
    config['tap_ttl_sec'] = _clamp_ttl(config.get('tap_ttl_sec', 30))
    config.setdefault('libusb_path', None)
    _write_config(config)
    return dict(card)


def remove_card(name: str) -> bool:
    """Remove a registration by its display name and persist when it exists."""
    config = _load_config()
    cards = config['registered_cards']
    removed = [
        mac for mac, card in cards.items()
        if isinstance(card, dict) and card.get('name') == name
    ]
    if not removed:
        return False
    for mac in removed:
        del cards[mac]
    _write_config(config)
    return True


def find_card(mac: str) -> Optional[dict]:
    """Find a registered card by its HMAC identifier."""
    card = load_cards().get(mac)
    return dict(card) if isinstance(card, dict) else None
