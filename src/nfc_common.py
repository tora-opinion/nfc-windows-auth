"""Shared helpers for the NFC reader daemons."""

import hashlib
import json
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict, Optional


REPO_ROOT = Path(__file__).resolve().parent.parent


def setup_logging(name: str, log_path) -> logging.Logger:
    """Configure console and rotating file logging for an NFC process."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)

    log_path = Path(log_path)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_path, maxBytes=1024 * 1024, backupCount=3, encoding='utf-8'
        )
    except OSError:
        # Repo dir not writable (e.g. under Program Files): fall back to a per-user dir
        fallback = Path(os.environ.get('LOCALAPPDATA', Path.home())) / 'nfc-windows-auth' / log_path.name
        try:
            fallback.parent.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                fallback, maxBytes=1024 * 1024, backupCount=3, encoding='utf-8'
            )
        except OSError:
            return logger  # console-only logging beats failing to start
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger


def hash_idm(idm: bytes) -> str:
    """Return the SHA-256 digest used for registered card identifiers."""
    return hashlib.sha256(idm).hexdigest()


def idm_preview(idm: bytes) -> str:
    """Return a short, non-reversible log preview for an IDm."""
    return hash_idm(idm)[:8]


def log_idm(logger: logging.Logger, level: int, message: str, idm: bytes):
    """Log a card message without exposing the IDm itself."""
    logger.log(level, '%s (IDm SHA-256: %s)', message, idm_preview(idm))


def load_config(config_path=None, defaults: Optional[Dict] = None) -> Dict:
    """Load config.json and merge it over the supplied defaults."""
    path = Path(config_path) if config_path is not None else REPO_ROOT / 'config.json'
    if not path.is_absolute():
        path = REPO_ROOT / path

    config = dict(defaults or {'registered_cards': {}})
    if not path.exists():
        return config

    try:
        raw = path.read_bytes()
        try:
            text = raw.decode('utf-8-sig')
        except UnicodeDecodeError:
            # Older versions wrote config.json with the locale codepage (cp932 on ja-JP)
            text = raw.decode('cp932')
        loaded = json.loads(text)
    except (OSError, ValueError) as error:
        logging.getLogger(__name__).warning('Failed to load config: %s', error)
        return config

    if isinstance(loaded, dict):
        config.update(loaded)
    return config


def find_libusb(config: Optional[Dict] = None, repo_root=None) -> Optional[str]:
    """Find libusb using config first, then the repository's known locations."""
    root = Path(repo_root) if repo_root is not None else REPO_ROOT
    if not root.is_absolute():
        root = root.resolve()
    config = config if config is not None else load_config()

    candidates = []
    configured_path = config.get('libusb_path') if isinstance(config, dict) else None
    if configured_path:
        configured_path = Path(configured_path)
        candidates.append(
            configured_path if configured_path.is_absolute() else root / configured_path
        )

    candidates.extend([
        root / 'libusb' / 'VS2022' / 'MS64' / 'dll' / 'libusb-1.0.dll',
        root / 'src' / 'libusb-1.0.dll',
        root / 'daemon' / 'libusb-1.0.dll',
    ])
    program_files = os.environ.get('PROGRAMFILES')
    if program_files:
        candidates.append(Path(program_files) / 'libusb' / 'libusb-1.0.dll')

    for path in candidates:
        if path.is_file():
            return str(path)
    return None


def next_backoff_delay(previous_delay: Optional[float], initial: float = 1,
                       maximum: float = 30) -> float:
    """Return the next exponential reconnect delay, or the initial delay."""
    if previous_delay is None:
        return initial
    return min(previous_delay * 2, maximum)
