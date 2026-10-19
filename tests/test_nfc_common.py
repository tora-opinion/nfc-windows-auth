import logging
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / 'src'))

from nfc_common import (
    find_libusb,
    hash_idm,
    idm_preview,
    log_idm,
    next_backoff_delay,
    setup_logging,
)


def test_hash_idm_stability():
    assert hash_idm(b'abc') == (
        'ba7816bf8f01cfea414140de5dae2223'
        'b00361a396177a9cb410ff61f20015ad'
    )


def test_backoff_sequence_and_reset():
    delay = None
    sequence = []
    for _ in range(8):
        delay = next_backoff_delay(delay)
        sequence.append(delay)

    assert sequence == [1, 2, 4, 8, 16, 30, 30, 30]
    assert next_backoff_delay(None) == 1


def test_find_libusb_search_order(tmp_path):
    configured = tmp_path / 'custom' / 'reader.dll'
    bundled = tmp_path / 'libusb' / 'VS2022' / 'MS64' / 'dll' / 'libusb-1.0.dll'
    src_copy = tmp_path / 'src' / 'libusb-1.0.dll'
    daemon_copy = tmp_path / 'daemon' / 'libusb-1.0.dll'

    for path in (configured, bundled, src_copy, daemon_copy):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'')

    assert find_libusb({'libusb_path': 'custom/reader.dll'}, tmp_path) == str(configured)
    configured.unlink()
    assert find_libusb({'libusb_path': 'custom/reader.dll'}, tmp_path) == str(bundled)
    bundled.unlink()
    assert find_libusb({}, tmp_path) == str(src_copy)
    src_copy.unlink()
    assert find_libusb({}, tmp_path) == str(daemon_copy)


def test_logging_uses_only_hashed_idm_preview(tmp_path):
    idm = bytes.fromhex('0102030405060708')
    logger = setup_logging('test.nfc.logging', tmp_path / 'nfc.log')

    log_idm(logger, logging.INFO, 'Card authenticated', idm)
    for handler in logger.handlers:
        handler.flush()

    content = (tmp_path / 'nfc.log').read_text(encoding='utf-8')
    assert idm_preview(idm) in content
    assert idm.hex().upper() not in content.upper()
    assert idm.hex() not in content.lower()
