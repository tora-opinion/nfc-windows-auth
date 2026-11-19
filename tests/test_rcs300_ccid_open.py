import sys
from pathlib import Path
from unittest import mock

import pytest
import usb.core


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / 'src'))

import rcs300
from rcs300 import RCS300, ReaderTimeout


def _response(seq, status=0x00, payload=b'\x90\x00', error=0x00):
    header = bytes([0x83]) + len(payload).to_bytes(4, 'little') + bytes([0x00, seq, status, error, 0x00])
    return header + payload


class _FakeDev:
    """Replays queued CCID responses; echoes the sequence number of the last write."""

    def __init__(self, reader, statuses, extension_error=0x00):
        self.reader = reader
        self.statuses = list(statuses)
        self.extension_error = extension_error
        self.reads = 0
        self.timeouts = []

    def write(self, ep, data):
        pass

    def read(self, ep, size, timeout=None):
        self.reads += 1
        self.timeouts.append(timeout)
        status = self.statuses.pop(0)
        error = self.extension_error if status == 0x80 else 0x00
        return _response(self.reader.seq, status=status, error=error)


def _reader_with(statuses):
    reader = RCS300()
    reader.dev = _FakeDev(reader, statuses)
    reader.ep_out = object()
    reader.ep_in = object()
    return reader


def test_ccid_escape_waits_through_time_extension():
    reader = _reader_with([0x80, 0x80, 0x00])
    assert reader._ccid_escape(b'\x00') == b'\x90\x00'
    assert reader.dev.reads == 3


def test_ccid_escape_gives_up_after_time_extension_deadline():
    reader = _reader_with([0x80] * 5)
    reader.MAX_TIME_EXTENSION_SEC = -1  # deadline already passed on the first extension
    with pytest.raises(ReaderTimeout):
        reader._ccid_escape(b'\x00')
    assert reader.dev.reads == 0


def test_ccid_escape_keeps_waiting_beyond_ten_extensions():
    reader = _reader_with([0x80] * 25 + [0x00])
    assert reader._ccid_escape(b'\x00') == b'\x90\x00'


def test_ccid_escape_applies_time_extension_multiplier():
    reader = _reader_with([0x80, 0x00])
    reader.dev.extension_error = 0x03
    assert reader._ccid_escape(b'\x00', timeout=1000) == b'\x90\x00'
    assert reader.dev.timeouts == [1000, 3000]


def test_ccid_escape_clamps_large_multiplier_to_remaining_deadline(monkeypatch):
    reader = _reader_with([0x80, 0x00])
    reader.dev.extension_error = 0xFF
    clock_values = iter([10.0, 10.0, 12.0])
    monkeypatch.setattr(rcs300.time, 'monotonic', lambda: next(clock_values))

    assert reader._ccid_escape(b'\x00', timeout=2000) == b'\x90\x00'

    assert reader.dev.timeouts == [2000, 28000]


def test_start_session_tolerates_failed_initial_cleanup():
    reader = RCS300()
    calls = []

    def fake_manage(tag, length=0):
        calls.append(tag)
        if len(calls) == 1:
            raise rcs300.ReaderProtocolError('no session to end')
        return b''

    reader._manage_session = fake_manage
    reader._ccid_escape = lambda data, timeout=2000: b'\x90\x00'
    with mock.patch.object(rcs300.time, 'sleep'):
        reader.start_session()
    assert calls == [0x82, 0x81, 0x83, 0x84]


def test_open_does_not_call_set_configuration_when_already_configured():
    dev = mock.MagicMock()
    dev.get_active_configuration.return_value = {(1, 0): mock.MagicMock()}
    with mock.patch.object(rcs300.usb.core, 'find', return_value=dev), \
            mock.patch.object(rcs300.usb.util, 'claim_interface'), \
            mock.patch.object(rcs300.usb.util, 'find_descriptor', return_value=object()), \
            mock.patch.object(RCS300, '_get_backend', return_value=None):
        assert RCS300().open() is True
    dev.set_configuration.assert_not_called()


def test_open_tolerates_rejected_set_configuration():
    dev = mock.MagicMock()
    # Unconfigured at first, set_configuration is rejected (WinUSB), descriptor lookup still works
    dev.get_active_configuration.side_effect = [
        usb.core.USBError('not configured'),
        {(1, 0): mock.MagicMock()},
    ]
    dev.set_configuration.side_effect = usb.core.USBError('rejected')
    with mock.patch.object(rcs300.usb.core, 'find', return_value=dev), \
            mock.patch.object(rcs300.usb.util, 'claim_interface'), \
            mock.patch.object(rcs300.usb.util, 'find_descriptor', return_value=object()), \
            mock.patch.object(RCS300, '_get_backend', return_value=None):
        assert RCS300().open() is True
