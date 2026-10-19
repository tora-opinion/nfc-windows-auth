import sys
from pathlib import Path
from unittest import mock

import pytest
import usb.core


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / 'src'))

import rcs300
from rcs300 import RCS300, ReaderTimeout


def _response(seq, status=0x00, payload=b'\x90\x00'):
    header = bytes([0x83]) + len(payload).to_bytes(4, 'little') + bytes([0x00, seq, status, 0x00, 0x00])
    return header + payload


class _FakeDev:
    """Replays queued CCID responses; echoes the sequence number of the last write."""

    def __init__(self, reader, statuses):
        self.reader = reader
        self.statuses = list(statuses)
        self.reads = 0

    def write(self, ep, data):
        pass

    def read(self, ep, size, timeout=None):
        self.reads += 1
        return _response(self.reader.seq, status=self.statuses.pop(0))


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


def test_ccid_escape_gives_up_after_too_many_time_extensions():
    reader = _reader_with([0x80] * (RCS300.MAX_TIME_EXTENSIONS + 1))
    with pytest.raises(ReaderTimeout):
        reader._ccid_escape(b'\x00')


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
