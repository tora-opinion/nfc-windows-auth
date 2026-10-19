"""
RC-S300 FeliCa Reader Driver for iPhone Express Card
=====================================================

Key Discovery: System code 0x0003 triggers iPhone Express Card mode!

Uses CCID Escape commands over USB Interface 1 (WinUSB).

Author: Generated with Claude Code
License: MIT
"""

import struct
import time
from typing import List, Optional, Tuple

import usb.backend.libusb1 as libusb1
import usb.core
import usb.util


class ReaderError(Exception):
    """Base class for RC-S300 communication errors."""


class ReaderDisconnected(ReaderError):
    """The reader could not be found or USB communication failed."""


class ReaderTimeout(ReaderError):
    """A USB or CCID operation timed out."""


class ReaderProtocolError(ReaderError):
    """The reader returned a malformed or unsuccessful response."""


def parse_tlvs(data: bytes) -> List[Tuple[int, bytes]]:
    """Parse BER-style TLVs with one- or two-byte extended lengths."""
    items = []
    offset = 0

    while offset < len(data):
        tag_bytes = [data[offset]]
        tag = data[offset]
        offset += 1

        if tag & 0x1F == 0x1F:
            while True:
                if offset >= len(data):
                    raise ValueError('Truncated TLV tag')
                next_tag_byte = data[offset]
                tag_bytes.append(next_tag_byte)
                offset += 1
                if not next_tag_byte & 0x80:
                    break
            tag = int.from_bytes(bytes(tag_bytes), 'big')

        if offset >= len(data):
            raise ValueError('Truncated TLV length')
        length = data[offset]
        offset += 1

        if length == 0x80:
            raise ValueError('Indefinite TLV lengths are not supported')
        if length & 0x80:
            length_bytes = length & 0x7F
            if length_bytes not in (1, 2):
                raise ValueError('Unsupported extended TLV length')
            if offset + length_bytes > len(data):
                raise ValueError('Truncated extended TLV length')
            length = int.from_bytes(data[offset:offset + length_bytes], 'big')
            offset += length_bytes

        end = offset + length
        if end > len(data):
            raise ValueError('Truncated TLV value')
        items.append((tag, bytes(data[offset:end])))
        offset = end

    return items


def parse_express_card_response(response: bytes) -> Optional[Tuple[bytes, bytes]]:
    """Extract IDm and PMm from the RC-S300 Express Card TLV response."""
    try:
        items = parse_tlvs(response)
    except ValueError as error:
        raise ReaderProtocolError('Malformed TLV response') from error

    sensf_response = None
    no_card = False
    for tag, value in items:
        if tag == 0xC0:
            if len(value) < 3:
                raise ReaderProtocolError('Truncated transceive status')
            status_word = value[-2:]
            if status_word == b'\x64\x00':
                no_card = True
            elif status_word != b'\x90\x00':
                raise ReaderProtocolError('Transceive command failed')

        if tag == 0x97:
            # SENSF_RES: length, response code, IDm[8], PMm[8], ...
            if len(value) < 18:
                raise ReaderProtocolError('Truncated SENSF_RES response')
            if value[1] != 0x01:
                continue
            sensf_response = bytes(value[2:10]), bytes(value[10:18])

    return None if no_card else sensf_response


class RCS300:
    """Sony RC-S300 (PaSoRi) FeliCa Reader Driver."""

    VENDOR_ID = 0x054C   # Sony
    PRODUCT_ID = 0x0DC9  # RC-S300

    # Express Card magic system code
    SYSTEM_CODE_EXPRESS_CARD = 0x0003

    # Max consecutive CCID time-extension responses to wait through per command
    MAX_TIME_EXTENSIONS = 10

    def __init__(self, libusb_path: Optional[str] = None):
        self.dev = None
        self.ep_out = None
        self.ep_in = None
        self.seq = 0
        self.libusb_path = libusb_path

    def _get_backend(self):
        if self.libusb_path:
            def find_library(name):
                if 'libusb' in name or '1.0' in name:
                    return self.libusb_path
                return None
            return libusb1.get_backend(find_library=find_library)
        return libusb1.get_backend()

    def open(self) -> bool:
        """Open connection to RC-S300, raising a typed error on failure."""
        self.close()
        try:
            self.dev = usb.core.find(
                idVendor=self.VENDOR_ID,
                idProduct=self.PRODUCT_ID,
                backend=self._get_backend()
            )
            if self.dev is None:
                raise ReaderDisconnected('RC-S300 not found')

            # Skip set_configuration() when already configured: repeating it resets the
            # device, and WinUSB often rejects it. A truly unusable device still fails
            # at the descriptor lookup / claim_interface below with a typed error.
            try:
                self.dev.get_active_configuration()
            except usb.core.USBError:
                try:
                    self.dev.set_configuration()
                except usb.core.USBError:
                    pass

            # Interface 1 = WinUSB for NFC Port access
            usb.util.claim_interface(self.dev, 1)

            cfg = self.dev.get_active_configuration()
            intf = cfg[(1, 0)]

            self.ep_out = usb.util.find_descriptor(
                intf,
                custom_match=lambda endpoint: (
                    usb.util.endpoint_direction(endpoint.bEndpointAddress)
                    == usb.util.ENDPOINT_OUT
                )
            )
            self.ep_in = usb.util.find_descriptor(
                intf,
                custom_match=lambda endpoint: (
                    usb.util.endpoint_direction(endpoint.bEndpointAddress)
                    == usb.util.ENDPOINT_IN
                )
            )
            if self.ep_out is None or self.ep_in is None:
                raise ReaderProtocolError('RC-S300 USB endpoints not found')
            return True
        except ReaderError:
            self.close()
            raise
        except usb.core.USBTimeoutError as error:
            self.close()
            raise ReaderTimeout('Timed out opening RC-S300') from error
        except usb.core.USBError as error:
            self.close()
            raise ReaderDisconnected('USB error opening RC-S300') from error
        except Exception as error:
            self.close()
            raise ReaderDisconnected('Failed to open RC-S300') from error

    def close(self):
        """Release the reader interface and clear the current connection."""
        dev = self.dev
        self.dev = None
        self.ep_out = None
        self.ep_in = None
        if dev is not None:
            try:
                usb.util.release_interface(dev, 1)
            except usb.core.USBError:
                # A detached device may reject release during reconnect.
                pass

    def _ccid_escape(self, data: bytes, timeout: int = 2000) -> bytes:
        """Send a CCID PC_to_RDR_Escape command and validate its response."""
        if self.dev is None or self.ep_out is None or self.ep_in is None:
            raise ReaderDisconnected('RC-S300 is not open')

        self.seq = (self.seq + 1) % 256

        # CCID PC_to_RDR_Escape header
        header = bytes([
            0x6B,                    # bMessageType = PC_to_RDR_Escape
            len(data) & 0xFF,        # dwLength (low)
            (len(data) >> 8) & 0xFF, # dwLength
            0x00, 0x00,              # dwLength (high bytes)
            0x00,                    # bSlot
            self.seq,                # bSeq
            0x00, 0x00, 0x00         # abRFU
        ])

        try:
            self.dev.write(self.ep_out, header + data)
            time.sleep(0.01)
            # A time-extension response (bStatus 0x80, same bSeq) is followed by the real
            # response (CCID 6.2.6), so keep reading instead of treating it as a failure.
            for _ in range(self.MAX_TIME_EXTENSIONS + 1):
                response = bytes(self.dev.read(self.ep_in, 300, timeout=timeout))
                is_time_extension = (
                    len(response) >= 8
                    and response[0] == 0x83
                    and response[6] == self.seq
                    and (response[7] & 0xC0) == 0x80
                )
                if not is_time_extension:
                    break
            else:
                raise ReaderTimeout('CCID time extension limit exceeded')
        except usb.core.USBTimeoutError as error:
            raise ReaderTimeout('Timed out communicating with RC-S300') from error
        except usb.core.USBError as error:
            raise ReaderDisconnected('USB communication with RC-S300 failed') from error

        if len(response) < 10:
            raise ReaderProtocolError('CCID response header is truncated')
        if response[0] != 0x83:
            raise ReaderProtocolError('Unexpected CCID response type')
        if response[6] != self.seq:
            raise ReaderProtocolError('CCID response sequence does not match')

        dw_length = int.from_bytes(response[1:5], 'little')
        status = response[7]
        error_code = response[8]
        command_status = status & 0xC0
        if command_status == 0x40:
            raise ReaderProtocolError(
                f'CCID command failed (error 0x{error_code:02X})'
            )
        if command_status == 0xC0:
            raise ReaderProtocolError('Invalid CCID command status')

        if len(response) < 10 + dw_length:
            raise ReaderProtocolError('CCID response data is truncated')
        return response[10:10 + dw_length]

    @staticmethod
    def _check_command_response(response: bytes, command: str):
        if len(response) < 2 or response[-2:] != b'\x90\x00':
            raise ReaderProtocolError(f'{command} command failed')

    def _manage_session(self, tag: int, length: int = 0):
        """Send and validate a session management command via CCID Escape."""
        command = bytes([0xFF, 0x50, 0x00, 0x00, 0x02, tag, length, 0x00])
        response = self._ccid_escape(command)
        self._check_command_response(response, 'Session management')
        return response[:-2]

    def start_session(self):
        """Initialize transparent session for FeliCa."""
        self._manage_session(0x82)
        time.sleep(0.01)

        self._manage_session(0x81)
        time.sleep(0.01)

        self._manage_session(0x83)
        time.sleep(0.03)

        self._manage_session(0x84)
        time.sleep(0.02)

        # Switch to FeliCa mode
        command = bytes([0xFF, 0x50, 0x00, 0x02, 0x04, 0x8F, 0x02, 0x03, 0x00, 0x00])
        response = self._ccid_escape(command)
        self._check_command_response(response, 'FeliCa protocol switch')
        time.sleep(0.01)

    def end_session(self):
        """End transparent session."""
        self._manage_session(0x82)

    def poll_express_card(self, timeout_ms: int = 500) -> Optional[Tuple[bytes, bytes]]:
        """
        Poll for iPhone Express Card using system code 0x0003.

        Returns:
            Tuple of (IDm, PMm) if card detected, None otherwise.
        """
        timeout_us = struct.pack('<I', timeout_ms * 1000)
        sys_hi = (self.SYSTEM_CODE_EXPRESS_CARD >> 8) & 0xFF
        sys_lo = self.SYSTEM_CODE_EXPRESS_CARD & 0xFF

        # SENSF_REQ: len=6, cmd=00, sys_hi, sys_lo, req_code=01, time_slot=00
        sensf_req = bytes([0x06, 0x00, sys_hi, sys_lo, 0x01, 0x00])

        # Build InDataExchange TLV command
        tlv_data = bytearray()
        tlv_data += bytes([0x5F, 0x46, 0x04])  # Timeout TLV tag
        tlv_data += timeout_us
        tlv_data += bytes([0x95, 0x82, 0x00, len(sensf_req)])  # Transceive TLV
        tlv_data += sensf_req

        command = bytes([
            0xFF, 0x50, 0x00, 0x01, 0x00,
            (len(tlv_data) >> 8) & 0xFF,
            len(tlv_data) & 0xFF
        ]) + bytes(tlv_data) + bytes([0x00, 0x00, 0x00])

        response = self._ccid_escape(command, timeout=timeout_ms + 1000)
        return parse_express_card_response(response)
