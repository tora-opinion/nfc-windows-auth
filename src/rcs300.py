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
from typing import Optional, Tuple

import usb.core
import usb.util
import usb.backend.libusb1 as libusb1


class RCS300:
    """Sony RC-S300 (PaSoRi) FeliCa Reader Driver"""

    VENDOR_ID = 0x054C   # Sony
    PRODUCT_ID = 0x0DC9  # RC-S300

    # Express Card magic system code
    SYSTEM_CODE_EXPRESS_CARD = 0x0003

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
        """Open connection to RC-S300"""
        try:
            self.dev = usb.core.find(
                idVendor=self.VENDOR_ID,
                idProduct=self.PRODUCT_ID,
                backend=self._get_backend()
            )
            if not self.dev:
                return False

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
                custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT
            )
            self.ep_in = usb.util.find_descriptor(
                intf,
                custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN
            )
            return True
        except Exception as e:
            print(f"Failed to open RC-S300: {e}")
            return False

    def close(self):
        """Close connection"""
        if self.dev:
            try:
                usb.util.release_interface(self.dev, 1)
            except:
                pass
            self.dev = None

    def _ccid_escape(self, data: bytes, timeout: int = 2000) -> Optional[bytes]:
        """Send CCID PC_to_RDR_Escape command"""
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
            resp = bytes(self.dev.read(self.ep_in, 300, timeout=timeout))

            # Parse CCID response
            if len(resp) >= 10 and resp[0] == 0x83:  # RDR_to_PC_Escape
                dw_len = resp[1] | (resp[2] << 8)
                status = resp[7]
                error = resp[8]
                # Status: 0=no ICC, 1=ICC present inactive, 2=ICC present active
                # Accept any status with data
                if dw_len > 0:
                    return resp[10:10 + dw_len]
            return None
        except Exception as e:
            return None

    def _manage_session(self, tag: int, length: int = 0):
        """Send session management command via CCID Escape"""
        cmd = bytes([0xFF, 0x50, 0x00, 0x00, 0x02, tag, length, 0x00])
        return self._ccid_escape(cmd)

    def start_session(self):
        """Initialize transparent session for FeliCa"""
        # End any existing session
        self._manage_session(0x82)
        time.sleep(0.01)

        # Start session
        self._manage_session(0x81)
        time.sleep(0.01)

        # RF OFF
        self._manage_session(0x83)
        time.sleep(0.03)

        # RF ON
        self._manage_session(0x84)
        time.sleep(0.02)

        # Switch to FeliCa mode
        cmd = bytes([0xFF, 0x50, 0x00, 0x02, 0x04, 0x8F, 0x02, 0x03, 0x00, 0x00])
        self._ccid_escape(cmd)
        time.sleep(0.01)

    def end_session(self):
        """End transparent session"""
        self._manage_session(0x82)

    def poll_express_card(self, timeout_ms: int = 500) -> Optional[Tuple[bytes, bytes]]:
        """
        Poll for iPhone Express Card using system code 0x0003

        Returns:
            Tuple of (IDm, PMm) if card detected, None otherwise
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

        cmd = bytes([0xFF, 0x50, 0x00, 0x01, 0x00,
                     (len(tlv_data) >> 8) & 0xFF,
                     len(tlv_data) & 0xFF]) + bytes(tlv_data) + bytes([0x00, 0x00, 0x00])

        resp = self._ccid_escape(cmd, timeout=timeout_ms + 1000)

        if resp:
            # Parse TLV response for tag 0x97 (response data)
            i = 0
            while i < len(resp) - 2:
                tag = resp[i]
                if tag == 0x97:  # Response data TLV
                    i += 1
                    length = resp[i]
                    i += 1
                    if length >= 17:
                        # SENSF_RES: length(1), response_code(1), IDm[8], PMm[8], RD[2]
                        data = resp[i:i + length]
                        if len(data) >= 17 and data[1] == 0x01:  # response_code 01 = success
                            idm = bytes(data[2:10])
                            pmm = bytes(data[10:18])
                            return (idm, pmm)
                    break
                else:
                    # Skip to next TLV
                    i += 1
                    if i < len(resp):
                        skip_len = resp[i]
                        i += 1 + skip_len
                    else:
                        break

        return None
