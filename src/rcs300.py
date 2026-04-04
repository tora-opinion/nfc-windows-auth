"""
RC-S300 FeliCa Reader Driver for iPhone Express Card
=====================================================

Key Discovery: System code 0x0003 triggers iPhone Express Card mode!

Standard system codes like 0xFFFF (wildcard) or 0x88B4 (transit IC)
trigger Apple Pay payment mode which requires Face ID/Touch ID.

System code 0x0003 is the magic code that activates Express Card (Suica)
without user authentication, enabling seamless NFC login.

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

    # Standard system codes (don't trigger Express Card!)
    SYSTEM_CODE_WILDCARD = 0xFFFF
    SYSTEM_CODE_TRANSIT = 0x88B4

    # CCID Session commands
    CMD_SESSION_END = 0x82
    CMD_SESSION_START = 0x81
    CMD_RF_OFF = 0x83
    CMD_RF_ON = 0x84

    # Timing (from Sony NFC Port Library)
    RF_OFF_GUARD_TIME = 0.030  # 30ms
    RF_ON_GUARD_TIME = 0.021   # 21ms

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
                pass  # Already configured

            # Use Interface 1 (WinUSB), not Interface 0 (PC/SC)
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

    def _ccid_escape(self, data: bytes, timeout: int = 2000) -> bytes:
        """Send CCID Escape command"""
        self.seq = (self.seq + 1) % 256
        header = bytes([
            0x6B,  # PC_to_RDR_Escape
            len(data) & 0xFF,
            (len(data) >> 8) & 0xFF,
            0, 0,  # dwLength high bytes
            0,     # bSlot
            self.seq,  # bSeq
            0, 0, 0    # abRFU
        ])

        self.dev.write(self.ep_out, header + bytes(data))
        time.sleep(0.005)

        resp = bytes(self.dev.read(self.ep_in, 300, timeout=timeout))
        dw_len = resp[1] | (resp[2] << 8)
        return resp[10:10 + dw_len]

    def _manage_session(self, tag: int, length: int = 0):
        """Send session management command"""
        cmd = [0xFF, 0x50, 0x00, 0x00, 2, tag, length, 0x00]
        return self._ccid_escape(bytes(cmd))

    def _transceive(self, cmd_bytes: bytes, timeout_ms: int = 500) -> Optional[bytes]:
        """Send transceive command and get response"""
        timeout_us = struct.pack('<I', timeout_ms * 1000)

        # Build TLV data
        cmd_data = [0x5F, 0x46, 0x04] + list(timeout_us)  # Timeout TLV
        cmd_data += [0x95, 0x82, 0x00, len(cmd_bytes)] + list(cmd_bytes)  # Transceive TLV

        # Build command
        cmd = [0xFF, 0x50, 0x00, 0x01, 0x00,
               (len(cmd_data) >> 8) & 0xFF,
               len(cmd_data) & 0xFF] + cmd_data + [0, 0, 0]

        resp = self._ccid_escape(bytes(cmd), timeout=timeout_ms + 500)

        # Parse response for tag 0x97 (response data)
        i = 0
        while i < len(resp) - 1:
            tag = resp[i]
            if tag == 0x97:
                i += 1
                length = resp[i]
                if length == 0x81:
                    length = resp[i + 1]
                    i += 1
                elif length == 0x82:
                    length = (resp[i + 1] << 8) | resp[i + 2]
                    i += 2
                i += 1
                return bytes(resp[i:i + length])
            elif tag == 0xC0:
                # Status TLV - check for timeout/error
                i += 1
                length = resp[i]
                i += 1
                status = resp[i:i + length]
                if length >= 3 and status[1] == 0x64:
                    return None  # Timeout/no card
                i += length
            else:
                i += 1
                if i < len(resp):
                    i += resp[i] + 1
        return None

    def start_session(self):
        """Initialize transparent session for FeliCa"""
        try:
            self._manage_session(self.CMD_SESSION_END)
        except:
            pass

        self._manage_session(self.CMD_SESSION_START)
        self._manage_session(self.CMD_RF_OFF)
        time.sleep(self.RF_OFF_GUARD_TIME)
        self._manage_session(self.CMD_RF_ON)
        time.sleep(self.RF_ON_GUARD_TIME)

        # Switch to FeliCa protocol (autoBaudRate=0)
        self._ccid_escape(bytes([0xFF, 0x50, 0x00, 0x02, 4, 0x8F, 0x02, 0x03, 0x00, 0x00]))

    def end_session(self):
        """End transparent session"""
        try:
            self._manage_session(self.CMD_SESSION_END)
        except:
            pass

    def poll_express_card(self, timeout_ms: int = 100) -> Optional[Tuple[bytes, bytes]]:
        """
        Poll for iPhone Express Card using system code 0x0003

        Returns:
            Tuple of (IDm, PMm) if card detected, None otherwise
        """
        # FeliCa Polling command: len, cmd, system_code_hi, system_code_lo, request_code, time_slot
        poll_cmd = bytes([
            6,      # Length
            0x00,   # SENSF_REQ command
            0x00,   # System code high byte
            0x03,   # System code low byte (0x0003 = Express Card magic!)
            0x01,   # Request code
            0x00    # Time slot
        ])

        resp = self._transceive(poll_cmd, timeout_ms)

        if resp and len(resp) >= 17:
            # Response: length, response_code, IDm[8], PMm[8], [RD[2]]
            idm = resp[1:9]
            pmm = resp[9:17]
            return (idm, pmm)
        return None

    def read_felica_block(self, idm: bytes, service_code: int, block_num: int) -> Optional[bytes]:
        """Read a block from FeliCa card"""
        # Read Without Encryption command
        cmd = bytes([
            16,     # Length
            0x06,   # Command code
        ]) + idm + bytes([
            1,      # Number of services
            service_code & 0xFF,
            (service_code >> 8) & 0xFF,
            1,      # Number of blocks
            0x80,   # Block list element (2-byte, access mode 0)
            block_num
        ])

        resp = self._transceive(cmd, timeout_ms=500)

        if resp and len(resp) >= 28 and resp[1] == 0x07:
            status1 = resp[10]
            if status1 == 0x00:
                # Block data starts at offset 13
                return resp[13:29]
        return None

    def read_suica_balance(self, idm: bytes) -> Optional[int]:
        """Read Suica balance (service 0x008B, block 0)"""
        block = self.read_felica_block(idm, 0x008B, 0)
        if block and len(block) >= 12:
            # Balance is at offset 10-11 (little-endian)
            return int.from_bytes(block[10:12], 'little')
        return None


def main():
    """Test the RC-S300 driver"""
    import os

    # Find libusb DLL
    script_dir = os.path.dirname(os.path.abspath(__file__))
    libusb_path = os.path.join(script_dir, '..', 'daemon', 'libusb-1.0.dll')

    reader = RCS300(libusb_path)

    if not reader.open():
        print("Failed to open RC-S300")
        return

    print("RC-S300 opened successfully")

    try:
        reader.start_session()
        print("Session started")
        print("\nPlace iPhone on reader...")

        for i in range(50):
            result = reader.poll_express_card(timeout_ms=100)
            if result:
                idm, pmm = result
                print(f"\n[SUCCESS] Express Card detected!")
                print(f"  IDm: {idm.hex().upper()}")
                print(f"  PMm: {pmm.hex().upper()}")

                # Try to read balance
                balance = reader.read_suica_balance(idm)
                if balance is not None:
                    print(f"  Balance: {balance} yen")
                break
            print(".", end="", flush=True)
            time.sleep(0.1)
        else:
            print("\n[TIMEOUT] No card detected")

    finally:
        reader.end_session()
        reader.close()
        print("\nReader closed")


if __name__ == "__main__":
    main()
