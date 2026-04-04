"""
RC-S300 FeliCa読み取り - Sony NFC Port Library互換
CCIDエスケープコマンドを使用
"""
import os
import usb.core
import usb.util
import usb.backend.libusb1 as libusb1
import time
import struct

VENDOR_ID = 0x054C
PRODUCT_ID = 0x0DC9  # RC-S300

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) if '__file__' in dir() else os.getcwd()
LIBUSB_DLL = os.path.join(SCRIPT_DIR, 'libusb-1.0.dll')

# CCID constants
CCID_PC_TO_RDR_ESCAPE = 0x6B
CCID_RDR_TO_PC_ESCAPE = 0x83

class RCS300:
    def __init__(self):
        self.dev = None
        self.ep_out = None
        self.ep_in = None
        self.seq = 0

    def _get_backend(self):
        def find_library(name):
            return LIBUSB_DLL if 'libusb' in name or '1.0' in name else None
        return libusb1.get_backend(find_library=find_library)

    def open(self):
        backend = self._get_backend()
        self.dev = usb.core.find(idVendor=VENDOR_ID, idProduct=PRODUCT_ID, backend=backend)
        if not self.dev:
            raise Exception("RC-S300 not found")

        try:
            self.dev.set_configuration()
        except:
            pass

        # Interface 1 (WinUSB)
        usb.util.claim_interface(self.dev, 1)

        cfg = self.dev.get_active_configuration()
        intf = cfg[(1, 0)]

        self.ep_out = usb.util.find_descriptor(
            intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT
        )
        self.ep_in = usb.util.find_descriptor(
            intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN
        )

        print(f"[OK] RC-S300 opened (OUT={self.ep_out.bEndpointAddress:#x}, IN={self.ep_in.bEndpointAddress:#x})")

    def close(self):
        if self.dev:
            usb.util.release_interface(self.dev, 1)
            self.dev = None

    def _get_seq(self):
        self.seq = (self.seq + 1) % 256
        return self.seq

    def _ccid_escape(self, data, timeout=2000):
        """CCIDエスケープコマンド送信"""
        seq = self._get_seq()

        # PC_to_RDR_Escape
        header = bytes([
            CCID_PC_TO_RDR_ESCAPE,  # bMessageType
            len(data) & 0xFF, (len(data) >> 8) & 0xFF,
            (len(data) >> 16) & 0xFF, (len(data) >> 24) & 0xFF,  # dwLength
            0,  # bSlot
            seq,  # bSeq
            0, 0, 0  # reserved
        ])

        self.dev.write(self.ep_out, header + bytes(data))
        time.sleep(0.01)

        # Response header (10 bytes)
        resp = bytes(self.dev.read(self.ep_in, 64, timeout=timeout))

        if len(resp) < 10:
            raise Exception(f"Invalid CCID response length: {len(resp)}")

        msg_type = resp[0]
        dw_length = resp[1] | (resp[2] << 8) | (resp[3] << 16) | (resp[4] << 24)
        resp_seq = resp[6]
        status = resp[7]
        error = resp[8]

        if msg_type != CCID_RDR_TO_PC_ESCAPE:
            raise Exception(f"Invalid CCID message type: {msg_type:#x}")

        # Get data portion
        data_resp = resp[10:10+dw_length] if len(resp) >= 10+dw_length else resp[10:]

        # Read remaining if needed
        while len(data_resp) < dw_length:
            more = bytes(self.dev.read(self.ep_in, 64, timeout=timeout))
            data_resp += more
            if len(more) == 0:
                break

        return data_resp[:dw_length]

    def manage_session(self, tags):
        """セッション管理コマンド"""
        data = []
        for tag, length in tags:
            data.extend([tag, length])

        cmd = [0xFF, 0x50, 0x00, 0x00, len(data)] + data + [0x00]
        resp = self._ccid_escape(cmd)

        # Check status
        if len(resp) >= 2 and resp[-2] == 0x90 and resp[-1] == 0x00:
            return resp[:-2]
        else:
            raise Exception(f"manage_session failed: {resp.hex()}")

    def start_transparent_session(self):
        """透過セッション開始"""
        # End previous session first
        try:
            self.manage_session([(0x82, 0)])  # END_TRANSPARENT_SESSION
        except:
            pass

        # Start new session
        self.manage_session([(0x81, 0)])  # START_TRANSPARENT_SESSION
        time.sleep(0.03)

        # RF OFF
        self.manage_session([(0x83, 0)])  # TURN_OFF_RF
        time.sleep(0.03)

        # RF ON
        self.manage_session([(0x84, 0)])  # TURN_ON_RF
        time.sleep(0.021)

        print("[OK] Transparent session started")

    def end_transparent_session(self):
        """透過セッション終了"""
        try:
            self.manage_session([(0x83, 0)])  # RF OFF
        except:
            pass
        self.manage_session([(0x82, 0)])  # END

    def switch_protocol_felica(self):
        """FeliCaプロトコルに切り替え"""
        # SWITCH_PROTOCOL_TAG=0x8F, length=2, protocol=3 (FeliCa), param=0
        cmd = [0xFF, 0x50, 0x00, 0x02, 4, 0x8F, 0x02, 0x03, 0x00, 0x00]
        resp = self._ccid_escape(cmd)
        print(f"[OK] Switched to FeliCa protocol")
        return resp

    def transceive(self, data, timeout_ms=1000):
        """FeliCaコマンド送受信"""
        timeout_bytes = struct.pack('<I', timeout_ms * 1000)  # microseconds

        # Build command
        cmd_data = []
        # Timeout TLV
        cmd_data.extend([0x5F, 0x46, 0x04])
        cmd_data.extend(timeout_bytes)
        # Transceive TLV (0x95=TRANSCEIVE, 0x82=2-byte length)
        cmd_data.extend([0x95, 0x82, (len(data) >> 8) & 0xFF, len(data) & 0xFF])
        cmd_data.extend(data)

        cmd = [0xFF, 0x50, 0x00, 0x01, 0x00, (len(cmd_data) >> 8) & 0xFF, len(cmd_data) & 0xFF]
        cmd.extend(cmd_data)
        cmd.extend([0x00, 0x00, 0x00])

        resp = self._ccid_escape(cmd, timeout=timeout_ms + 1000)

        # Parse response - look for 0x97 (RESPONSE_DATA_TAG)
        i = 0
        while i < len(resp) - 1:
            tag = resp[i]
            if tag == 0x97:  # Response data
                i += 1
                length = resp[i]
                if length >= 0x80:
                    if length == 0x81:
                        length = resp[i+1]
                        i += 1
                    elif length == 0x82:
                        length = (resp[i+1] << 8) | resp[i+2]
                        i += 2
                i += 1
                return bytes(resp[i:i+length])
            elif tag == 0xC0:  # Status
                i += 1
                length = resp[i]
                i += 1
                status = resp[i:i+length]
                if length >= 3 and (status[1] != 0x90 or status[2] != 0x00):
                    if status[1] == 0x64 and status[2] == 0x00:
                        return None  # No card
                    raise Exception(f"Transceive error: {bytes(status).hex()}")
                i += length
            else:
                i += 1
                if i < len(resp):
                    i += resp[i] + 1

        return None

    def felica_polling(self, system_code=b'\xFF\xFF', time_slot=0):
        """FeliCa Polling"""
        # Polling command: length, cmd, system_code[2], request_code, time_slot
        cmd = bytes([6, 0x00, system_code[0], system_code[1], 0x01, time_slot])

        resp = self.transceive(cmd, timeout_ms=500)

        if resp and len(resp) >= 17:
            # Response: length, response_code, IDm[8], PMm[8], ...
            idm = resp[1:9]
            pmm = resp[9:17]
            return idm, pmm

        return None, None


def main():
    print("=== RC-S300 FeliCa Test (Sony NFC Port Library互換) ===\n")

    rcs = RCS300()

    try:
        rcs.open()
        rcs.start_transparent_session()
        rcs.switch_protocol_felica()

        print("\niPhoneをRC-S300に置いてください...")

        for i in range(20):
            idm, pmm = rcs.felica_polling()
            if idm:
                print(f"\n[OK] FeliCa検出!")
                print(f"  IDm: {idm.hex().upper()}")
                print(f"  PMm: {pmm.hex().upper()}")
                break
            print(".", end="", flush=True)
            time.sleep(0.3)
        else:
            print("\n[NG] カードが検出されませんでした")

        rcs.end_transparent_session()

    except Exception as e:
        print(f"\n[Error] {e}")
    finally:
        rcs.close()

    print("\n=== 完了 ===")


if __name__ == '__main__':
    main()
