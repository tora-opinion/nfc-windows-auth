"""
RC-S300 pyusb direct test
Vendor ID: 0x054C (Sony)
Product ID: 0x0DC9 (PaSoRi 400 / RC-S300)
"""
import os
import usb.core
import usb.util
import usb.backend.libusb1 as libusb1
import time

VENDOR_ID = 0x054C
PRODUCT_ID = 0x0DC9

# libusb DLLを明示的に指定
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LIBUSB_DLL = os.path.join(SCRIPT_DIR, 'libusb-1.0.dll')

def get_backend():
    def find_library(name):
        if 'libusb' in name or '1.0' in name:
            return LIBUSB_DLL
        return None
    return libusb1.get_backend(find_library=find_library)

# RC-S380互換コマンド（RC-S300でも動く可能性）
CMD_ACK = bytes([0x00, 0x00, 0xff, 0x00, 0xff, 0x00])
CMD_SET_COMMAND_TYPE = bytes([0x00, 0x00, 0xff, 0xff, 0xff, 0x03, 0x00, 0xfd, 0xd6, 0x2a, 0x01, 0xff, 0x00])
CMD_SWITCH_RF = bytes([0x00, 0x00, 0xff, 0xff, 0xff, 0x03, 0x00, 0xfd, 0xd6, 0x06, 0x00, 0x24, 0x00])
CMD_IN_SET_RF = bytes([0x00, 0x00, 0xff, 0xff, 0xff, 0x06, 0x00, 0xfa, 0xd6, 0x00, 0x01, 0x01, 0x0f, 0x01, 0x18, 0x00])
CMD_IN_SET_PROTOCOL = bytes([
    0x00, 0x00, 0xff, 0xff, 0xff, 0x28, 0x00, 0xd8, 0xd6, 0x02, 0x00, 0x18, 0x01, 0x01,
    0x02, 0x01, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x08, 0x08, 0x00,
    0x09, 0x00, 0x0a, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x0e, 0x04, 0x0f, 0x00, 0x10, 0x00,
    0x11, 0x00, 0x12, 0x00, 0x13, 0x06, 0x4b, 0x00
])
CMD_IN_SET_PROTOCOL2 = bytes([0x00, 0x00, 0xff, 0xff, 0xff, 0x04, 0x00, 0xfc, 0xd6, 0x02, 0x00, 0x18, 0x10, 0x00])
# SENSF_REQ (FeliCa Polling) - System Code 0xFFFF (wildcard)
CMD_SENSF_REQ = bytes([
    0x00, 0x00, 0xff, 0xff, 0xff, 0x0a, 0x00, 0xf6, 0xd6, 0x04, 0x6e, 0x00,
    0x06, 0x00, 0xff, 0xff, 0x01, 0x00, 0xb3, 0x00
])

def find_device():
    """RC-S300を検索"""
    backend = get_backend()
    if backend is None:
        print(f"[NG] libusb backend not found. Ensure libusb-1.0.dll exists at: {LIBUSB_DLL}")
        return None

    dev = usb.core.find(idVendor=VENDOR_ID, idProduct=PRODUCT_ID, backend=backend)
    if dev is None:
        print(f"[NG] RC-S300 not found (VID={VENDOR_ID:04X}, PID={PRODUCT_ID:04X})")
        return None
    print(f"[OK] RC-S300 found: {dev.manufacturer} {dev.product}")
    return dev

def show_config(dev):
    """デバイス設定を表示"""
    print("\n=== Device Configuration ===")
    for cfg in dev:
        print(f"  Configuration {cfg.bConfigurationValue}")
        for intf in cfg:
            print(f"    Interface {intf.bInterfaceNumber}, AltSetting {intf.bAlternateSetting}")
            print(f"      Class: {intf.bInterfaceClass}, SubClass: {intf.bInterfaceSubClass}")
            for ep in intf:
                print(f"      Endpoint {ep.bEndpointAddress:#04x}: {usb.util.endpoint_direction(ep.bEndpointAddress)}")

def send_cmd(dev, ep_out, ep_in, cmd, expect_response=True):
    """コマンド送信"""
    try:
        dev.write(ep_out, cmd)
        time.sleep(0.01)
        if expect_response:
            resp = dev.read(ep_in, 64, timeout=1000)
            return bytes(resp)
    except usb.core.USBError as e:
        print(f"  USB Error: {e}")
        return None
    return b''

def main():
    print("=== RC-S300 pyusb Test ===\n")

    dev = find_device()
    if dev is None:
        return

    show_config(dev)

    # WinUSBインターフェース (1) を使用
    intf_num = 1

    try:
        if dev.is_kernel_driver_active(intf_num):
            dev.detach_kernel_driver(intf_num)
            print(f"[OK] Detached kernel driver from interface {intf_num}")
    except Exception as e:
        print(f"[INFO] Kernel driver: {e}")

    try:
        dev.set_configuration()
        print("[OK] Configuration set")
    except usb.core.USBError as e:
        print(f"[INFO] Set configuration: {e}")

    try:
        usb.util.claim_interface(dev, intf_num)
        print(f"[OK] Claimed interface {intf_num}")
    except usb.core.USBError as e:
        print(f"[NG] Claim interface failed: {e}")
        return

    # エンドポイントを取得
    cfg = dev.get_active_configuration()
    intf = cfg[(intf_num, 0)]

    ep_out = usb.util.find_descriptor(
        intf,
        custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT
    )
    ep_in = usb.util.find_descriptor(
        intf,
        custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN
    )

    if ep_out is None or ep_in is None:
        print("[NG] Endpoints not found")
        return

    print(f"[OK] OUT: {ep_out.bEndpointAddress:#04x}, IN: {ep_in.bEndpointAddress:#04x}")

    print("\n=== Sending Commands ===")

    # ACK
    print("Sending ACK...")
    resp = send_cmd(dev, ep_out, ep_in, CMD_ACK)
    if resp:
        print(f"  Response: {resp.hex().upper()}")

    # SetCommandType
    print("Sending SetCommandType...")
    resp = send_cmd(dev, ep_out, ep_in, CMD_SET_COMMAND_TYPE)
    if resp:
        print(f"  Response: {resp.hex().upper()}")

    # SwitchRF
    print("Sending SwitchRF...")
    resp = send_cmd(dev, ep_out, ep_in, CMD_SWITCH_RF)
    if resp:
        print(f"  Response: {resp.hex().upper()}")

    # InSetRF
    print("Sending InSetRF...")
    resp = send_cmd(dev, ep_out, ep_in, CMD_IN_SET_RF)
    if resp:
        print(f"  Response: {resp.hex().upper()}")

    # InSetProtocol
    print("Sending InSetProtocol...")
    resp = send_cmd(dev, ep_out, ep_in, CMD_IN_SET_PROTOCOL)
    if resp:
        print(f"  Response: {resp.hex().upper()}")

    print("Sending InSetProtocol2...")
    resp = send_cmd(dev, ep_out, ep_in, CMD_IN_SET_PROTOCOL2)
    if resp:
        print(f"  Response: {resp.hex().upper()}")

    # Polling
    print("\niPhoneをRC-S300に置いてください...")
    time.sleep(3)

    print("Sending SENSF_REQ (FeliCa Polling)...")
    for i in range(5):
        resp = send_cmd(dev, ep_out, ep_in, CMD_SENSF_REQ)
        if resp and len(resp) > 17:
            print(f"  Response ({len(resp)} bytes): {resp.hex().upper()}")
            # IDmは17-24バイト目
            if len(resp) >= 25:
                idm = resp[17:25]
                print(f"  IDm: {idm.hex().upper()}")
                break
        elif resp:
            print(f"  Response: {resp.hex().upper()}")
        time.sleep(0.5)

    # クリーンアップ
    usb.util.release_interface(dev, intf_num)
    print("\n[OK] Interface released")

if __name__ == '__main__':
    main()
