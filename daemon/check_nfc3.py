"""nfcpy経由でRC-S300からFeliCa IDmを読む診断"""
import nfc
import sys

print("=== nfcpy FeliCa診断 ===")
print("iPhoneをRC-S300に置いてください...")

def on_connect(tag):
    print(f"\nタグ検出: {type(tag).__name__}")
    print(f"  IDm: {tag.identifier.hex().upper()}")
    if hasattr(tag, 'pmm'):
        print(f"  PMm: {tag.pmm.hex().upper()}")
    # Suica SF残高を読む
    if hasattr(tag, 'read_without_encryption'):
        try:
            sc_list = [nfc.tag.tt3.ServiceCode(0x008B >> 6, 0x008B & 0x3F)]
            bc_list = [nfc.tag.tt3.BlockCode(0, service=0)]
            data = tag.read_without_encryption(sc_list, bc_list)
            if data:
                balance = int.from_bytes(data[:2], 'little')
                print(f"  SF残高: {balance}円")
        except Exception as e:
            print(f"  SF読み取り失敗: {e}")
    return True  # タグを保持

try:
    with nfc.ContactlessFrontend('usb') as clf:
        print(f"リーダー: {clf}")
        clf.connect(rdwr={'on-connect': on_connect,
                          'targets': ['106A', '106B', '212F', '424F']})
except Exception as e:
    print(f"エラー: {e}")
    print("\n[ヒント] nfcpyはWinUSBドライバが必要な場合があります。")
    print("Zadig (https://zadig.akeo.ie) でRC-S300をWinUSBドライバに切り替えてください。")
    sys.exit(1)
