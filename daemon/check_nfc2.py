"""RC-S300 詳細診断 - ATR確認とFeliCa直接コマンド"""
import sys, ctypes
from ctypes import wintypes
sys.path.insert(0, r'C:\Users\suger.G-GEAR\nfc-windows-auth\daemon')
import winscard as sc

# SCardGetAttrib を追加で定義
_lib = sc._lib
SCARD_ATTR_ATR_STRING = 0x00090303
_lib.SCardGetAttrib.restype  = wintypes.LONG
_lib.SCardGetAttrib.argtypes = [
    sc.SCARDHANDLE,
    wintypes.DWORD,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(wintypes.DWORD),
]

def get_atr(hcard):
    size = wintypes.DWORD(256)
    buf  = (ctypes.c_ubyte * 256)()
    ret  = _lib.SCardGetAttrib(hcard, SCARD_ATTR_ATR_STRING, buf, ctypes.byref(size))
    if ret == 0:
        return bytes(buf[:size.value])
    return None

print("=== NFC詳細診断 ===")
hctx = sc.establish_context()
readers = sc.list_readers(hctx)
reader  = readers[0]
print(f"Reader: {reader}")

hcard, protocol = sc.connect(hctx, reader)
print(f"Protocol: 0x{protocol:X} ({'T=1/FeliCa' if protocol==2 else 'T=0'})")

# ATR確認
atr = get_atr(hcard)
if atr:
    print(f"ATR: {atr.hex().upper()}")
    # FeliCa ATRは "3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 xx xx xx xx 00" パターン
    # IDmはATRの9-16バイト目に含まれる場合がある
    if len(atr) >= 17 and atr[0] == 0x3B:
        print(f"  IDm候補(ATR[9:17]): {atr[9:17].hex().upper()}")
else:
    print("ATR取得失敗")

# FF CA 00 00 00 (通常のUID/IDm取得)
resp = sc.transmit(hcard, protocol, [0xFF, 0xCA, 0x00, 0x00, 0x00])
print(f"\nFF CA 00 00 00: {resp.hex().upper()} ({len(resp)-2}バイト)")

# FF CA 01 00 00 (FeliCa専用IDm)
resp2 = sc.transmit(hcard, protocol, [0xFF, 0xCA, 0x01, 0x00, 0x00])
print(f"FF CA 01 00 00: {resp2.hex().upper()} ({len(resp2)-2}バイト)")

# FeliCa直接Polling (06 04 FF FF 00)
# APDU: FF B0 00 00 05 [06 04 FF FF 00]
felica_poll = [0xFF, 0xB0, 0x00, 0x00, 0x06, 0x06, 0x04, 0xFF, 0xFF, 0x00, 0x00]
try:
    resp3 = sc.transmit(hcard, protocol, felica_poll)
    print(f"FeliCa Polling:  {resp3.hex().upper()} ({len(resp3)-2}バイト)")
    if len(resp3) >= 10:
        print(f"  IDm候補: {resp3[1:9].hex().upper()}")
except Exception as e:
    print(f"FeliCa Polling失敗: {e}")

sc.disconnect(hcard)
sc.release_context(hctx)
