"""
SCardControl で RC-S300 を FeliCa 専用ポーリングに設定できるか試す。
カードなしで SCARD_SHARE_DIRECT 接続 → SCardControl で設定 → iPhone を置く
"""
import ctypes, sys, time
from ctypes import wintypes
sys.path.insert(0, r'C:\Users\suger.G-GEAR\nfc-windows-auth\daemon')
import winscard as sc

_lib = sc._lib

# SCardControl
SCARD_CTL_CODE = lambda n: (0x31 << 16) | (n << 2)
IOCTL_CCID_ESCAPE = SCARD_CTL_CODE(3500)   # 0x003136A0
IOCTL_VENDOR      = SCARD_CTL_CODE(2049)   # 0x00312004

_lib.SCardControl.restype  = wintypes.LONG
_lib.SCardControl.argtypes = [
    sc.SCARDHANDLE,
    wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]

SCARD_SHARE_DIRECT = 3

def scard_control(hcard, ioctl, data: bytes) -> bytes | None:
    inbuf  = (ctypes.c_ubyte * len(data))(*data)
    outbuf = (ctypes.c_ubyte * 512)()
    outlen = wintypes.DWORD(512)
    ret = _lib.SCardControl(hcard, ioctl, inbuf, len(data), outbuf, 512, ctypes.byref(outlen))
    if ret == 0:
        return bytes(outbuf[:outlen.value])
    return None

# ---- FeliCa Polling 設定コマンド候補 ----
# RC-S300/380 系の Sony 固有コマンドを試す
FELICA_CFG_CMDS = {
    'Set polling params (F003=Suica)': bytes([0xFF, 0x50, 0x00, 0x00, 0x04, 0x8F, 0x00, 0x03, 0x00]),
    'FeliCa-only type select':         bytes([0xFF, 0x50, 0x01, 0x00, 0x01, 0x04]),
    'RC-S380 FeliCa mode':             bytes([0x6E, 0x00, 0x08, 0x01, 0x01]),
}

print("=== SCardControl FeliCa設定テスト ===")
hctx = sc.establish_context()
readers = sc.list_readers(hctx)
reader = readers[0]
print(f"Reader: {reader}")

# SCARD_SHARE_DIRECT でカードなし接続
hcard = sc.SCARDHANDLE(0)
proto  = wintypes.DWORD(0)
ret = _lib.SCardConnectW(hctx, reader, SCARD_SHARE_DIRECT, 0,
                         ctypes.byref(hcard), ctypes.byref(proto))
print(f"Direct connect: 0x{ret & 0xFFFFFFFF:08X} {'OK' if ret==0 else 'NG'}")

if ret == 0:
    for name, cmd in FELICA_CFG_CMDS.items():
        r1 = scard_control(hcard, IOCTL_CCID_ESCAPE, cmd)
        r2 = scard_control(hcard, IOCTL_VENDOR, cmd)
        print(f"  [{name}]")
        print(f"    CCID_ESCAPE: {r1.hex().upper() if r1 is not None else 'NG'}")
        print(f"    VENDOR:      {r2.hex().upper() if r2 is not None else 'NG'}")

    sc.disconnect(hcard)

sc.release_context(hctx)
print()

# --- 通常接続で UID を2回読んで一致するか確認 ---
print("同じ UID が返るか確認中（iPhone を置いたまま3回読みます）...")
hctx = sc.establish_context()
uids = []
for i in range(3):
    try:
        hcard2, proto2 = sc.connect(hctx, reader)
        resp = sc.transmit(hcard2, proto2, [0xFF, 0xCA, 0x00, 0x00, 0x00])
        uid  = resp[:-2].hex().upper()
        uids.append(uid)
        print(f"  [{i+1}] UID: {uid}")
        sc.disconnect(hcard2)
        time.sleep(1)
    except Exception as e:
        print(f"  [{i+1}] 失敗: {e}")
        time.sleep(1)

sc.release_context(hctx)
if len(set(uids)) == 1 and uids:
    print(f"\n→ UID が一定！ '{uids[0]}' を認証トークンとして使えます")
else:
    print(f"\n→ UID がランダムに変わっています（FeliCa直接読み取りが必要）")
