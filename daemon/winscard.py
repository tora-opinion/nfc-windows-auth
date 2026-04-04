"""
winscard.py - Windows PC/SC API を ctypes で直接呼び出すラッパー
pyscard 不要。winscard.dll は Windows 標準。
"""
import ctypes
from ctypes import wintypes

_lib = ctypes.WinDLL('winscard.dll')

# ---------------------------------------------------------------------------
# 定数
# ---------------------------------------------------------------------------
SCARD_S_SUCCESS       = 0x00000000
SCARD_E_NO_READERS_AVAILABLE = 0x8010002E
SCARD_E_NO_SMARTCARD  = 0x8010000C
SCARD_W_REMOVED_CARD  = 0x80100069
SCARD_E_READER_UNAVAILABLE = 0x80100017

SCARD_SCOPE_USER      = 0
SCARD_SHARE_SHARED    = 2
SCARD_PROTOCOL_T0     = 0x0001
SCARD_PROTOCOL_T1     = 0x0002
SCARD_PROTOCOL_T0_T1  = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1
SCARD_LEAVE_CARD      = 0

# ---------------------------------------------------------------------------
# 型
# 64ビットWindowsでは SCARDCONTEXT/SCARDHANDLE は ULONG_PTR (8バイト)
# c_ulong は Windows では常に4バイトなので c_size_t を使う
# ---------------------------------------------------------------------------
SCARDCONTEXT = ctypes.c_size_t
SCARDHANDLE  = ctypes.c_size_t

class SCARD_IO_REQUEST(ctypes.Structure):
    _fields_ = [
        ('dwProtocol',  wintypes.DWORD),
        ('cbPciLength', wintypes.DWORD),
    ]

# T0/T1 プロトコル用 PCI (定数値)
_PCI_T0  = SCARD_IO_REQUEST(dwProtocol=SCARD_PROTOCOL_T0,  cbPciLength=8)
_PCI_T1  = SCARD_IO_REQUEST(dwProtocol=SCARD_PROTOCOL_T1,  cbPciLength=8)

def _pci(protocol: int) -> SCARD_IO_REQUEST:
    return _PCI_T1 if protocol & SCARD_PROTOCOL_T1 else _PCI_T0

# ---------------------------------------------------------------------------
# 関数プロトタイプ
# ---------------------------------------------------------------------------
_lib.SCardEstablishContext.restype  = wintypes.LONG
_lib.SCardEstablishContext.argtypes = [
    wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.POINTER(SCARDCONTEXT),
]

_lib.SCardReleaseContext.restype  = wintypes.LONG
_lib.SCardReleaseContext.argtypes = [SCARDCONTEXT]

_lib.SCardListReadersW.restype  = wintypes.LONG
_lib.SCardListReadersW.argtypes = [
    SCARDCONTEXT, ctypes.c_wchar_p, ctypes.c_wchar_p,
    ctypes.POINTER(wintypes.DWORD),
]

_lib.SCardConnectW.restype  = wintypes.LONG
_lib.SCardConnectW.argtypes = [
    SCARDCONTEXT, ctypes.c_wchar_p,
    wintypes.DWORD, wintypes.DWORD,
    ctypes.POINTER(SCARDHANDLE), ctypes.POINTER(wintypes.DWORD),
]

_lib.SCardDisconnect.restype  = wintypes.LONG
_lib.SCardDisconnect.argtypes = [SCARDHANDLE, wintypes.DWORD]

_lib.SCardTransmit.restype  = wintypes.LONG
_lib.SCardTransmit.argtypes = [
    SCARDHANDLE,
    ctypes.POINTER(SCARD_IO_REQUEST),
    ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD,
    ctypes.POINTER(SCARD_IO_REQUEST),
    ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(wintypes.DWORD),
]

# ---------------------------------------------------------------------------
# 高レベルAPI
# ---------------------------------------------------------------------------

def establish_context() -> SCARDCONTEXT:
    """PC/SC コンテキストを確立。失敗時は RuntimeError。"""
    hctx = SCARDCONTEXT(0)
    ret  = _lib.SCardEstablishContext(SCARD_SCOPE_USER, None, None, ctypes.byref(hctx))
    if ret != SCARD_S_SUCCESS:
        raise RuntimeError(f'SCardEstablishContext: 0x{ret & 0xFFFFFFFF:08X}')
    return hctx


def release_context(hctx: SCARDCONTEXT):
    _lib.SCardReleaseContext(hctx)


def list_readers(hctx: SCARDCONTEXT) -> list[str]:
    """利用可能なリーダー名のリストを返す。"""
    pcch = wintypes.DWORD(0)
    ret  = _lib.SCardListReadersW(hctx, None, None, ctypes.byref(pcch))
    if ret != SCARD_S_SUCCESS or pcch.value == 0:
        return []
    buf = ctypes.create_unicode_buffer(pcch.value)
    ret = _lib.SCardListReadersW(hctx, None, buf, ctypes.byref(pcch))
    if ret != SCARD_S_SUCCESS:
        return []
    # マルチ文字列（ヌル区切り、ダブルヌル終端）をパース
    raw   = bytes(buf)[:pcch.value * 2]
    text  = raw.decode('utf-16-le', errors='replace')
    return [r for r in text.split('\x00') if r]


def connect(hctx: SCARDCONTEXT, reader: str):
    """カードに接続。(hcard, protocol) を返す。失敗時は RuntimeError。"""
    hcard    = SCARDHANDLE(0)
    protocol = wintypes.DWORD(0)
    ret = _lib.SCardConnectW(
        hctx, reader,
        SCARD_SHARE_SHARED,
        SCARD_PROTOCOL_T0_T1,
        ctypes.byref(hcard),
        ctypes.byref(protocol),
    )
    if ret != SCARD_S_SUCCESS:
        raise RuntimeError(f'SCardConnect: 0x{ret & 0xFFFFFFFF:08X}')
    return hcard, protocol.value


def disconnect(hcard: SCARDHANDLE):
    _lib.SCardDisconnect(hcard, SCARD_LEAVE_CARD)


def transmit(hcard: SCARDHANDLE, protocol: int, apdu: list[int]) -> bytes:
    """APDUを送信してレスポンスバイト列を返す。失敗時は RuntimeError。"""
    send_buf  = (ctypes.c_ubyte * len(apdu))(*apdu)
    recv_buf  = (ctypes.c_ubyte * 512)()
    recv_len  = wintypes.DWORD(512)
    pci       = _pci(protocol)
    ret = _lib.SCardTransmit(
        hcard,
        ctypes.byref(pci),
        send_buf, len(apdu),
        None,
        recv_buf,
        ctypes.byref(recv_len),
    )
    if ret != SCARD_S_SUCCESS:
        raise RuntimeError(f'SCardTransmit: 0x{ret & 0xFFFFFFFF:08X}')
    return bytes(recv_buf[:recv_len.value])


def is_no_card_error(code: int) -> bool:
    masked = code & 0xFFFFFFFF
    return masked in (SCARD_E_NO_SMARTCARD, SCARD_W_REMOVED_CARD,
                      SCARD_E_READER_UNAVAILABLE)
