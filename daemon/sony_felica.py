"""
sony_felica.py - Sony felica.dll を ctypes で直接呼び出すラッパー
PC/SC APIではなくSony独自APIを使用してFeliCaにアクセス
iPhone Express Card (Suica) の読み取りに対応

Based on: https://github.com/tmurakam/felicalib
"""
import ctypes
from ctypes import wintypes
import os

# felica.dll のパス
FELICA_DLL_PATH = r"C:\Program Files\Common Files\Sony Shared\FeliCaLibrary\felica.dll"

if not os.path.exists(FELICA_DLL_PATH):
    raise FileNotFoundError(f"felica.dll not found: {FELICA_DLL_PATH}")

# WinDLL (stdcall) で呼び出し
_lib = ctypes.WinDLL(FELICA_DLL_PATH)

# ---------------------------------------------------------------------------
# 構造体定義 (felicalib/felicaint.h より)
# ---------------------------------------------------------------------------

class POLLING(ctypes.Structure):
    """ポーリングパラメータ"""
    _fields_ = [
        ('system_code', ctypes.POINTER(ctypes.c_ubyte)),  # 2バイトへのポインタ
        ('time_slot', ctypes.c_ubyte),
    ]

class CARD_INFO(ctypes.Structure):
    """カード情報 (IDm, PMm)"""
    _fields_ = [
        ('card_idm', ctypes.POINTER(ctypes.c_ubyte)),  # 8バイトへのポインタ
        ('card_pmm', ctypes.POINTER(ctypes.c_ubyte)),  # 8バイトへのポインタ
    ]

class INSTR_READ_BLOCK(ctypes.Structure):
    """Read Without Encryption 入力パラメータ"""
    _fields_ = [
        ('card_idm', ctypes.POINTER(ctypes.c_ubyte)),  # 8バイトへのポインタ
        ('number_of_services', ctypes.c_ubyte),
        ('service_code_list', ctypes.POINTER(ctypes.c_ubyte)),
        ('number_of_blocks', ctypes.c_ubyte),
        ('block_list', ctypes.POINTER(ctypes.c_ubyte)),
    ]

class OUTSTR_READ_BLOCK(ctypes.Structure):
    """Read Without Encryption 出力パラメータ (全てポインタ)"""
    _fields_ = [
        ('status_flag_1', ctypes.POINTER(ctypes.c_ubyte)),
        ('status_flag_2', ctypes.POINTER(ctypes.c_ubyte)),
        ('result_number_of_blocks', ctypes.POINTER(ctypes.c_ubyte)),
        ('block_data', ctypes.POINTER(ctypes.c_ubyte)),  # 16バイト * ブロック数
    ]

# ---------------------------------------------------------------------------
# 関数プロトタイプ (戻り値はintだがboolとして扱う: 0=失敗, 非0=成功)
# ---------------------------------------------------------------------------

# int initialize_library(void)
_lib.initialize_library.restype = ctypes.c_int
_lib.initialize_library.argtypes = []

# int dispose_library(void)
_lib.dispose_library.restype = ctypes.c_int
_lib.dispose_library.argtypes = []

# int open_reader_writer_auto(void)
_lib.open_reader_writer_auto.restype = ctypes.c_int
_lib.open_reader_writer_auto.argtypes = []

# int close_reader_writer(void)
_lib.close_reader_writer.restype = ctypes.c_int
_lib.close_reader_writer.argtypes = []

# void set_polling_timeout(int)
_lib.set_polling_timeout.restype = None
_lib.set_polling_timeout.argtypes = [ctypes.c_int]

# void set_retry_count(int)
_lib.set_retry_count.restype = None
_lib.set_retry_count.argtypes = [ctypes.c_int]

# int polling_and_get_card_information(polling*, num_cards*, card_info*)
_lib.polling_and_get_card_information.restype = ctypes.c_int
_lib.polling_and_get_card_information.argtypes = [
    ctypes.POINTER(POLLING),
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(CARD_INFO),
]

# int read_block_without_encryption(irb*, orb*)
_lib.read_block_without_encryption.restype = ctypes.c_int
_lib.read_block_without_encryption.argtypes = [
    ctypes.POINTER(INSTR_READ_BLOCK),
    ctypes.POINTER(OUTSTR_READ_BLOCK),
]

# ---------------------------------------------------------------------------
# 高レベルAPI
# ---------------------------------------------------------------------------

_initialized = False
_reader_open = False

def initialize() -> bool:
    """ライブラリ初期化"""
    global _initialized
    if _initialized:
        return True
    result = _lib.initialize_library()
    print(f"  [DEBUG] initialize_library() = {result}")
    if result:
        _initialized = True
    return bool(result)

def dispose():
    """ライブラリ終了"""
    global _initialized, _reader_open
    if _reader_open:
        close_reader()
    if _initialized:
        _lib.dispose_library()
        _initialized = False

def open_reader() -> bool:
    """リーダー自動検出・接続"""
    global _reader_open
    if _reader_open:
        return True
    result = _lib.open_reader_writer_auto()
    print(f"  [DEBUG] open_reader_writer_auto() = {result}")
    if result:
        _reader_open = True
        # ポーリングパラメータ設定
        _lib.set_polling_timeout(200)
        _lib.set_retry_count(10)
    return bool(result)

def close_reader():
    """リーダー切断"""
    global _reader_open
    if _reader_open:
        _lib.close_reader_writer()
        _reader_open = False

def polling(system_code: bytes = b'\xFF\xFF') -> tuple[bytes, bytes] | None:
    """
    FeliCa Polling

    Args:
        system_code: システムコード (2バイト), デフォルトはワイルドカード

    Returns:
        (IDm, PMm) タプル、カードなしの場合はNone
    """
    # システムコードバッファ
    sc_buf = (ctypes.c_ubyte * 2)(*system_code)

    # ポーリングパラメータ
    poll = POLLING()
    poll.system_code = ctypes.cast(sc_buf, ctypes.POINTER(ctypes.c_ubyte))
    poll.time_slot = 0

    # カード情報バッファ
    idm_buf = (ctypes.c_ubyte * 8)()
    pmm_buf = (ctypes.c_ubyte * 8)()

    card_info = CARD_INFO()
    card_info.card_idm = ctypes.cast(idm_buf, ctypes.POINTER(ctypes.c_ubyte))
    card_info.card_pmm = ctypes.cast(pmm_buf, ctypes.POINTER(ctypes.c_ubyte))

    num_cards = ctypes.c_ubyte(0)

    result = _lib.polling_and_get_card_information(
        ctypes.byref(poll),
        ctypes.byref(num_cards),
        ctypes.byref(card_info),
    )

    if result and num_cards.value > 0:
        idm = bytes(idm_buf)
        pmm = bytes(pmm_buf)
        return (idm, pmm)
    return None

def read_block(
    idm: bytes,
    service_code: int,
    block_number: int = 0,
) -> bytes | None:
    """
    暗号化なしブロック読み取り

    Args:
        idm: カードIDm (8バイト)
        service_code: サービスコード (例: 0x008B for Suica SF残高)
        block_number: ブロック番号

    Returns:
        ブロックデータ (16バイト)、失敗時はNone
    """
    if len(idm) != 8:
        raise ValueError("IDm must be 8 bytes")

    # IDmバッファ
    idm_buf = (ctypes.c_ubyte * 8)(*idm)

    # サービスコード (リトルエンディアン)
    sc_buf = (ctypes.c_ubyte * 2)(service_code & 0xFF, (service_code >> 8) & 0xFF)

    # ブロックリスト (2バイト形式: 0x80 | サービスインデックス, ブロック番号)
    bl_buf = (ctypes.c_ubyte * 2)(0x80, block_number)

    # 入力パラメータ
    irb = INSTR_READ_BLOCK()
    irb.card_idm = ctypes.cast(idm_buf, ctypes.POINTER(ctypes.c_ubyte))
    irb.number_of_services = 1
    irb.service_code_list = ctypes.cast(sc_buf, ctypes.POINTER(ctypes.c_ubyte))
    irb.number_of_blocks = 1
    irb.block_list = ctypes.cast(bl_buf, ctypes.POINTER(ctypes.c_ubyte))

    # 出力パラメータ用バッファ
    status1 = ctypes.c_ubyte(0)
    status2 = ctypes.c_ubyte(0)
    num_blocks = ctypes.c_ubyte(0)
    block_data = (ctypes.c_ubyte * 16)()

    orb = OUTSTR_READ_BLOCK()
    orb.status_flag_1 = ctypes.pointer(status1)
    orb.status_flag_2 = ctypes.pointer(status2)
    orb.result_number_of_blocks = ctypes.pointer(num_blocks)
    orb.block_data = ctypes.cast(block_data, ctypes.POINTER(ctypes.c_ubyte))

    result = _lib.read_block_without_encryption(
        ctypes.byref(irb),
        ctypes.byref(orb),
    )

    if result and status1.value == 0:
        return bytes(block_data)
    return None

def read_suica_balance(idm: bytes) -> int | None:
    """
    Suica SF残高読み取り

    Args:
        idm: カードIDm (8バイト)

    Returns:
        残高（円）、失敗時はNone
    """
    # Suica SF残高: Service Code 0x008B, Block 0
    block = read_block(idm, 0x008B, 0)
    if block:
        # 残高は先頭2バイト、リトルエンディアン
        balance = int.from_bytes(block[0:2], 'little')
        return balance
    return None

# ---------------------------------------------------------------------------
# テスト
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=== Sony felica.dll テスト ===")

    if not initialize():
        print("[NG] initialize_library 失敗")
        exit(1)
    print("[OK] initialize_library")

    if not open_reader():
        print("[NG] open_reader_writer_auto 失敗")
        dispose()
        exit(1)
    print("[OK] open_reader_writer_auto (RC-S300検出)")

    print("\niPhoneをRC-S300にかざしてください...")

    import time
    for i in range(30):
        result = polling(b'\xFF\xFF')  # ワイルドカード
        if result:
            idm, pmm = result
            print(f"\n[OK] カード検出!")
            print(f"  IDm: {idm.hex().upper()}")
            print(f"  PMm: {pmm.hex().upper()}")

            # Suica残高読み取り
            balance = read_suica_balance(idm)
            if balance is not None:
                print(f"  SF残高: {balance}円")
            else:
                print("  SF残高: 読み取り失敗")
            break
        time.sleep(0.5)
    else:
        print("\n[NG] タイムアウト - カードが検出されませんでした")

    close_reader()
    dispose()
    print("\n=== テスト完了 ===")
