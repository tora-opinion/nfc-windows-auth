"""
NFC Auth 初回セットアップ
- iPhoneのSuicaをRC-S300で読み取りIDmを登録
- Windowsアカウントパスワードを暗号化して保存
  ※ CRYPTPROTECT_LOCAL_MACHINE を使うのでCredential Provider(SYSTEM)でも復号可能
"""
import getpass
import hashlib
import sys
import time
import winreg

import win32crypt
import winscard as sc

REG_REGISTERED = r'Software\NfcAuth\Registered'
POLL_APDU      = [0xFF, 0xCA, 0x00, 0x00, 0x00]

# CRYPTPROTECT_LOCAL_MACHINE: マシン単位暗号化 (SYSTEM でも復号可)
CRYPTPROTECT_LOCAL_MACHINE = 0x4


def _pick_reader(readers: list[str]) -> str:
    for r in readers:
        if 'RC-S300' in r or 'SONY' in r.upper() or 'NFC' in r.upper():
            return r
    return readers[0]


def _wait_for_card(hctx, reader: str):
    """カードが置かれるまでポーリング。(hcard, protocol) を返す。"""
    print('iPhoneをRC-S300の上に置いてください...', flush=True)
    while True:
        try:
            return sc.connect(hctx, reader)
        except RuntimeError:
            time.sleep(0.5)


def main():
    print('=== NFC Windows Auth セットアップ ===\n')

    try:
        hctx = sc.establish_context()
    except RuntimeError as e:
        print(f'エラー: {e}')
        sys.exit(1)

    readers = sc.list_readers(hctx)
    if not readers:
        print('エラー: NFCリーダーが見つかりません。RC-S300が接続されているか確認してください。')
        sc.release_context(hctx)
        sys.exit(1)

    reader = _pick_reader(readers)
    print(f'リーダー: {reader}\n')

    hcard, protocol = _wait_for_card(hctx, reader)

    try:
        resp = sc.transmit(hcard, protocol, POLL_APDU)
    except RuntimeError as e:
        print(f'IDm読み取り失敗: {e}')
        sc.disconnect(hcard)
        sc.release_context(hctx)
        sys.exit(1)

    sc.disconnect(hcard)
    sc.release_context(hctx)

    # SW1 SW2 チェック (レスポンス末尾2バイト)
    if len(resp) < 10 or resp[-2] != 0x90 or resp[-1] != 0x00:
        print('エラー: IDm読み取り失敗。Suicaカードですか？')
        sys.exit(1)

    idm      = bytes(resp[:8])
    idm_hash = hashlib.sha256(idm).hexdigest()
    print(f'Suica IDm: {idm.hex().upper()}')
    print(f'IDm Hash : {idm_hash}\n')

    print('Windowsアカウントのパスワードを入力してください。')
    print('（Windows Hello PINではなく、Microsoftアカウントまたはローカルアカウントのパスワード）')
    password = getpass.getpass('パスワード: ')
    if not password:
        print('エラー: パスワードが空です。')
        sys.exit(1)

    password_bytes = password.encode('utf-8')
    encrypted = win32crypt.CryptProtectData(
        password_bytes,
        'NfcAuthPassword',
        None, None, None,
        CRYPTPROTECT_LOCAL_MACHINE,
    )

    # メモリを即消去
    import ctypes
    buf = (ctypes.c_char * len(password_bytes)).from_buffer_copy(password_bytes)
    ctypes.memset(buf, 0, len(password_bytes))
    del password, password_bytes

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_REGISTERED) as k:
        winreg.SetValueEx(k, 'RegisteredIdmHash', 0, winreg.REG_SZ,     idm_hash)
        winreg.SetValueEx(k, 'EncryptedPin',       0, winreg.REG_BINARY, encrypted)

    print('\n登録完了！')
    print('次のステップ: py install_task.py を実行してデーモンを自動起動に登録してください。')


if __name__ == '__main__':
    main()
