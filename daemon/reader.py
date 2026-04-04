"""
NFC Auth Daemon - RC-S300でiPhone SuicaのIDmを読み取りWindowsレジストリに認証状態を書き込む
pyscard不要。winscard.dll を ctypes 経由で直接使用。
"""
import hashlib
import logging
import sys
import time
import winreg

import winscard as sc

LOG_PATH       = r'C:\Users\suger.G-GEAR\nfc-windows-auth\daemon\nfc_daemon.log'
REG_STATE      = r'Software\NfcAuth\State'
REG_REGISTERED = r'Software\NfcAuth\Registered'

POLL_APDU = [0xFF, 0xCA, 0x00, 0x00, 0x00]

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH, encoding='utf-8'),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger(__name__)


def _read_idm(hcard, protocol: int) -> bytes | None:
    """FeliCa Polling (FF CA 00 00 00) でIDm 8バイトを返す。失敗時None。"""
    try:
        resp = sc.transmit(hcard, protocol, POLL_APDU)
    except RuntimeError:
        return None
    if len(resp) >= 10 and resp[-2] == 0x90 and resp[-1] == 0x00:
        return bytes(resp[:8])
    return None


def _read_sf_balance(hcard, protocol: int, idm: bytes) -> int | None:
    """
    Read Without Encryption で Suica SF残高 (Service Code 0x008B, Block 0) を読む。
    """
    body = [0x06] + list(idm) + [0x01, 0x8B, 0x00, 0x01, 0x80, 0x00]
    length = len(body) + 1
    apdu = [0xFF, 0xB0, 0x00, 0x00, len([length] + body)] + [length] + body
    try:
        resp = sc.transmit(hcard, protocol, apdu)
    except RuntimeError:
        return None
    if len(resp) < 30 or resp[-2] != 0x90 or resp[-1] != 0x00:
        return None
    # レスポンス: [len][09][IDm 8B][status1][status2][num_blocks][block_data 16B]
    # block_data は offset=12 (status2まで = offset11)
    block_data = resp[12:28]
    return int.from_bytes(block_data[:2], 'little')


def _get_registered_hash() -> str | None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_REGISTERED) as k:
            val, _ = winreg.QueryValueEx(k, 'RegisteredIdmHash')
            return val
    except FileNotFoundError:
        return None


def _write_state(idm_hash: str, tap_ms: int, auth_valid: int):
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_STATE) as k:
        winreg.SetValueEx(k, 'LastIdmHash', 0, winreg.REG_SZ,    idm_hash)
        winreg.SetValueEx(k, 'LastTapTime', 0, winreg.REG_QWORD, tap_ms)
        winreg.SetValueEx(k, 'AuthValid',   0, winreg.REG_DWORD, auth_valid)


def _clear_auth():
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_STATE) as k:
            winreg.SetValueEx(k, 'AuthValid', 0, winreg.REG_DWORD, 0)
    except Exception:
        pass


def _pick_reader(readers: list[str]) -> str:
    for r in readers:
        if 'RC-S300' in r or 'SONY' in r.upper() or 'NFC' in r.upper() or 'FELICA' in r.upper():
            return r
    return readers[0]


def main():
    log.info('NFC Auth Daemon 起動')
    if not _get_registered_hash():
        log.warning('登録済みSuicaがありません。register.py を実行してください。')

    while True:
        try:
            hctx = sc.establish_context()
            readers = sc.list_readers(hctx)
            if not readers:
                sc.release_context(hctx)
                time.sleep(2)
                continue

            reader = _pick_reader(readers)

            try:
                hcard, protocol = sc.connect(hctx, reader)
            except RuntimeError as e:
                err_code = int(str(e).split('0x')[1], 16) if '0x' in str(e) else 0
                if sc.is_no_card_error(err_code):
                    _clear_auth()
                else:
                    log.debug('connect: %s', e)
                    _clear_auth()
                sc.release_context(hctx)
                time.sleep(1)
                continue

            idm = _read_idm(hcard, protocol)
            if idm:
                idm_hash      = hashlib.sha256(idm).hexdigest()
                tap_ms        = int(time.time() * 1000)
                registered    = _get_registered_hash()
                auth_valid    = 1 if (registered and idm_hash == registered) else 0
                _write_state(idm_hash, tap_ms, auth_valid)

                balance = _read_sf_balance(hcard, protocol, idm)
                sf_str  = f'{balance}円' if balance is not None else '(読み取り失敗)'
                status  = 'OK' if auth_valid else 'MISMATCH'
                log.info('カード検出 IDm=%s SF=%s Auth=%s', idm.hex().upper(), sf_str, status)
            else:
                _clear_auth()
                log.debug('カードあり IDm読み取り失敗')

            sc.disconnect(hcard)
            sc.release_context(hctx)

        except Exception as exc:
            log.error('予期せぬエラー: %s', exc)
            _clear_auth()

        time.sleep(1)


if __name__ == '__main__':
    main()
