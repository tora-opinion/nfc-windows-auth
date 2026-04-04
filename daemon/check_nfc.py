"""RC-S300とSuica読み取りの診断"""
import sys
sys.path.insert(0, r'C:\Users\suger.G-GEAR\nfc-windows-auth\daemon')
import winscard as sc

print("=== NFC診断 ===")

# コンテキスト確立
try:
    hctx = sc.establish_context()
    print("[OK] PC/SCコンテキスト確立")
except RuntimeError as e:
    print(f"[NG] PC/SCコンテキスト失敗: {e}")
    sys.exit(1)

# リーダー一覧
readers = sc.list_readers(hctx)
print(f"[INFO] 検出リーダー ({len(readers)}台):")
for r in readers:
    print(f"  - {r!r}")

if not readers:
    print("[NG] リーダーが見つかりません")
    sc.release_context(hctx)
    sys.exit(1)

# 各リーダーにカードがあるか試行
for reader in readers:
    print(f"\n[試行] {reader}")
    try:
        hcard, protocol = sc.connect(hctx, reader)
        print(f"  [OK] 接続成功 protocol=0x{protocol:X}")
        # Polling APDU
        try:
            resp = sc.transmit(hcard, protocol, [0xFF, 0xCA, 0x00, 0x00, 0x00])
            print(f"  [OK] レスポンス: {resp.hex().upper()}")
            if len(resp) >= 10 and resp[-2] == 0x90 and resp[-1] == 0x00:
                idm = resp[:8]
                print(f"  [OK] IDm: {idm.hex().upper()}")
            else:
                print(f"  [NG] SW1SW2: {resp[-2]:02X}{resp[-1]:02X} (FeliCaカードが必要)")
        except RuntimeError as e:
            print(f"  [NG] Transmit失敗: {e}")
        sc.disconnect(hcard)
    except RuntimeError as e:
        code = int(str(e).split('0x')[1], 16) if '0x' in str(e) else 0
        if sc.is_no_card_error(code):
            print(f"  [INFO] カードなし")
        else:
            print(f"  [NG] 接続失敗: {e}")

sc.release_context(hctx)
print("\n=== 診断完了 ===")
