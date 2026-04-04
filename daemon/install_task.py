"""
reader.py をログオン時に自動起動するTask Schedulerタスクとして登録する。

Windows Serviceではなくタスクスケジューラを使う理由:
- デーモンはHKCU（ユーザーレジストリ）を読み書きするため、
  ユーザーセッションで動く必要がある（SYSTEMではHKCUが異なる）
"""
import os
import subprocess
import sys

TASK_NAME   = 'NfcAuthDaemon'
SCRIPT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reader.py')
PYTHON_EXE  = sys.executable


def register():
    cmd = [
        'schtasks', '/create',
        '/tn', TASK_NAME,
        '/tr', f'"{PYTHON_EXE}" "{SCRIPT_PATH}"',
        '/sc', 'ONLOGON',
        '/rl', 'HIGHEST',
        '/f',              # 既存タスクを上書き
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print(f'タスク "{TASK_NAME}" を登録しました。')
        print('次回ログイン時から自動起動します。')
        print('今すぐ起動するには: schtasks /run /tn NfcAuthDaemon')
    else:
        print(f'エラー: {result.stderr}')
        sys.exit(1)


def unregister():
    result = subprocess.run(
        ['schtasks', '/delete', '/tn', TASK_NAME, '/f'],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        print(f'タスク "{TASK_NAME}" を削除しました。')
    else:
        print(f'エラー: {result.stderr}')


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'uninstall':
        unregister()
    else:
        register()
