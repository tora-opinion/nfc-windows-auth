import json
import os
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / 'src'))

import nfc_common
from nfc_common import find_libusb, load_config, setup_logging


def test_load_config_reads_cp932_file(tmp_path):
    path = tmp_path / 'config.json'
    path.write_bytes(json.dumps({'name': '日本語'}, ensure_ascii=False).encode('cp932'))
    assert load_config(path, {})['name'] == '日本語'


def test_load_config_reads_utf8_bom_file(tmp_path):
    path = tmp_path / 'config.json'
    path.write_bytes(b'\xef\xbb\xbf' + json.dumps({'a': 1}).encode('utf-8'))
    assert load_config(path, {})['a'] == 1


def test_load_config_garbage_returns_defaults(tmp_path):
    path = tmp_path / 'config.json'
    path.write_bytes(b'\xff\xfe\x00not json')
    assert load_config(path, {'x': 1}) == {'x': 1}


def test_find_libusb_falls_back_to_program_files(tmp_path, monkeypatch):
    program_files = tmp_path / 'pf'
    dll = program_files / 'libusb' / 'libusb-1.0.dll'
    dll.parent.mkdir(parents=True)
    dll.write_bytes(b'')
    monkeypatch.setenv('PROGRAMFILES', str(program_files))
    empty_repo = tmp_path / 'repo'
    empty_repo.mkdir()
    assert find_libusb({}, empty_repo) == str(dll)


def test_setup_logging_survives_unwritable_log_dir(tmp_path, monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'local'))
    blocker = tmp_path / 'blocker'
    blocker.write_text('a file, so mkdir under it fails')
    logger = setup_logging('nfc_test_fallback', blocker / 'sub' / 'x.log')
    logger.info('hello')
    assert (tmp_path / 'local' / 'nfc-windows-auth' / 'x.log').exists()
