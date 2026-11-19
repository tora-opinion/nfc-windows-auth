import hashlib
import json
import sys
from types import SimpleNamespace
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / 'src'))

import nfc_store
from nfc_store import (
    add_card,
    ensure_data_dir,
    find_card,
    get_data_dir,
    idm_mac,
    load_cards,
    load_key,
    load_settings,
    remove_card,
)


def _use_data_dir(monkeypatch, path):
    monkeypatch.setenv('NFCAUTH_DATA_DIR', str(path))
    # Keep the test process able to read/write its temporary directory even when
    # it is running under a non-elevated Windows token.
    monkeypatch.setattr(
        nfc_store, '_apply_protected_acl', lambda _path, **_kwargs: None
    )


def test_get_data_dir_uses_environment_override(tmp_path, monkeypatch):
    _use_data_dir(monkeypatch, tmp_path / 'private-state')
    assert get_data_dir() == tmp_path / 'private-state'
    assert ensure_data_dir(apply_acl=False) == tmp_path / 'private-state'
    assert (tmp_path / 'private-state').is_dir()


def test_acl_is_protected_and_grants_only_system_and_administrators(monkeypatch, tmp_path):
    calls = []
    fake_security = SimpleNamespace(
        SDDL_REVISION_1=1,
        OWNER_SECURITY_INFORMATION=1,
        GROUP_SECURITY_INFORMATION=2,
        DACL_SECURITY_INFORMATION=4,
        PROTECTED_DACL_SECURITY_INFORMATION=-2147483648,
        ConvertStringSecurityDescriptorToSecurityDescriptor=(
            lambda sddl, revision: calls.append(('sddl', sddl, revision)) or object()
        ),
        SetFileSecurity=(
            lambda path, flags, descriptor:
            calls.append(('set', path, flags, descriptor))
        ),
    )
    monkeypatch.setitem(sys.modules, 'win32security', fake_security)

    nfc_store._apply_protected_acl(tmp_path, directory=True)

    assert calls[0] == (
        'sddl', 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)',
        fake_security.SDDL_REVISION_1,
    )
    # Owner and group travel with the DACL: an owner can rewrite a DACL.
    assert calls[1][0:3] == ('set', str(tmp_path), -2147483641)

    calls.clear()
    nfc_store._apply_protected_acl(tmp_path)
    assert calls[0] == (
        'sddl', 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)',
        fake_security.SDDL_REVISION_1,
    )


def test_load_key_creates_and_reuses_32_random_bytes(tmp_path, monkeypatch):
    _use_data_dir(monkeypatch, tmp_path)

    first = load_key()
    second = load_key()

    assert len(first) == 32
    assert first == second
    assert (tmp_path / 'hmac.key').read_bytes() == first


def test_load_key_applies_acl_to_empty_temp_file_before_writing(tmp_path, monkeypatch):
    _use_data_dir(monkeypatch, tmp_path)
    events = []
    original_fdopen = nfc_store.os.fdopen

    def record_acl(path, directory=False, verify_existing=False):
        path = Path(path)
        if not directory:
            events.append(('acl', path, path.stat().st_size))

    class RecordingFile:
        def __init__(self, wrapped):
            self.wrapped = wrapped

        def __enter__(self):
            self.wrapped.__enter__()
            return self

        def __exit__(self, *args):
            return self.wrapped.__exit__(*args)

        def write(self, content):
            assert events[-1][0] == 'acl'
            assert events[-1][1].name.startswith('.hmac.key.')
            assert events[-1][2] == 0
            events.append(('write', len(content)))
            return self.wrapped.write(content)

        def flush(self):
            return self.wrapped.flush()

        def fileno(self):
            return self.wrapped.fileno()

    monkeypatch.setattr(nfc_store, '_apply_protected_acl', record_acl)
    monkeypatch.setattr(
        nfc_store.os,
        'fdopen',
        lambda descriptor, mode: RecordingFile(original_fdopen(descriptor, mode)),
    )

    key = load_key()

    assert len(key) == 32
    assert events[-1] == ('write', 32)
    assert events[-2][0] == 'acl'
    assert events[-2][2] == 0
    assert (tmp_path / 'hmac.key').read_bytes() == key
    assert not list(tmp_path.glob('.hmac.key.*.tmp'))


def test_load_key_reads_the_winning_key_when_another_process_creates_it(
    tmp_path, monkeypatch
):
    _use_data_dir(monkeypatch, tmp_path)
    key_path = tmp_path / 'hmac.key'
    winning_key = b'w' * 32

    def competing_link(_source, destination):
        Path(destination).write_bytes(winning_key)
        raise FileExistsError

    monkeypatch.setattr(nfc_store.os, 'link', competing_link)

    assert load_key() == winning_key
    assert key_path.read_bytes() == winning_key
    assert not list(tmp_path.glob('.hmac.key.*.tmp'))


@pytest.mark.parametrize('stored_key', [b'', b'x' * 31, b'x' * 33])
def test_load_key_rejects_wrong_length_without_regenerating(
    tmp_path, monkeypatch, stored_key
):
    _use_data_dir(monkeypatch, tmp_path)
    key_path = tmp_path / 'hmac.key'
    key_path.write_bytes(stored_key)
    monkeypatch.setattr(
        nfc_store.secrets,
        'token_bytes',
        lambda *_args: pytest.fail('must not silently regenerate a stored key'),
    )

    with pytest.raises(ValueError, match='hmac.key must contain exactly 32 bytes'):
        load_key()

    assert key_path.read_bytes() == stored_key


def test_idm_mac_matches_hmac_sha256_vector_and_changes_with_key():
    key = bytes.fromhex('0b' * 20)
    idm = b'Hi There'
    assert idm_mac(idm, key) == (
        'b0344c61d8db38535ca8afceaf0bf12b'
        '881dc200c9833da726e9376c2e32cff7'
    )
    assert idm_mac(idm, key) != idm_mac(idm, b'different key')


@pytest.mark.parametrize(('stored_ttl', 'expected'), [
    (1, 5),
    (30, 30),
    (999, 120),
    ('bad', 30),
])
def test_load_settings_clamps_ttl(tmp_path, monkeypatch, stored_ttl, expected):
    _use_data_dir(monkeypatch, tmp_path)
    (tmp_path / 'config.json').write_text(
        json.dumps({'tap_ttl_sec': stored_ttl}), encoding='utf-8'
    )

    settings = load_settings()

    assert settings['tap_ttl_sec'] == expected
    assert settings['registered_cards'] == {}
    assert settings['libusb_path'] is None


def test_add_card_writes_utf8_config_atomically(tmp_path, monkeypatch):
    _use_data_dir(monkeypatch, tmp_path)
    calls = []
    replace = nfc_store.os.replace

    def record_replace(source, destination):
        calls.append((Path(source), Path(destination)))
        replace(source, destination)

    monkeypatch.setattr(nfc_store.os, 'replace', record_replace)
    card = add_card('a' * 64, '通勤カード', r'DESKTOP\suger')

    config_path = tmp_path / 'config.json'
    raw = config_path.read_bytes()
    assert raw.decode('utf-8')
    assert card['name'] == '通勤カード'
    assert card['windows_user'] == r'DESKTOP\suger'
    assert len(calls) == 1
    assert calls[0][0].parent == tmp_path
    assert calls[0][1] == config_path
    assert not calls[0][0].exists()
    assert load_cards()['a' * 64]['name'] == '通勤カード'


def test_find_card_does_not_accept_legacy_plain_sha256_identifier(tmp_path, monkeypatch):
    _use_data_dir(monkeypatch, tmp_path)
    idm = bytes.fromhex('0102030405060708')
    key = b'k' * 32
    old_identifier = hashlib.sha256(idm).hexdigest()
    new_identifier = idm_mac(idm, key)
    assert old_identifier != new_identifier

    (tmp_path / 'config.json').write_text(json.dumps({
        'registered_cards': {
            old_identifier: {'name': 'legacy', 'windows_user': None},
        },
    }), encoding='utf-8')

    assert find_card(new_identifier) is None


def test_remove_card_removes_only_the_named_registration(tmp_path, monkeypatch):
    _use_data_dir(monkeypatch, tmp_path)
    add_card('a' * 64, 'Work', 'DESKTOP\\work')
    add_card('b' * 64, 'Home', 'DESKTOP\\home')

    assert remove_card('Work') is True
    assert remove_card('Missing') is False
    assert find_card('a' * 64) is None
    assert find_card('b' * 64)['name'] == 'Home'


def _decrypt_credential(path):
    """Decrypt a stored credential blob the way the Credential Provider does."""
    import win32crypt

    _description, record = win32crypt.CryptUnprotectData(
        path.read_bytes(), nfc_store._CREDENTIAL_ENTROPY, None, None, 0
    )
    return record


def test_save_credential_round_trips_through_dpapi(tmp_path, monkeypatch):
    _use_data_dir(monkeypatch, tmp_path / 'state')
    nfc_store.save_credential(r'MicrosoftAccount\someone@example.com', 'pa ss:word')

    # The provider splits on the first newline, so the record must be exactly
    # "<qualified user>\n<password>" encoded as UTF-8.
    assert _decrypt_credential(nfc_store.credential_path()) == (
        (r'MicrosoftAccount\someone@example.com' + '\npa ss:word').encode('utf-8')
    )
    assert nfc_store.load_credential_user() == r'MicrosoftAccount\someone@example.com'


def test_save_credential_keeps_a_password_containing_a_newline(tmp_path, monkeypatch):
    _use_data_dir(monkeypatch, tmp_path / 'state')
    nfc_store.save_credential(r'.\local', 'first\nsecond')

    # Only the first newline separates the fields, so the password survives.
    assert nfc_store.load_credential_user() == r'.\local'
    assert _decrypt_credential(nfc_store.credential_path()).decode('utf-8') == (
        r'.\local' + '\nfirst\nsecond'
    )


def test_save_credential_overwrites_without_leaving_temporary_files(tmp_path, monkeypatch):
    _use_data_dir(monkeypatch, tmp_path / 'state')
    nfc_store.save_credential(r'.\local', 'first')
    nfc_store.save_credential(r'.\other', 'second')

    assert nfc_store.load_credential_user() == r'.\other'
    leftovers = [item.name for item in get_data_dir().iterdir() if item.suffix == '.tmp']
    assert leftovers == []


@pytest.mark.parametrize(
    'user, password',
    [
        ('', 'secret'),
        ('   ', 'secret'),
        ('bad\nuser', 'secret'),
        ('bad\x00user', 'secret'),
        (r'.\local', ''),
    ],
)
def test_save_credential_rejects_unusable_input(tmp_path, monkeypatch, user, password):
    _use_data_dir(monkeypatch, tmp_path / 'state')
    with pytest.raises(ValueError):
        nfc_store.save_credential(user, password)
    assert not nfc_store.credential_path().exists()


def test_credential_helpers_handle_a_missing_blob(tmp_path, monkeypatch):
    _use_data_dir(monkeypatch, tmp_path / 'state')
    assert nfc_store.load_credential_user() is None
    assert nfc_store.clear_credential() is False

    nfc_store.save_credential(r'.\local', 'secret')
    assert nfc_store.clear_credential() is True
    assert nfc_store.load_credential_user() is None


def test_load_credential_user_ignores_a_corrupt_blob(tmp_path, monkeypatch):
    _use_data_dir(monkeypatch, tmp_path / 'state')
    ensure_data_dir(apply_acl=False)
    nfc_store.credential_path().write_bytes(b'not a dpapi blob')
    assert nfc_store.load_credential_user() is None


def test_reject_untrusted_state_accepts_a_directory_owned_by_administrators(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(nfc_store, '_owner_sid', lambda _path: 'S-1-5-32-544')
    nfc_store._reject_untrusted_state(tmp_path)


def test_reject_untrusted_state_refuses_a_directory_a_user_pre_created(
    tmp_path, monkeypatch
):
    # Any user may create a folder under C:\ProgramData and owns what they
    # create, which keeps them able to rewrite its DACL afterwards.
    monkeypatch.setattr(
        nfc_store, '_owner_sid', lambda _path: 'S-1-5-21-1-2-3-1001'
    )
    with pytest.raises(PermissionError, match='owned by'):
        nfc_store._reject_untrusted_state(tmp_path)


def test_reject_untrusted_state_refuses_a_planted_file_in_a_sound_directory(
    tmp_path, monkeypatch
):
    planted = tmp_path / 'config.json'
    planted.write_text('{"libusb_path": "C:/Users/evil/evil.dll"}', encoding='utf-8')

    def owner(path):
        return 'S-1-5-21-1-2-3-1001' if Path(path) == planted else 'S-1-5-18'

    monkeypatch.setattr(nfc_store, '_owner_sid', owner)
    with pytest.raises(PermissionError, match='config.json'):
        nfc_store._reject_untrusted_state(tmp_path)


def test_ensure_data_dir_checks_ownership_only_for_a_directory_it_adopts(
    tmp_path, monkeypatch
):
    seen = []
    monkeypatch.setenv('NFCAUTH_DATA_DIR', str(tmp_path / 'state'))
    monkeypatch.setattr(
        nfc_store,
        '_apply_protected_acl',
        lambda path, directory=False, verify_existing=False: seen.append(verify_existing),
    )

    ensure_data_dir()
    assert seen == [False]  # freshly created, nothing to inherit

    ensure_data_dir()
    assert seen == [False, True]  # already there, so its owner matters
