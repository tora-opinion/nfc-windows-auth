import json
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / 'src'))

from nfc_pipe import (
    MAX_MESSAGE_BYTES,
    PipeServer,
    PresenceGate,
    TapState,
    handle_request,
)


def _request(payload, state, now=0):
    raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode('utf-8')
    return json.loads(handle_request(raw, state, now=now).decode('utf-8'))


def test_status_without_tap_and_with_tap():
    state = TapState()
    assert _request({'v': 1, 'op': 'status'}, state) == {
        'v': 1, 'ok': True, 'tap': False,
    }

    nonce = state.set_tap(r'DESKTOP\suger', 30, now=10)
    response = _request({'v': 1, 'op': 'status'}, state, now=10)
    assert response == {
        'v': 1,
        'ok': True,
        'tap': True,
        'user': r'DESKTOP\suger',
        'ttl_ms': 30000,
        'nonce': nonce,
    }
    assert _request({'v': 1, 'op': 'status'}, state, now=11)['nonce'] == nonce


def test_status_returns_null_user_when_registration_has_no_user():
    state = TapState()
    state.set_tap(None, 5, now=10)
    assert _request({'v': 1, 'op': 'status'}, state, now=10) == {
        'v': 1,
        'ok': True,
        'tap': True,
        'user': None,
        'ttl_ms': 5000,
        'nonce': state.status(now=10)['nonce'],
    }


def test_consume_success_is_one_time():
    state = TapState()
    nonce = state.set_tap('user', 30, now=0)

    assert _request({'v': 1, 'op': 'consume', 'nonce': nonce}, state, now=1) == {
        'v': 1, 'ok': True,
    }
    assert _request({'v': 1, 'op': 'consume', 'nonce': nonce}, state, now=1) == {
        'v': 1, 'ok': False, 'error': 'no_tap',
    }
    assert state.cooldown_active(now=3.99)
    assert not state.cooldown_active(now=4)


def test_presence_gate_requires_absence_window_and_only_arms_once_per_tap():
    clock = [0.0]
    gate = PresenceGate(absence_sec=0.6, clock=lambda: clock[0])

    # A card already present when monitoring starts has no observed prior absence.
    assert not gate.observe(True)
    clock[0] = 10
    assert not gate.observe(True)

    clock[0] = 11
    assert not gate.observe(False)
    clock[0] = 11.59
    assert not gate.observe(False)
    assert not gate.observe(True)

    clock[0] = 12
    assert not gate.observe(False)
    clock[0] = 12.61
    assert gate.observe(True)

    # Continuous presence cannot generate another tap, even after cooldown time.
    clock[0] = 30
    assert not gate.observe(True)


def test_presence_gate_allows_a_new_tap_only_after_card_is_removed():
    clock = [0.0]
    gate = PresenceGate(absence_sec=0.6, clock=lambda: clock[0])
    assert not gate.observe(False)
    clock[0] = 0.61
    assert gate.observe(True)
    assert not gate.observe(True)

    clock[0] = 1
    assert not gate.observe(False)
    clock[0] = 1.61
    assert gate.observe(True)


def test_wrong_nonce_does_not_erase_live_tap():
    state = TapState()
    nonce = state.set_tap('user', 30, now=0)

    assert state.consume('wrong nonce', now=1) == {
        'v': 1, 'ok': False, 'error': 'bad_nonce',
    }
    assert state.status(now=1)['nonce'] == nonce
    assert state.consume(nonce, now=1) == {'v': 1, 'ok': True}


def test_expired_tap_is_reported_then_cleared_by_consume():
    state = TapState()
    nonce = state.set_tap('user', 5, now=10)

    assert state.status(now=15) == {'v': 1, 'ok': True, 'tap': False}
    assert state.consume(nonce, now=15) == {
        'v': 1, 'ok': False, 'error': 'expired',
    }
    assert state.consume(nonce, now=15) == {
        'v': 1, 'ok': False, 'error': 'no_tap',
    }


def test_new_tap_replaces_old_token_with_a_new_nonce():
    state = TapState()
    old_nonce = state.set_tap('old', 30, now=0)
    new_nonce = state.set_tap('new', 30, now=1)

    assert old_nonce != new_nonce
    assert state.status(now=1)['user'] == 'new'
    assert state.consume(old_nonce, now=1)['error'] == 'bad_nonce'
    assert state.status(now=1)['nonce'] == new_nonce
    assert state.consume(new_nonce, now=1) == {'v': 1, 'ok': True}


@pytest.mark.parametrize(('ttl_sec', 'expected'), [(1, 5), (30, 30), (500, 120)])
def test_tap_state_clamps_ttl(ttl_sec, expected):
    state = TapState()
    state.set_tap('user', ttl_sec, now=3)
    assert state.status(now=3)['ttl_ms'] == expected * 1000


@pytest.mark.parametrize('raw', [
    b'{',
    b'\xff',
    b'[]',
    b'{"v":2,"op":"status"}',
    b'{"v":true,"op":"status"}',
    b'{"v":1,"op":"unknown"}',
])
def test_bad_request_variants(raw):
    assert json.loads(handle_request(raw, TapState(), now=0)) == {
        'v': 1, 'ok': False, 'error': 'bad_request',
    }


def test_oversize_request_is_rejected():
    raw = b' ' * (MAX_MESSAGE_BYTES + 1)
    assert json.loads(handle_request(raw, TapState(), now=0)) == {
        'v': 1, 'ok': False, 'error': 'bad_request',
    }


def test_consume_missing_or_invalid_nonce_is_bad_nonce():
    state = TapState()
    state.set_tap('user', 30, now=0)
    assert _request({'v': 1, 'op': 'consume'}, state, now=1) == {
        'v': 1, 'ok': False, 'error': 'bad_nonce',
    }
    assert _request({'v': 1, 'op': 'consume', 'nonce': 1}, state, now=1) == {
        'v': 1, 'ok': False, 'error': 'bad_nonce',
    }


def test_pipe_server_round_trip_or_skip_if_pipe_creation_is_unavailable():
    try:
        import pywintypes
        import win32file
        import win32pipe
    except ImportError:
        pytest.skip('pywin32 named-pipe APIs are unavailable')

    pipe_name = rf'\\.\pipe\NfcAuthTapTest-{uuid.uuid4().hex}'
    state = TapState()
    state.set_tap('round-trip-user', 30)
    server = PipeServer(
        state,
        name=pipe_name,
        sddl='D:P(A;;GA;;;WD)',
        read_timeout_sec=0.2,
    )
    server.start()
    client = None
    deadline = time.monotonic() + 3
    last_error = None
    while client is None and time.monotonic() < deadline:
        try:
            win32pipe.WaitNamedPipe(pipe_name, 200)
            client = win32file.CreateFile(
                pipe_name,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                None,
            )
        except pywintypes.error as error:
            last_error = error
            time.sleep(0.02)

    if client is None:
        server.stop()
        server.join(timeout=2)
        pytest.skip(f'Named pipe could not be created or opened: {last_error}')

    try:
        win32file.WriteFile(client, b'{"v":1,"op":"status"}')
        _status, response = win32file.ReadFile(client, MAX_MESSAGE_BYTES)
        decoded = json.loads(response.decode('utf-8'))
        assert decoded['v'] == 1
        assert decoded['tap'] is True
        assert decoded['user'] == 'round-trip-user'
        win32file.CloseHandle(client)
        client = None

        # A connected client that sends nothing must not leave the listener stuck.
        deadline = time.monotonic() + 3
        last_error = None
        while client is None and time.monotonic() < deadline:
            try:
                win32pipe.WaitNamedPipe(pipe_name, 200)
                client = win32file.CreateFile(
                    pipe_name,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0,
                    None,
                    win32file.OPEN_EXISTING,
                    0,
                    None,
                )
            except pywintypes.error as error:
                last_error = error
                time.sleep(0.02)

        if client is None:
            pytest.fail(f'Pipe server did not accept a second connection: {last_error}')

        _status, response = win32file.ReadFile(client, MAX_MESSAGE_BYTES)
        assert json.loads(response.decode('utf-8')) == {
            'v': 1, 'ok': False, 'error': 'bad_request',
        }
    finally:
        if client is not None:
            win32file.CloseHandle(client)
        server.stop()
        server.join(timeout=2)
    assert not server.is_alive()


def test_pipe_server_uses_production_security_configuration(monkeypatch):
    class SecurityAttributes:
        pass

    descriptor = object()
    created = []
    converted = []
    fake_pywin = SimpleNamespace(SECURITY_ATTRIBUTES=SecurityAttributes)
    fake_security = SimpleNamespace(
        SDDL_REVISION_1=1,
        ConvertStringSecurityDescriptorToSecurityDescriptor=(
            lambda sddl, revision:
            converted.append((sddl, revision)) or descriptor
        ),
    )
    fake_pipe = SimpleNamespace(
        PIPE_ACCESS_DUPLEX=0x00000003,
        PIPE_TYPE_MESSAGE=0x00000004,
        PIPE_READMODE_MESSAGE=0x00000002,
        PIPE_NOWAIT=0x00000001,
        PIPE_REJECT_REMOTE_CLIENTS=0x00000008,
        FILE_FLAG_FIRST_PIPE_INSTANCE=0x00080000,
        PIPE_UNLIMITED_INSTANCES=255,
        CreateNamedPipe=lambda *args: created.append(args) or object(),
    )
    monkeypatch.setitem(sys.modules, 'pywintypes', fake_pywin)
    monkeypatch.setitem(sys.modules, 'win32security', fake_security)
    monkeypatch.setitem(sys.modules, 'win32pipe', fake_pipe)

    PipeServer(TapState())._create_pipe()

    assert converted == [('D:P(A;;GA;;;SY)', fake_security.SDDL_REVISION_1)]
    assert len(created) == 1
    args = created[0]
    assert args[1] == (
        fake_pipe.PIPE_ACCESS_DUPLEX | fake_pipe.FILE_FLAG_FIRST_PIPE_INSTANCE
    )
    assert args[2] & fake_pipe.PIPE_TYPE_MESSAGE
    assert args[2] & fake_pipe.PIPE_READMODE_MESSAGE
    assert args[2] & fake_pipe.PIPE_REJECT_REMOTE_CLIENTS
    assert args[2] & fake_pipe.PIPE_NOWAIT
    assert args[3] == fake_pipe.PIPE_UNLIMITED_INSTANCES
    assert isinstance(args[7], SecurityAttributes)
    assert args[7].SECURITY_DESCRIPTOR is descriptor
    assert args[7].bInheritHandle is False
