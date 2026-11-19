import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / 'src'))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

pytest.importorskip('win32service')

import nfc_cards


RUNNING = 4
STOPPED = 1


class _FakeServiceControl:
    """Records stop/start calls the way win32serviceutil would receive them."""

    def __init__(self, state):
        self.state = state
        self.calls = []

    def StopService(self, name):
        self.calls.append(('stop', name))
        self.state = STOPPED

    def StartService(self, name):
        self.calls.append(('start', name))
        self.state = RUNNING


def _install(monkeypatch, control):
    monkeypatch.setitem(sys.modules, 'win32serviceutil', control)
    monkeypatch.setattr(nfc_cards, '_service_state', lambda: control.state)


def test_reader_released_stops_and_restarts_a_running_service(monkeypatch):
    control = _FakeServiceControl(RUNNING)
    _install(monkeypatch, control)

    with nfc_cards._reader_released():
        # The service must already be gone while the reader is in use.
        assert control.calls == [('stop', nfc_cards.SERVICE_NAME)]

    assert control.calls == [
        ('stop', nfc_cards.SERVICE_NAME),
        ('start', nfc_cards.SERVICE_NAME),
    ]


def test_reader_released_leaves_a_stopped_service_alone(monkeypatch):
    control = _FakeServiceControl(STOPPED)
    _install(monkeypatch, control)

    with nfc_cards._reader_released():
        pass

    assert control.calls == []


def test_reader_released_restarts_the_service_after_a_failure(monkeypatch):
    control = _FakeServiceControl(RUNNING)
    _install(monkeypatch, control)

    with pytest.raises(RuntimeError):
        with nfc_cards._reader_released():
            raise RuntimeError('no card was presented')

    assert ('start', nfc_cards.SERVICE_NAME) in control.calls


def test_reader_released_refuses_to_continue_if_the_service_will_not_stop(monkeypatch):
    control = _FakeServiceControl(RUNNING)
    monkeypatch.setitem(sys.modules, 'win32serviceutil', control)
    # Report the service as still running however long we wait for it.
    monkeypatch.setattr(nfc_cards, '_service_state', lambda: RUNNING)
    monkeypatch.setattr(nfc_cards, 'SERVICE_STOP_TIMEOUT_SEC', 0.05)
    monkeypatch.setattr(nfc_cards, 'SERVICE_POLL_SEC', 0.01)

    entered = False
    with pytest.raises(RuntimeError, match='did not stop'):
        with nfc_cards._reader_released():
            entered = True

    # Enrolment must not run against a reader the service still owns.
    assert not entered
    assert ('start', nfc_cards.SERVICE_NAME) not in control.calls


def test_reader_released_reports_a_failed_restart_without_masking_success(
    monkeypatch, capsys
):
    control = _FakeServiceControl(RUNNING)

    def failing_start(_name):
        raise OSError('access denied')

    control.StartService = failing_start
    _install(monkeypatch, control)

    with nfc_cards._reader_released():
        pass

    message = capsys.readouterr().err
    assert 'could not be restarted' in message
    assert nfc_cards.SERVICE_NAME in message
