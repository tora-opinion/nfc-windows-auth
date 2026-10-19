import importlib.util
import sys
import threading
from pathlib import Path
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / 'src'))


def _load_service_module(monkeypatch):
    class ServiceFramework:
        def __init__(self, _args):
            self.status_updates = []

        def ReportServiceStatus(self, *args, **kwargs):
            self.status_updates.append((args, kwargs))

    fake_service = SimpleNamespace(
        SERVICE_AUTO_START=2,
        SERVICE_RUNNING=4,
        SERVICE_STOP_PENDING=3,
    )
    fake_service_util = SimpleNamespace(
        ServiceFramework=ServiceFramework,
        HandleCommandLine=lambda _service: None,
    )
    monkeypatch.setitem(sys.modules, 'win32service', fake_service)
    monkeypatch.setitem(sys.modules, 'win32serviceutil', fake_service_util)

    module_path = REPO_ROOT / 'src' / 'nfc_auth_service.py'
    spec = importlib.util.spec_from_file_location(
        '_nfc_auth_service_test', module_path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_stop_reports_increasing_checkpoints_while_joining_reader(monkeypatch):
    module = _load_service_module(monkeypatch)
    monkeypatch.setattr(module, 'STOP_JOIN_INTERVAL_SEC', 0.01)
    monkeypatch.setattr(module, 'STOP_JOIN_TIMEOUT_SEC', 1)
    service = module.NfcAuthService([])

    class ReaderThread:
        def __init__(self):
            self.joins_remaining = 2
            self.timeouts = []

        def is_alive(self):
            return self.joins_remaining > 0

        def join(self, timeout=None):
            self.timeouts.append(timeout)
            self.joins_remaining -= 1

    reader_thread = ReaderThread()
    service.reader_thread = reader_thread

    service.SvcStop()

    assert service.stop_event.is_set()
    assert reader_thread.timeouts == [0.01, 0.01]
    reports = service.status_updates
    assert [args[0] for args, _kwargs in reports] == [
        module.win32service.SERVICE_STOP_PENDING,
        module.win32service.SERVICE_STOP_PENDING,
    ]
    assert [kwargs['checkPoint'] for _args, kwargs in reports] == [1, 2]
    assert all(kwargs['waitHint'] == module.STOP_WAIT_HINT_MS for _args, kwargs in reports)


def test_reader_loop_checks_stop_after_each_reader_call(monkeypatch, tmp_path):
    module = _load_service_module(monkeypatch)
    calls = []

    class Logger:
        def info(self, *_args):
            pass

        def warning(self, *_args):
            pass

        def error(self, *_args):
            pass

        def exception(self, *_args):
            pass

    class PipeServer:
        def __init__(self, *_args, **_kwargs):
            pass

        def start(self):
            pass

        def stop(self):
            pass

        def join(self, timeout=None):
            pass

        def is_alive(self):
            return False

    service = module.NfcAuthService([])

    class Reader:
        def __init__(self, _path):
            self.dev = None

        def open(self):
            calls.append('open')
            service.stop_event.set()

        def start_session(self):
            calls.append('start_session')

        def poll_express_card(self, timeout_ms):
            calls.append(('poll', timeout_ms))

        def close(self):
            calls.append('close')

    monkeypatch.setattr(module, 'ensure_data_dir', lambda: tmp_path)
    monkeypatch.setattr(module, 'setup_logging', lambda *_args: Logger())
    monkeypatch.setattr(module, 'load_key', lambda: b'k' * 32)
    monkeypatch.setattr(
        module,
        'load_settings',
        lambda: {'tap_ttl_sec': 30, 'poll_interval_ms': 0},
    )
    monkeypatch.setattr(module, 'load_cards', lambda: {'registered': {}})
    monkeypatch.setattr(module, 'find_libusb', lambda *_args: 'fake-libusb')
    monkeypatch.setattr(module, 'PipeServer', PipeServer)
    monkeypatch.setattr(module, 'RCS300', Reader)

    service.run_service()

    assert calls == ['open', 'close']
