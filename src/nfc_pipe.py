"""Named-pipe protocol and one-slot tap state for the NFC service."""

import hmac
import json
import logging
import math
import secrets
import threading
import time
from typing import Callable, Optional


DEFAULT_PIPE_NAME = r'\\.\pipe\NfcAuthTap'
DEFAULT_PIPE_SDDL = 'D:P(A;;GA;;;SY)'
MAX_MESSAGE_BYTES = 4096
CARD_ABSENCE_SEC = 0.6


def _response_bytes(response: dict) -> bytes:
    return json.dumps(
        response, ensure_ascii=False, separators=(',', ':')
    ).encode('utf-8')


class TapState:
    """Hold one expiring, one-time tap token in memory."""

    def __init__(self, clock: Optional[Callable[[], float]] = None):
        self._clock = clock or time.monotonic
        self._slot = None
        self._last_consumed_at = None
        self._lock = threading.Lock()

    def _now(self, now: Optional[float]) -> float:
        return self._clock() if now is None else now

    def set_tap(self, user: Optional[str], ttl_sec: int, now: Optional[float] = None) -> str:
        """Replace the pending token and return its new, random nonce."""
        try:
            ttl = int(ttl_sec)
        except (TypeError, ValueError, OverflowError):
            ttl = 30
        ttl = max(5, min(120, ttl))
        current = self._now(now)
        nonce = secrets.token_hex(16)
        with self._lock:
            self._slot = {
                'user': user if isinstance(user, str) else None,
                'expires_at': current + ttl,
                'nonce': nonce,
            }
        return nonce

    def status(self, now: Optional[float] = None) -> dict:
        """Report the current token without consuming or erasing it."""
        current = self._now(now)
        with self._lock:
            slot = self._slot
            if slot is None or current >= slot['expires_at']:
                return {'v': 1, 'ok': True, 'tap': False}
            ttl_ms = max(1, math.ceil((slot['expires_at'] - current) * 1000))
            return {
                'v': 1,
                'ok': True,
                'tap': True,
                'user': slot['user'],
                'ttl_ms': int(ttl_ms),
                'nonce': slot['nonce'],
            }

    def consume(self, nonce, now: Optional[float] = None) -> dict:
        """Consume the live token only when its nonce matches in constant time."""
        current = self._now(now)
        with self._lock:
            slot = self._slot
            if slot is None:
                return {'v': 1, 'ok': False, 'error': 'no_tap'}
            if current >= slot['expires_at']:
                self._slot = None
                return {'v': 1, 'ok': False, 'error': 'expired'}
            if not isinstance(nonce, str):
                return {'v': 1, 'ok': False, 'error': 'bad_nonce'}
            try:
                matches = hmac.compare_digest(nonce, slot['nonce'])
            except (TypeError, UnicodeEncodeError):
                matches = False
            if not matches:
                return {'v': 1, 'ok': False, 'error': 'bad_nonce'}
            self._slot = None
            self._last_consumed_at = current
            return {'v': 1, 'ok': True}

    def cooldown_active(self, cooldown_sec: float = 3, now: Optional[float] = None) -> bool:
        """Return whether a successful consume is still within its re-arm cooldown."""
        current = self._now(now)
        with self._lock:
            return (
                self._last_consumed_at is not None
                and current - self._last_consumed_at < cooldown_sec
            )


class PresenceGate:
    """Allow one arm when a card appears after a confirmed absence window."""

    def __init__(
        self,
        absence_sec: float = CARD_ABSENCE_SEC,
        clock: Optional[Callable[[], float]] = None,
    ):
        self.absence_sec = max(0.0, float(absence_sec))
        self._clock = clock or time.monotonic
        self._present = False
        self._absent_since = None

    def observe(self, card_present: bool, now: Optional[float] = None) -> bool:
        """Return true once when presence follows a long enough observed absence."""
        current = self._clock() if now is None else now
        if not card_present:
            self._present = False
            if self._absent_since is None:
                self._absent_since = current
            return False

        if self._present:
            return False

        absent_since = self._absent_since
        self._present = True
        self._absent_since = None
        return (
            absent_since is not None
            and current - absent_since >= self.absence_sec
        )


def handle_request(raw: bytes, tap_state: TapState, now: Optional[float] = None) -> bytes:
    """Parse one request and return a protocol response; never raise to the caller."""
    try:
        if not isinstance(raw, bytes) or len(raw) > MAX_MESSAGE_BYTES:
            return _response_bytes({'v': 1, 'ok': False, 'error': 'bad_request'})
        request = json.loads(raw.decode('utf-8'))
        if not isinstance(request, dict) or type(request.get('v')) is not int or request['v'] != 1:
            return _response_bytes({'v': 1, 'ok': False, 'error': 'bad_request'})

        operation = request.get('op')
        if operation == 'status':
            response = tap_state.status(now)
        elif operation == 'consume':
            response = tap_state.consume(request.get('nonce'), now)
        else:
            response = {'v': 1, 'ok': False, 'error': 'bad_request'}
        return _response_bytes(response)
    except Exception:
        return _response_bytes({'v': 1, 'ok': False, 'error': 'bad_request'})


class PipeServer(threading.Thread):
    """Serve one JSON request per local named-pipe connection."""

    def __init__(
        self,
        tap_state: TapState,
        name: str = DEFAULT_PIPE_NAME,
        sddl: str = DEFAULT_PIPE_SDDL,
        read_timeout_sec: float = 2,
        clock: Optional[Callable[[], float]] = None,
        logger=None,
    ):
        super().__init__(name='NfcAuthPipeServer', daemon=True)
        self.tap_state = tap_state
        self.name = name
        self.sddl = sddl
        self.read_timeout_sec = read_timeout_sec
        self.clock = clock or time.monotonic
        self.logger = logger or logging.getLogger(__name__)
        self._stop_event = threading.Event()

    def stop(self):
        """Stop the listener; nonblocking pipe operations keep this bounded."""
        self._stop_event.set()

    @staticmethod
    def _error_code(error):
        return getattr(error, 'winerror', None) or (error.args[0] if error.args else None)

    def _create_pipe(self):
        import pywintypes
        import win32pipe
        import win32security

        descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            self.sddl, win32security.SDDL_REVISION_1
        )
        security_attributes = pywintypes.SECURITY_ATTRIBUTES()
        security_attributes.SECURITY_DESCRIPTOR = descriptor
        security_attributes.bInheritHandle = False

        pipe_mode = (
            win32pipe.PIPE_TYPE_MESSAGE
            | win32pipe.PIPE_READMODE_MESSAGE
            | win32pipe.PIPE_NOWAIT
            | getattr(win32pipe, 'PIPE_REJECT_REMOTE_CLIENTS', 0x00000008)
        )
        first_instance = getattr(win32pipe, 'FILE_FLAG_FIRST_PIPE_INSTANCE', 0x00080000)
        return win32pipe.CreateNamedPipe(
            self.name,
            win32pipe.PIPE_ACCESS_DUPLEX | first_instance,
            pipe_mode,
            win32pipe.PIPE_UNLIMITED_INSTANCES,
            MAX_MESSAGE_BYTES,
            MAX_MESSAGE_BYTES,
            0,
            security_attributes,
        )

    def _wait_for_client(self, pipe, win32pipe, pywintypes) -> bool:
        error_pipe_connected = getattr(win32pipe, 'ERROR_PIPE_CONNECTED', 535)
        error_pipe_listening = getattr(win32pipe, 'ERROR_PIPE_LISTENING', 536)
        while not self._stop_event.is_set():
            try:
                result = win32pipe.ConnectNamedPipe(pipe, None)
                if result is not False:
                    return True
            except pywintypes.error as error:
                code = self._error_code(error)
                if code == error_pipe_connected:
                    return True
                if code != error_pipe_listening:
                    raise
            self._stop_event.wait(0.02)
        return False

    def _read_request(self, pipe, win32file, pywintypes) -> Optional[bytes]:
        no_data = getattr(win32file, 'ERROR_NO_DATA', 232)
        more_data = getattr(win32file, 'ERROR_MORE_DATA', 234)
        broken_pipe = getattr(win32file, 'ERROR_BROKEN_PIPE', 109)
        deadline = self.clock() + self.read_timeout_sec
        request = bytearray()

        while not self._stop_event.is_set():
            if self.clock() >= deadline:
                return bytes(request)
            # Keep only one byte beyond the protocol limit, but drain the message so
            # a client blocked in a large WriteFile can still receive bad_request.
            size = min(MAX_MESSAGE_BYTES, max(1, MAX_MESSAGE_BYTES + 1 - len(request)))
            try:
                result = win32file.ReadFile(pipe, size)
                code, data = result[0], result[1]
            except pywintypes.error as error:
                code = self._error_code(error)
                data = b''
                if code == broken_pipe:
                    return None
                if code not in (no_data, more_data):
                    raise

            if data and len(request) <= MAX_MESSAGE_BYTES:
                remaining = MAX_MESSAGE_BYTES + 1 - len(request)
                request.extend(data[:remaining])
            if code == more_data:
                continue
            if code == no_data:
                self._stop_event.wait(0.01)
                continue
            return bytes(request)
        return None

    def _serve_connection(self, pipe, win32file, win32pipe, pywintypes):
        raw = self._read_request(pipe, win32file, pywintypes)
        if raw is None:
            return
        response = handle_request(raw, self.tap_state, now=self.clock())
        win32file.WriteFile(pipe, response)

    def run(self):
        import pywintypes
        import win32file
        import win32pipe

        while not self._stop_event.is_set():
            pipe = None
            try:
                pipe = self._create_pipe()
                if self._wait_for_client(pipe, win32pipe, pywintypes):
                    self._serve_connection(pipe, win32file, win32pipe, pywintypes)
            except Exception:
                self.logger.exception('Named pipe connection failed')
                self._stop_event.wait(0.05)
            finally:
                if pipe is not None:
                    try:
                        win32pipe.DisconnectNamedPipe(pipe)
                    except Exception:
                        pass
                    try:
                        win32file.CloseHandle(pipe)
                    except Exception:
                        pass
