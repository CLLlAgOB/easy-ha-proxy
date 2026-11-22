"""Optional native Rust accelerator bridge (`libguardd_core.so`) for batch log parsing."""

from __future__ import annotations

import ctypes
import json
import os
import threading
from pathlib import Path
from typing import Any, List, Optional

from . import constants as _constants
from .constants import LOG
from .parser import ParsedRequest

DEFAULT_NATIVE_LIB = "/usr/local/sbin/libguardd_core.so"
NATIVE_BATCH_MIN_LINES = 32


class _NativeBridge:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._loaded = False
        self._lib: Optional[Any] = None
        self._handle: Optional[int] = None
        self._sig_key: tuple[str, str] = ("", "")

    def _resolve_path(self) -> Optional[str]:
        configured = os.environ.get("GUARDD_NATIVE_LIB", "").strip()
        if configured:
            return configured if Path(configured).is_file() else None
        if Path(DEFAULT_NATIVE_LIB).is_file():
            return DEFAULT_NATIVE_LIB
        return None

    def _ensure_loaded_locked(self) -> Optional[Any]:
        if self._loaded:
            return self._lib
        self._loaded = True
        path = self._resolve_path()
        if not path:
            return None
        try:
            lib = ctypes.CDLL(path)
            lib.guardd_engine_new.argtypes = [ctypes.c_char_p]
            lib.guardd_engine_new.restype = ctypes.c_void_p
            lib.guardd_engine_free.argtypes = [ctypes.c_void_p]
            lib.guardd_parse_batch_json.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            lib.guardd_parse_batch_json.restype = ctypes.c_void_p
            lib.guardd_string_free.argtypes = [ctypes.c_void_p]
            self._lib = lib
            LOG.info("Loaded native Rust guardd-core accelerator from %s", path)
        except OSError as exc:
            LOG.warning("Could not load native guardd-core library %s (%s); using Python parser", path, exc)
            self._lib = None
        return self._lib

    def _ensure_handle_locked(self, lib: Any) -> Optional[int]:
        key = (_constants.SIGNATURE_SOURCE, _constants.SIGNATURE_VERSION)
        if self._handle and self._sig_key == key:
            return self._handle
        if self._handle:
            lib.guardd_engine_free(self._handle)
            self._handle = None
        src = _constants.SIGNATURE_SOURCE or _constants.SIGNATURE_PATH
        arg = src.encode("utf-8") if src else None
        handle = lib.guardd_engine_new(arg)
        if not handle:
            return None
        self._handle = handle
        self._sig_key = key
        return handle

    def reset(self) -> None:
        with self._lock:
            if self._lib is not None and self._handle:
                self._lib.guardd_engine_free(self._handle)
            self._handle = None
            self._lib = None
            self._loaded = False
            self._sig_key = ("", "")

    def parse_batch(self, lines: List[str]) -> Optional[List[Optional[ParsedRequest]]]:
        if not lines:
            return []
        with self._lock:
            lib = self._ensure_loaded_locked()
            if lib is None:
                return None
            handle = self._ensure_handle_locked(lib)
            if not handle:
                return None
            payload = "\n".join(lines).encode("utf-8", "replace")
            raw_ptr = lib.guardd_parse_batch_json(handle, payload)
            if not raw_ptr:
                return None
            try:
                raw_json = ctypes.string_at(raw_ptr).decode("utf-8")
            finally:
                lib.guardd_string_free(raw_ptr)
        try:
            decoded = json.loads(raw_json)
        except ValueError:
            return None
        if not isinstance(decoded, list) or len(decoded) != len(lines):
            return None
        out: List[Optional[ParsedRequest]] = []
        for item in decoded:
            if item is None:
                out.append(None)
            else:
                out.append(
                    ParsedRequest(
                        client_ip=item["client_ip"],
                        status=item["status"],
                        frontend=item["frontend"],
                        backend=item["backend"],
                        method=item["method"],
                        path=item["path"],
                        host=item["host"],
                        bad_request=item["bad_request"],
                        query_flag=item["query_flag"],
                        path_flag=item["path_flag"],
                        observation_flags=tuple(item["observation_flags"]),
                        ts=item["ts"],
                        request_id=item["request_id"],
                        bytes_out=item["bytes_out"],
                        duration_ms=item["duration_ms"],
                        response_ms=item["response_ms"],
                        times=item["times"],
                        term=item["term"],
                        ban_reason=item["ban_reason"],
                        user_agent=item["user_agent"],
                        authenticated_user=item["authenticated_user"],
                        protocol=item["protocol"],
                    )
                )
        return out


_BRIDGE = _NativeBridge()


def parse_access_lines_native(lines: List[str]) -> Optional[List[Optional[ParsedRequest]]]:
    """Parse a batch of access-log lines with Rust `libguardd_core.so` when present."""
    return _BRIDGE.parse_batch(lines)


def reset_native_bridge() -> None:
    """Release any loaded native handle (primarily for tests)."""
    _BRIDGE.reset()
