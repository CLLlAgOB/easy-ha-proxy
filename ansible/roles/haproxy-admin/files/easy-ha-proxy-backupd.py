#!/usr/bin/env python3
"""easy-ha-proxy-backupd.py: host daemon CLI entrypoint and compatibility facade.

The implementation lives in the sibling `backupd/` package:
  - backupd.constants        : Constants, paths, locks, and job state records for backupd.
  - backupd.jobs             : Upload staging, transient systemd job runner, and local artifact storage.
  - backupd.operations       : Backup and restore stage records and execution workflows.
  - backupd.destinations     : Off-host SFTP/SSH and S3-compatible backup destinations.
  - backupd.api              : Scheduled backup timer management, Unix-socket server, and CLI entrypoint.
"""

from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path
import sys
import types
from typing import Any, List, Optional, Tuple

_HERE = Path(__file__).resolve().parent
_PKG_NAME = "backupd"
_PKG_DIR = _HERE / _PKG_NAME
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

_SUBMODULE_NAMES: Tuple[str, ...] = (
    "constants",
    "jobs",
    "operations",
    "destinations",
    "api",
)

_LIVE_GLOBALS = frozenset({"APP_GROUP_GID", "APP_PRIMARY_GID", "APP_UID"})

_SKIP_EXPORT = frozenset({
    "__builtins__",
    "__cached__",
    "__doc__",
    "__file__",
    "__loader__",
    "__name__",
    "__package__",
    "__path__",
    "__spec__",
    "_constants",
    "annotations",
})


def _load_submodules(isolated_pkg: Optional[str]) -> Tuple[types.ModuleType, ...]:
    if isolated_pkg is None:
        pkg_mod = importlib.import_module(_PKG_NAME)
        return pkg_mod.load_all(_PKG_NAME)

    pkg = types.ModuleType(isolated_pkg)
    pkg.__file__ = str(_PKG_DIR / "__init__.py")
    pkg.__package__ = isolated_pkg
    pkg.__path__ = [str(_PKG_DIR)]
    sys.modules[isolated_pkg] = pkg

    init_spec = importlib.util.spec_from_file_location(
        isolated_pkg, _PKG_DIR / "__init__.py"
    )
    if init_spec is None or init_spec.loader is None:
        raise ImportError(f'Cannot load {_PKG_NAME} package __init__')
    init_spec.loader.exec_module(pkg)

    loaded: List[types.ModuleType] = []
    for name in _SUBMODULE_NAMES:
        full_name = f"{isolated_pkg}.{name}"
        spec = importlib.util.spec_from_file_location(
            full_name, _PKG_DIR / f"{name}.py"
        )
        if spec is None or spec.loader is None:
            raise ImportError(f'Cannot load {_PKG_NAME} submodule {name!r}')
        mod = importlib.util.module_from_spec(spec)
        mod.__package__ = isolated_pkg
        sys.modules[full_name] = mod
        spec.loader.exec_module(mod)
        setattr(pkg, name, mod)
        loaded.append(mod)
    sub_tuple = tuple(loaded)
    pkg.bind_submodules(sub_tuple)
    return sub_tuple


class _DaemonFacade(types.ModuleType):
    """Module facade that forwards live global reads and monkeypatches."""

    def __getattr__(self, name: str) -> Any:
        if name in _LIVE_GLOBALS:
            return getattr(object.__getattribute__(self, "_daemon_constants"), name)
        raise AttributeError(f"module {self.__name__!r} has no attribute {name!r}")

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_daemon_"):
            super().__setattr__(name, value)
            return
        submodules: Tuple[types.ModuleType, ...] = object.__getattribute__(
            self, "_daemon_submodules"
        )
        if name in _LIVE_GLOBALS:
            setattr(object.__getattribute__(self, "_daemon_constants"), name, value)
        else:
            super().__setattr__(name, value)
        for sub in submodules:
            if name in sub.__dict__:
                setattr(sub, name, value)

    def __delattr__(self, name: str) -> None:
        if name in _LIVE_GLOBALS:
            delattr(object.__getattribute__(self, "_daemon_constants"), name)
            return
        super().__delattr__(name)
        for sub in object.__getattribute__(self, "_daemon_submodules"):
            if name in sub.__dict__:
                delattr(sub, name)


def _bootstrap() -> Tuple[types.ModuleType, ...]:
    ns = globals()
    this_mod = sys.modules.get(__name__)
    if this_mod is None:
        import gc

        for obj in gc.get_referrers(ns):
            if isinstance(obj, types.ModuleType) and obj.__dict__ is ns:
                this_mod = obj
                break
    isolated = None if __name__ == "__main__" else f"_{_PKG_NAME}_pkg_{id(ns)}"
    submodules = _load_submodules(isolated)
    for sub in submodules:
        for key, val in sub.__dict__.items():
            if key in _SKIP_EXPORT or key in _LIVE_GLOBALS:
                continue
            ns[key] = val
    ns["_daemon_submodules"] = submodules
    ns["_daemon_constants"] = submodules[0]
    if this_mod is not None:
        this_mod.__class__ = _DaemonFacade
    return submodules


_SUBMODULES = _bootstrap()

if __name__ == "__main__":
    raise SystemExit(_SUBMODULES[-1].main())
