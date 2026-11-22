#!/usr/bin/env python3
"""easy-ha-proxy-guardd: adaptive protection daemon (CLI entrypoint & facade).

The implementation lives in the sibling `guardd/` package:
  - guardd.constants   : scoring defaults, event types, signature loading
  - guardd.parser      : HAProxy access-log parsing and protocol anomaly checks
  - guardd.runtime     : configuration loading and HAProxy admin-socket client
  - guardd.scoring     : scoring policy, decay calculation, and exclusions
  - guardd.watchers    : trusted rate warnings, hard floor, and ban policy watch
  - guardd.tracking    : SLRU IpMemory, /24 SubnetCorrelator, detection context
  - guardd.storage     : SQLite security database, migrations, quality metrics
  - guardd.request_log : optional SQLite access-request log
  - guardd.enforcer    : PathShield and tbl_ban enforcement primitives
  - guardd.live        : in-memory live buffer, minute digests, enforcement queue
  - guardd.engine      : GuardEngine orchestrator
  - guardd.api         : Unix-socket HTTP API handler, server, and CLI main()
"""

from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path
import sys
import types
from typing import Any, List, Optional, Tuple

_HERE = Path(__file__).resolve().parent
_PKG_DIR = _HERE / "guardd"
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

_SUBMODULE_NAMES: Tuple[str, ...] = (
    "constants",
    "parser",
    "native",
    "runtime",
    "scoring",
    "watchers",
    "tracking",
    "storage",
    "request_log",
    "enforcer",
    "live",
    "engine",
    "api",
)

# Module-level signature tables/metadata that `load_signatures()` and
# `publish_signatures()` can rebind inside `guardd.constants`. Keeping them
# delegated through `__getattr__` guarantees callers always read live values.
_LIVE_GLOBALS = frozenset({
    "DECISIVE_CATEGORIES",
    "SCANNER_PATHS",
    "SCANNER_PREFIXES",
    "SCANNER_SEGMENTS",
    "SIGNATURE_SOURCE",
    "SIGNATURE_VERSION",
    "_SHIPPED_PATHS",
    "_SHIPPED_SEGMENTS",
    "_overrides",
})

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
        return tuple(
            importlib.import_module(f"guardd.{name}") for name in _SUBMODULE_NAMES
        )

    pkg = types.ModuleType(isolated_pkg)
    pkg.__file__ = str(_PKG_DIR / "__init__.py")
    pkg.__package__ = isolated_pkg
    pkg.__path__ = [str(_PKG_DIR)]
    sys.modules[isolated_pkg] = pkg

    loaded: List[types.ModuleType] = []
    for name in _SUBMODULE_NAMES:
        full_name = f"{isolated_pkg}.{name}"
        spec = importlib.util.spec_from_file_location(
            full_name, _PKG_DIR / f"{name}.py"
        )
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load guardd submodule {name!r}")
        mod = importlib.util.module_from_spec(spec)
        mod.__package__ = isolated_pkg
        sys.modules[full_name] = mod
        spec.loader.exec_module(mod)
        setattr(pkg, name, mod)
        loaded.append(mod)
    return tuple(loaded)


class _GuarddFacade(types.ModuleType):
    """Module facade that forwards live global reads and monkeypatches."""

    def __getattr__(self, name: str) -> Any:
        if name in _LIVE_GLOBALS:
            return getattr(object.__getattribute__(self, "_guardd_constants"), name)
        raise AttributeError(f"module {self.__name__!r} has no attribute {name!r}")

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_guardd_"):
            super().__setattr__(name, value)
            return
        submodules: Tuple[types.ModuleType, ...] = object.__getattribute__(
            self, "_guardd_submodules"
        )
        if name in _LIVE_GLOBALS:
            setattr(object.__getattribute__(self, "_guardd_constants"), name, value)
        else:
            super().__setattr__(name, value)
        for sub in submodules:
            if name in sub.__dict__:
                setattr(sub, name, value)

    def __delattr__(self, name: str) -> None:
        if name in _LIVE_GLOBALS:
            delattr(object.__getattribute__(self, "_guardd_constants"), name)
            return
        super().__delattr__(name)
        for sub in object.__getattribute__(self, "_guardd_submodules"):
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
    isolated = None if __name__ == "__main__" else f"_guardd_pkg_{id(ns)}"
    submodules = _load_submodules(isolated)
    for sub in submodules:
        for key, val in sub.__dict__.items():
            if key in _SKIP_EXPORT or key in _LIVE_GLOBALS:
                continue
            ns[key] = val
    ns["_guardd_submodules"] = submodules
    ns["_guardd_constants"] = submodules[0]
    if this_mod is not None:
        this_mod.__class__ = _GuarddFacade
    return submodules


_SUBMODULES = _bootstrap()

if __name__ == "__main__":
    raise SystemExit(_SUBMODULES[-1].main())
