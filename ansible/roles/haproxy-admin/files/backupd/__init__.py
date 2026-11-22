"""Package implementation for easy-ha-proxy-backupd.py."""

from __future__ import annotations

import importlib
import types
from typing import Tuple

SUBMODULES: Tuple[str, ...] = (
    "constants",
    "jobs",
    "operations",
    "destinations",
    "api",
)


def bind_submodules(loaded: Tuple[types.ModuleType, ...]) -> None:
    """Wire late-bound cross-submodule symbols once all modules are loaded."""
    by_name = {mod.__name__.rsplit('.', 1)[-1]: mod for mod in loaded}
    by_name["constants"].__dict__["SYSTEMCTL_PATH"] = by_name["jobs"].__dict__["SYSTEMCTL_PATH"]
    by_name["constants"].__dict__["stop_transient_unit"] = by_name["jobs"].__dict__["stop_transient_unit"]
    by_name["constants"].__dict__["transient_jobs_supported"] = by_name["jobs"].__dict__["transient_jobs_supported"]
    by_name["jobs"].__dict__["resolve_upload_source"] = by_name["operations"].__dict__["resolve_upload_source"]


def load_all(pkg_name: str = __name__) -> Tuple[types.ModuleType, ...]:
    loaded = tuple(importlib.import_module(f'{pkg_name}.{m}') for m in SUBMODULES)
    bind_submodules(loaded)
    return loaded
