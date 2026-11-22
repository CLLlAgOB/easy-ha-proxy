"""Package implementation for easy-ha-proxy-metricsd.py."""

from __future__ import annotations

import importlib
import types
from typing import Tuple

SUBMODULES: Tuple[str, ...] = (
    "constants",
    "runtime",
    "storage",
    "collector",
    "api",
)


def bind_submodules(loaded: Tuple[types.ModuleType, ...]) -> None:
    """Wire late-bound cross-submodule symbols once all modules are loaded."""
    by_name = {mod.__name__.rsplit('.', 1)[-1]: mod for mod in loaded}
    del by_name


def load_all(pkg_name: str = __name__) -> Tuple[types.ModuleType, ...]:
    loaded = tuple(importlib.import_module(f'{pkg_name}.{m}') for m in SUBMODULES)
    bind_submodules(loaded)
    return loaded
