"""Package implementation for haproxy-controld.py."""

from __future__ import annotations

import importlib
import types
from typing import Tuple

SUBMODULES: Tuple[str, ...] = (
    "constants",
    "ipset_bans",
    "transactions",
    "rollback_geoip",
    "api",
)


def bind_submodules(loaded: Tuple[types.ModuleType, ...]) -> None:
    """Wire late-bound cross-submodule symbols once all modules are loaded."""
    by_name = {mod.__name__.rsplit('.', 1)[-1]: mod for mod in loaded}
    by_name["rollback_geoip"].__dict__["_run_geoip_command"] = by_name["api"].__dict__["_run_geoip_command"]
    by_name["transactions"].__dict__["_rollback_config_transaction_locked"] = by_name["rollback_geoip"].__dict__["_rollback_config_transaction_locked"]
    by_name["transactions"].__dict__["_verify_transaction_admin_allowlist_candidate"] = by_name["rollback_geoip"].__dict__["_verify_transaction_admin_allowlist_candidate"]
    by_name["transactions"].__dict__["_verify_transaction_geoip_candidate"] = by_name["rollback_geoip"].__dict__["_verify_transaction_geoip_candidate"]


def load_all(pkg_name: str = __name__) -> Tuple[types.ModuleType, ...]:
    loaded = tuple(importlib.import_module(f'{pkg_name}.{m}') for m in SUBMODULES)
    bind_submodules(loaded)
    return loaded
