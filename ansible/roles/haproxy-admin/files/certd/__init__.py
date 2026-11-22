"""Package implementation for haproxy-certd.py."""

from __future__ import annotations

import importlib
import types
from typing import Tuple

SUBMODULES: Tuple[str, ...] = (
    "constants",
    "issuance",
    "renewals",
    "internal_ca",
    "inventory_trash",
    "api",
)


def bind_submodules(loaded: Tuple[types.ModuleType, ...]) -> None:
    """Wire late-bound cross-submodule symbols once all modules are loaded."""
    by_name = {mod.__name__.rsplit('.', 1)[-1]: mod for mod in loaded}
    by_name["constants"].__dict__["_trash_commit"] = by_name["inventory_trash"].__dict__["_trash_commit"]
    by_name["constants"].__dict__["_trash_listing"] = by_name["inventory_trash"].__dict__["_trash_listing"]
    by_name["constants"].__dict__["_trash_put"] = by_name["inventory_trash"].__dict__["_trash_put"]
    by_name["constants"].__dict__["_trash_settle"] = by_name["inventory_trash"].__dict__["_trash_settle"]
    by_name["internal_ca"].__dict__["APPLIED_WEBSITES"] = by_name["api"].__dict__["APPLIED_WEBSITES"]
    by_name["internal_ca"].__dict__["_cert_details"] = by_name["api"].__dict__["_cert_details"]
    by_name["internal_ca"].__dict__["_trash_commit"] = by_name["inventory_trash"].__dict__["_trash_commit"]
    by_name["internal_ca"].__dict__["_trash_listing"] = by_name["inventory_trash"].__dict__["_trash_listing"]
    by_name["internal_ca"].__dict__["_trash_put"] = by_name["inventory_trash"].__dict__["_trash_put"]
    by_name["internal_ca"].__dict__["_trash_settle"] = by_name["inventory_trash"].__dict__["_trash_settle"]
    by_name["inventory_trash"].__dict__["_cert_details"] = by_name["api"].__dict__["_cert_details"]
    by_name["inventory_trash"].__dict__["_trash_purge_locked"] = by_name["api"].__dict__["_trash_purge_locked"]
    by_name["issuance"].__dict__["_trash_commit"] = by_name["inventory_trash"].__dict__["_trash_commit"]
    by_name["issuance"].__dict__["_trash_listing"] = by_name["inventory_trash"].__dict__["_trash_listing"]
    by_name["issuance"].__dict__["_trash_put"] = by_name["inventory_trash"].__dict__["_trash_put"]
    by_name["issuance"].__dict__["_trash_settle"] = by_name["inventory_trash"].__dict__["_trash_settle"]
    by_name["issuance"].__dict__["read_pin"] = by_name["renewals"].__dict__["read_pin"]
    by_name["renewals"].__dict__["_load_client_auth_ids"] = by_name["internal_ca"].__dict__["_load_client_auth_ids"]
    by_name["renewals"].__dict__["_load_revoked_fingerprints"] = by_name["internal_ca"].__dict__["_load_revoked_fingerprints"]
    by_name["renewals"].__dict__["_names_claimed_by"] = by_name["internal_ca"].__dict__["_names_claimed_by"]
    by_name["renewals"].__dict__["_subject_cns"] = by_name["internal_ca"].__dict__["_subject_cns"]
    by_name["renewals"].__dict__["get_latest_account_id"] = by_name["inventory_trash"].__dict__["get_latest_account_id"]


def load_all(pkg_name: str = __name__) -> Tuple[types.ModuleType, ...]:
    loaded = tuple(importlib.import_module(f'{pkg_name}.{m}') for m in SUBMODULES)
    bind_submodules(loaded)
    return loaded
