"""Package implementation for easy-ha-proxy-updated.py."""

from __future__ import annotations

import importlib
import types
from typing import Tuple

SUBMODULES: Tuple[str, ...] = (
    "constants",
    "runner",
    "maintenance",
    "migrations",
    "api",
)


def bind_submodules(loaded: Tuple[types.ModuleType, ...]) -> None:
    """Wire late-bound cross-submodule symbols once all modules are loaded."""
    by_name = {mod.__name__.rsplit('.', 1)[-1]: mod for mod in loaded}
    by_name["constants"].__dict__["SYSTEMCTL_PATH"] = by_name["runner"].__dict__["SYSTEMCTL_PATH"]
    by_name["constants"].__dict__["read_file_tail"] = by_name["runner"].__dict__["read_file_tail"]
    by_name["constants"].__dict__["stop_transient_unit"] = by_name["runner"].__dict__["stop_transient_unit"]
    by_name["constants"].__dict__["systemctl_properties"] = by_name["runner"].__dict__["systemctl_properties"]
    by_name["constants"].__dict__["transient_jobs_supported"] = by_name["runner"].__dict__["transient_jobs_supported"]
    by_name["maintenance"].__dict__["OS_SECURITY_ROOT"] = by_name["migrations"].__dict__["OS_SECURITY_ROOT"]
    by_name["maintenance"].__dict__["auto_reboot_tick"] = by_name["migrations"].__dict__["auto_reboot_tick"]
    by_name["maintenance"].__dict__["current_boot_id"] = by_name["api"].__dict__["current_boot_id"]
    by_name["maintenance"].__dict__["haproxy_operation"] = by_name["migrations"].__dict__["haproxy_operation"]
    by_name["maintenance"].__dict__["os_security_check_tick"] = by_name["api"].__dict__["os_security_check_tick"]
    by_name["maintenance"].__dict__["os_security_local_time"] = by_name["migrations"].__dict__["os_security_local_time"]
    by_name["maintenance"].__dict__["os_security_snapshot"] = by_name["migrations"].__dict__["os_security_snapshot"]
    by_name["maintenance"].__dict__["os_security_tick"] = by_name["api"].__dict__["os_security_tick"]
    by_name["maintenance"].__dict__["os_security_watch"] = by_name["migrations"].__dict__["os_security_watch"]
    by_name["maintenance"].__dict__["os_security_worker"] = by_name["migrations"].__dict__["os_security_worker"]
    by_name["maintenance"].__dict__["reboot_guard_present"] = by_name["api"].__dict__["reboot_guard_present"]
    by_name["maintenance"].__dict__["request_reboot"] = by_name["api"].__dict__["request_reboot"]
    by_name["maintenance"].__dict__["service_reboot_reason"] = by_name["migrations"].__dict__["service_reboot_reason"]
    by_name["maintenance"].__dict__["service_restart_tick"] = by_name["migrations"].__dict__["service_restart_tick"]
    by_name["migrations"].__dict__["current_boot_id"] = by_name["api"].__dict__["current_boot_id"]
    by_name["migrations"].__dict__["reboot_marker_state"] = by_name["api"].__dict__["reboot_marker_state"]
    by_name["migrations"].__dict__["request_identity"] = by_name["api"].__dict__["request_identity"]
    by_name["migrations"].__dict__["request_reboot"] = by_name["api"].__dict__["request_reboot"]
    by_name["migrations"].__dict__["restart_check_predates_boot"] = by_name["api"].__dict__["restart_check_predates_boot"]
    by_name["migrations"].__dict__["start_os_security"] = by_name["api"].__dict__["start_os_security"]
    by_name["migrations"].__dict__["stop_reboot_unit"] = by_name["api"].__dict__["stop_reboot_unit"]
    by_name["runner"].__dict__["auto_install_settings"] = by_name["maintenance"].__dict__["auto_install_settings"]
    by_name["runner"].__dict__["haproxy_patch_active"] = by_name["migrations"].__dict__["haproxy_patch_active"]
    by_name["runner"].__dict__["last_auto_install"] = by_name["maintenance"].__dict__["last_auto_install"]
    by_name["runner"].__dict__["read_deployment"] = by_name["maintenance"].__dict__["read_deployment"]
    by_name["runner"].__dict__["reboot_guard_present"] = by_name["api"].__dict__["reboot_guard_present"]
    by_name["runner"].__dict__["security_recovery_pending"] = by_name["migrations"].__dict__["security_recovery_pending"]


def load_all(pkg_name: str = __name__) -> Tuple[types.ModuleType, ...]:
    loaded = tuple(importlib.import_module(f'{pkg_name}.{m}') for m in SUBMODULES)
    bind_submodules(loaded)
    return loaded
