"""Helper for static source-inspection tests of decomposed host daemons."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "ansible" / "roles" / "haproxy-admin" / "files"
GUARDD_DIR = FILES / "guardd"

SUBMODULES = (
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

PACKAGE_MODULES: dict[str, tuple[str, tuple[str, ...]]] = {
    "easy-ha-proxy-guardd.py": ("guardd", SUBMODULES),
    "easy-ha-proxy-metricsd.py": (
        "metricsd",
        ("constants", "runtime", "storage", "collector", "api"),
    ),
    "easy-ha-proxy-backupd.py": (
        "backupd",
        ("constants", "jobs", "operations", "destinations", "api"),
    ),
    "easy-ha-proxy-updated.py": (
        "updated",
        ("constants", "runner", "maintenance", "migrations", "api"),
    ),
    "haproxy-controld.py": (
        "controld",
        ("constants", "ipset_bans", "transactions", "rollback_geoip", "api"),
    ),
    "haproxy-certd.py": (
        "certd",
        ("constants", "issuance", "renewals", "internal_ca", "inventory_trash", "api"),
    ),
}


def daemon_source(name: str) -> str:
    """Return full daemon source (entrypoint + package submodules) for static tests."""
    spec = PACKAGE_MODULES.get(name)
    if spec is None:
        return (FILES / name).read_text(encoding="utf-8")
    pkg_name, mod_names = spec
    pkg_dir = FILES / pkg_name
    parts = [(FILES / name).read_text(encoding="utf-8")]
    for mod_name in mod_names:
        text = (pkg_dir / f"{mod_name}.py").read_text(encoding="utf-8")
        # Comment out future imports in subsequent chunks so ast.parse() works
        # on the concatenated source string.
        text = text.replace(
            "\nfrom __future__ import annotations\n",
            "\n# from __future__ import annotations\n",
        )
        parts.append(text)
    return "\n".join(parts)


def guardd_source() -> str:
    """Return the combined source of easy-ha-proxy-guardd (entrypoint + package)."""
    return daemon_source("easy-ha-proxy-guardd.py")
