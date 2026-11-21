"""Helper for static source-inspection tests of easy-ha-proxy-guardd."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "ansible" / "roles" / "haproxy-admin" / "files"
GUARDD_DIR = FILES / "guardd"

SUBMODULES = (
    "constants",
    "parser",
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


def guardd_source() -> str:
    """Return the combined source of easy-ha-proxy-guardd (entrypoint + package)."""
    parts = [(FILES / "easy-ha-proxy-guardd.py").read_text(encoding="utf-8")]
    for name in SUBMODULES:
        parts.append((GUARDD_DIR / f"{name}.py").read_text(encoding="utf-8"))
    return "\n".join(parts)


def daemon_source(name: str) -> str:
    """Return full daemon source for static inspection tests."""
    if name == "easy-ha-proxy-guardd.py":
        return guardd_source()
    return (FILES / name).read_text(encoding="utf-8")
