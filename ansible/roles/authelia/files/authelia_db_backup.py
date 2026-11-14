#!/usr/bin/env python3
"""Copy Authelia's SQLite database before a different Authelia image runs on it.

A new Authelia version migrates its storage schema on first start, and there
is no way back: the old version refuses a newer schema. The only rollback is
the database as it was, so the role takes this copy just before the stack is
recreated on a different image.

Usage: authelia_db_backup.py SOURCE BACKUP_DIR LABEL KEEP

The copy is taken through SQLite's online backup API, so Authelia keeps
running and the copy is consistent even mid-write. It is integrity-checked,
written under a temporary name and renamed into place, readable by root only.
Only the newest KEEP copies made by this script are kept. Exit status 0 means
a verified copy exists (or there was no database to copy); anything else
means the caller must not let the new image start.
"""

from __future__ import annotations

import datetime as dt
import os
from pathlib import Path
import re
import sqlite3
import sys


PREFIX = "authelia-db-"
SUFFIX = ".sqlite3"


def backup(source: Path, directory: Path, label: str, keep: int) -> Path | None:
    if not source.is_file():
        return None
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    safe_label = re.sub(r"[^A-Za-z0-9._-]+", "_", label)[:80] or "unknown"
    target = directory / f"{PREFIX}{stamp}-{safe_label}{SUFFIX}"
    partial = target.with_name(target.name + ".partial")
    descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    try:
        with sqlite3.connect(f"file:{source}?mode=ro", uri=True) as origin, \
                sqlite3.connect(partial) as copy:
            origin.backup(copy)
        with sqlite3.connect(f"file:{partial}?mode=ro", uri=True) as check:
            result = check.execute("PRAGMA integrity_check").fetchone()
        if not result or result[0] != "ok":
            raise RuntimeError(f"the copy failed its integrity check: {result!r}")
        os.chmod(partial, 0o600)
        os.replace(partial, target)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    prune(directory, keep)
    return target


def prune(directory: Path, keep: int) -> None:
    copies = sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and path.name.startswith(PREFIX) and path.name.endswith(SUFFIX)
    )
    for path in copies[: max(len(copies) - max(keep, 1), 0)]:
        path.unlink()


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    source, directory, label, keep = argv[1:]
    try:
        copied = backup(Path(source), Path(directory), label, int(keep))
    except Exception as exc:  # noqa: BLE001 - reported to Ansible verbatim
        print(f"Authelia database backup failed: {exc}", file=sys.stderr)
        return 1
    print(copied if copied else f"no database at {source}; nothing to copy")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
