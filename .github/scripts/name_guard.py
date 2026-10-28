#!/usr/bin/env python3
"""Keep the names of real installations out of a public repository.

The words come from the NAME_GUARD_WORDS secret, one per line, and never
from the repository: the list would name the very installations it keeps
out. Every tracked file is searched, and the messages of the commits being
pushed (BASE..HEAD, when both are given). A hit is reported by file and
line, or by commit, and never with the word or the line, so the log does
not repeat what it found.

Without the secret -- a fork, or before it has been added -- the check says
so and passes.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


def words_from(text: str) -> list[str]:
    return sorted({line.strip().casefold() for line in text.splitlines() if line.strip()})


def tracked_files(root: Path) -> list[str]:
    listed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True
    ).stdout
    return [name for name in listed.decode("utf-8", "surrogateescape").split("\0") if name]


def file_hits(root: Path, words: list[str]) -> list[str]:
    hits = []
    for name in tracked_files(root):
        path = root / name
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if b"\0" in data[:8192]:
            continue  # binary
        for number, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
            folded = line.casefold()
            if any(word in folded for word in words):
                hits.append(f"{name}:{number}")
    return hits


def message_hits(root: Path, words: list[str], base: str, head: str) -> list[str]:
    if not base or not head or set(base) == {"0"}:
        return []
    log = subprocess.run(
        ["git", "-C", str(root), "log", "--format=%H%x00%B%x01", f"{base}..{head}"],
        capture_output=True, text=True, check=True,
    ).stdout
    hits = []
    for entry in log.split("\x01"):
        commit, _, message = entry.strip().partition("\0")
        if commit and any(word in message.casefold() for word in words):
            hits.append(f"commit {commit[:12]}")
    return hits


def main() -> int:
    words = words_from(os.environ.get("NAME_GUARD_WORDS", ""))
    if not words:
        print("::notice::NAME_GUARD_WORDS is not set, so no names were checked.")
        return 0
    root = Path(os.environ.get("NAME_GUARD_ROOT", ".")).resolve()
    hits = file_hits(root, words) + message_hits(
        root, words, os.environ.get("NAME_GUARD_BASE", ""), os.environ.get("NAME_GUARD_HEAD", "")
    )
    for hit in hits:
        print(f"::error::A guarded name appears at {hit}")
    print(f"{len(words)} guarded names, {len(hits)} found.")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
