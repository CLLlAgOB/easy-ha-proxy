#!/usr/bin/env python3
"""Report newer releases of the versions pinned in Ansible role defaults.

Dependabot reads requirements files, Dockerfiles and workflows, but not the
images and packages pinned as Ansible variables (Authelia, Redis, the mail
relay, the GeoIP packages). This compares each pin with its registry:

- the newest release in the same series (same major.minor, same suffix such
  as "-alpine") -- the update to take without much thought;
- the newest release overall -- worth a look, may need care.

Prints a Markdown report; with --github it also writes the job summary and
keeps one issue open while anything is behind (closed when nothing is).
Standard library only, so it runs on a bare runner.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Callable, Iterable, Optional
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[2]
ISSUE_TITLE = "Pinned versions have updates"

# (defaults file, variable, source, name). For a Docker Hub image given as a
# bare version the image name is here; a full reference carries its own.
PINS = (
    ("ansible/roles/authelia/defaults/main.yml", "authelia_version", "dockerhub", "authelia/authelia"),
    ("ansible/roles/authelia/defaults/main.yml", "authelia_redis_image", "dockerhub", None),
    ("ansible/roles/authelia/defaults/main.yml", "mail_relay_image", "dockerhub", None),
    ("ansible/roles/geoip_acl/defaults/main.yml", "geoip_maxminddb_version", "pypi", "maxminddb"),
    ("ansible/roles/geoip_acl/defaults/main.yml", "geoip_pyyaml_version", "pypi", "PyYAML"),
)

_VERSION_RE = re.compile(r"^v?(?P<numbers>\d+(?:\.\d+)*)(?P<suffix>-[A-Za-z0-9.]+)?$")
_PRERELEASE_RE = re.compile(r"(?i)(alpha|beta|rc|dev|pre|preview)")


def parse_version(tag: str) -> Optional[tuple[tuple[int, ...], str]]:
    """(numbers, suffix) for a release tag, or None for anything else."""
    match = _VERSION_RE.match(tag.strip())
    if not match:
        return None
    suffix = match.group("suffix") or ""
    if _PRERELEASE_RE.search(suffix):
        return None
    return tuple(int(part) for part in match.group("numbers").split(".")), suffix


def newer_releases(pinned: str, tags: Iterable[str]) -> dict[str, Optional[str]]:
    """The newest release in the pinned series and the newest overall, both
    only if newer than the pin and of the same shape (part count, suffix)."""
    parsed = parse_version(pinned)
    if parsed is None:
        return {"series": None, "latest": None}
    numbers, suffix = parsed
    candidates = []
    for tag in tags:
        found = parse_version(tag)
        if found and found[1] == suffix and len(found[0]) == len(numbers) and found[0] > numbers:
            candidates.append((found[0], tag))
    candidates.sort()
    series = [tag for parts, tag in candidates if parts[:2] == numbers[:2]]
    return {
        "series": series[-1] if series else None,
        "latest": candidates[-1][1] if candidates else None,
    }


def read_pin(text: str, variable: str) -> Optional[str]:
    match = re.search(rf"^{re.escape(variable)}:\s*['\"]?([^'\"\s#]+)", text, re.MULTILINE)
    return match.group(1) if match else None


def split_image(reference: str) -> tuple[str, str]:
    name, _, tag = reference.rpartition(":")
    return name, tag


def _get_json(url: str) -> dict:
    request = Request(url, headers={"User-Agent": "easy-ha-proxy-pinned-versions"})
    with urlopen(request, timeout=30) as response:  # noqa: S310 - fixed https URLs
        return json.loads(response.read().decode("utf-8"))


def dockerhub_tags(image: str, fetch: Callable[[str], dict] = _get_json, pages: int = 4) -> list[str]:
    namespace, _, repository = image.rpartition("/")
    namespace = namespace or "library"
    url = (f"https://hub.docker.com/v2/namespaces/{namespace}/repositories/{repository}"
           "/tags?page_size=100&ordering=last_updated")
    tags: list[str] = []
    for _ in range(pages):
        data = fetch(url)
        tags.extend(str(item.get("name")) for item in data.get("results") or [])
        url = data.get("next")
        if not url:
            break
    return tags


def pypi_versions(package: str, fetch: Callable[[str], dict] = _get_json) -> list[str]:
    data = fetch(f"https://pypi.org/pypi/{package}/json")
    return list((data.get("releases") or {}).keys())


def check(root: Path = ROOT, fetch: Callable[[str], dict] = _get_json) -> list[dict]:
    rows = []
    for relative, variable, source, name in PINS:
        text = (root / relative).read_text(encoding="utf-8")
        value = read_pin(text, variable)
        row = {"variable": variable, "file": relative, "pinned": value, "error": ""}
        if not value:
            row["error"] = "not found"
            rows.append(row)
            continue
        try:
            if source == "dockerhub":
                image, pinned = (name, value) if name else split_image(value)
                row.update(name=image, pinned=pinned)
                row.update(newer_releases(pinned, dockerhub_tags(image, fetch)))
            else:
                row.update(name=name)
                row.update(newer_releases(value, pypi_versions(name, fetch)))
        except Exception as exc:  # noqa: BLE001 - one registry down is a line, not a crash
            row["error"] = str(exc)[:200]
        rows.append(row)
    return rows


def report(rows: list[dict]) -> str:
    lines = ["| Pinned | Version | Same series | Newest |", "|---|---|---|---|"]
    for row in rows:
        label = f"`{row['variable']}` ({row.get('name') or '?'})"
        if row["error"]:
            lines.append(f"| {label} | {row.get('pinned') or '-'} | error: {row['error']} | |")
            continue
        lines.append(
            f"| {label} | {row['pinned']} | {row.get('series') or '-'} | {row.get('latest') or '-'} |"
        )
    return "\n".join(lines) + "\n"


def behind(rows: list[dict]) -> bool:
    return any(row.get("series") or row.get("latest") for row in rows)


def sync_issue(body: str, outdated: bool) -> None:
    """One open issue while anything is behind; closed once nothing is."""
    found = subprocess.run(
        ["gh", "issue", "list", "--state", "open", "--search", f'in:title "{ISSUE_TITLE}"',
         "--json", "number,title"],
        check=True, capture_output=True, text=True,
    )
    issues = [item for item in json.loads(found.stdout or "[]") if item.get("title") == ISSUE_TITLE]
    if outdated and issues:
        subprocess.run(["gh", "issue", "edit", str(issues[0]["number"]), "--body", body], check=True)
    elif outdated:
        subprocess.run(["gh", "issue", "create", "--title", ISSUE_TITLE, "--body", body], check=True)
    else:
        for issue in issues:
            subprocess.run(["gh", "issue", "close", str(issue["number"]),
                            "--comment", "Every pinned version is current."], check=True)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--github", action="store_true",
                        help="write the job summary and keep the tracking issue in step")
    args = parser.parse_args(argv)
    rows = check()
    text = report(rows)
    print(text)
    if args.github:
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as handle:
                handle.write("## Pinned versions\n\n" + text)
        body = (
            "Versions pinned in Ansible role defaults that have newer releases. "
            "Take the same-series update after reading its notes; a newer series may "
            "need care.\n\n" + text
        )
        sync_issue(body, behind(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
