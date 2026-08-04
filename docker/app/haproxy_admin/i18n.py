"""Small, dependency-free localization layer for the web interface.

The UI uses English source strings. Translation catalogs map those strings to
the selected language and are shared with the browser so server-rendered and
dynamically generated content use the same vocabulary.
"""

from __future__ import annotations

from functools import lru_cache
import json
import logging
import os
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit

from flask import Request, current_app, g, has_request_context, request


logger = logging.getLogger("haproxy-admin")

CATALOG_DIR = Path(__file__).with_name("translations")
DEFAULT_LANGUAGE = os.environ.get("HAPROXY_ADMIN_DEFAULT_LANGUAGE", "en").strip().lower()
if DEFAULT_LANGUAGE not in {"en", "ru"}:
    DEFAULT_LANGUAGE = "en"
LANGUAGE_COOKIE = "easy_ha_proxy_language"


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate translation key: {key}")
        result[key] = value
    return result


@lru_cache(maxsize=1)
def load_catalogs() -> dict[str, dict[str, Any]]:
    """Load and validate every ``translations/*.json`` catalog."""

    catalogs: dict[str, dict[str, Any]] = {}
    for path in sorted(CATALOG_DIR.rglob("*.json")):
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle, object_pairs_hook=_unique_object)

        meta = payload.get("meta")
        messages = payload.get("messages")
        if not isinstance(meta, dict) or not isinstance(messages, dict):
            raise ValueError(f"Invalid translation catalog: {path}")

        code = str(meta.get("code", "")).strip().lower()
        label = str(meta.get("label", "")).strip()
        if not code or not label:
            raise ValueError(f"Invalid translation metadata: {path}")
        if not all(isinstance(key, str) and isinstance(value, str) for key, value in messages.items()):
            raise ValueError(f"Translation messages must be strings: {path}")

        if code in catalogs:
            catalog = catalogs[code]
            if catalog["label"] != label:
                raise ValueError(f"Conflicting translation label: {path}")
            duplicates = catalog["messages"].keys() & messages.keys()
            if duplicates:
                duplicate = sorted(duplicates)[0]
                raise ValueError(f"Duplicate translation key for {code}: {duplicate}")
            catalog["messages"].update(messages)
        else:
            catalogs[code] = {"code": code, "label": label, "messages": messages}

    if DEFAULT_LANGUAGE not in catalogs or "ru" not in catalogs:
        raise RuntimeError("The en and ru translation catalogs are required")
    return catalogs


def supported_languages() -> list[dict[str, str]]:
    return [
        {"code": item["code"], "label": item["label"]}
        for item in load_catalogs().values()
    ]


def normalize_language(value: str | None) -> str | None:
    if not value:
        return None
    code = value.strip().lower().replace("_", "-").split("-", 1)[0]
    return code if code in load_catalogs() else None


def select_language(req: Request) -> str:
    """Select locale from the saved preference, then browser preferences."""

    saved = normalize_language(req.cookies.get(LANGUAGE_COOKIE))
    if saved:
        return saved
    match = req.accept_languages.best_match(list(load_catalogs()))
    return normalize_language(match) or DEFAULT_LANGUAGE


def get_messages(language: str | None = None) -> dict[str, str]:
    code = normalize_language(language) or DEFAULT_LANGUAGE
    return load_catalogs()[code]["messages"]


@lru_cache(maxsize=None)
def _replacement_rules(language: str) -> tuple[tuple[re.Pattern[str] | None, str, str], ...]:
    rules = []
    for source, target in sorted(
        get_messages(language).items(), key=lambda item: len(item[0]), reverse=True
    ):
        if not source or source == target:
            continue
        pattern = None
        if re.fullmatch(r"[\w-]+", source, flags=re.UNICODE):
            pattern = re.compile(rf"(?<!\w){re.escape(source)}(?!\w)", re.UNICODE)
        rules.append((pattern, source, target))
    return tuple(rules)


def translate(message: str, language: str | None = None, **values: Any) -> str:
    """Translate a source message and optionally format placeholders."""

    selected = language or (
        getattr(g, "language", DEFAULT_LANGUAGE)
        if has_request_context()
        else DEFAULT_LANGUAGE
    )
    messages = get_messages(selected)
    normalized = " ".join(message.split())
    translated = messages.get(message, messages.get(normalized, message))
    if translated == message:
        for pattern, source, target in _replacement_rules(selected):
            translated = (
                pattern.sub(lambda _match: target, translated)
                if pattern is not None
                else translated.replace(source, target)
            )
    if not values:
        return translated
    try:
        return translated.format(**values)
    except (IndexError, KeyError, ValueError):
        # A stray brace or an unknown placeholder in a catalog entry must not
        # turn a user-facing message into a 500; show the unformatted text.
        logger.warning("Cannot format translated message: %r", translated)
        return translated


def init_request_language() -> None:
    g.language = select_language(request)


def localize_json_response(response):
    """Translate user-facing message fields returned by JSON endpoints."""

    if not response.is_json:
        return response
    payload = response.get_json(silent=True)
    if payload is None:
        return response

    def localize(value: Any, key: str | None = None) -> Any:
        if isinstance(value, dict):
            return {item_key: localize(item, item_key) for item_key, item in value.items()}
        if isinstance(value, list):
            return [localize(item, key) for item in value]
        if isinstance(value, str) and key in {"error", "message", "warning", "detail"}:
            return translate(value)
        return value

    response.set_data(current_app.json.dumps(localize(payload)))
    return response


def safe_local_redirect(value: str | None, fallback: str = "/") -> str:
    """Allow only an absolute path on this host as a post-switch redirect."""

    if not value or "\\" in value or any(ord(char) < 32 for char in value):
        return fallback
    target = urlsplit(value)
    if target.scheme or target.netloc or not target.path.startswith("/") or target.path.startswith("//"):
        return fallback
    return value


def clear_catalog_cache() -> None:
    """Test/development helper used after adding or changing catalogs."""

    load_catalogs.cache_clear()
    _replacement_rules.cache_clear()
