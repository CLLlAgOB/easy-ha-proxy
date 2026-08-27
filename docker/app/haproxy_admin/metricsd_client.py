# -*- coding: utf-8 -*-
"""Клиент к root-сервису easy-ha-proxy-metricsd через Unix-socket.

Демон отдаёт только чтение и только по сокету; тайм-ауты держим короткими,
чтобы страница мониторинга не подвешивала воркер, если сборщик занят.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional
from urllib.parse import quote

import requests

try:
    import requests_unixsocket  # type: ignore
except Exception:  # pylint: disable=broad-except
    requests_unixsocket = None  # type: ignore


LOG = logging.getLogger("haproxy-admin")

METRICSD_SOCKET_PATH = os.environ.get(
    "METRICSD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-metricsd.sock"
).strip()

DEFAULT_TIMEOUT = 10


class MetricsdUnavailable(RuntimeError):
    """Сборщик не отвечает: страница должна деградировать, а не падать."""


def _session() -> requests.Session:
    if requests_unixsocket is None:
        raise MetricsdUnavailable("requests-unixsocket is not installed")
    return requests_unixsocket.Session()  # type: ignore[return-value]


def _get_json(
    path: str,
    params: Optional[Dict[str, Any]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    url = "http+unix://" + quote(METRICSD_SOCKET_PATH, safe="") + path
    try:
        response = _session().get(url, params=params or {}, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except MetricsdUnavailable:
        raise
    except ValueError as exc:
        raise MetricsdUnavailable("metricsd returned a non-JSON response") from exc
    except Exception as exc:  # pylint: disable=broad-except
        raise MetricsdUnavailable(str(exc)) from exc


def _window_params(
    range_key: str,
    site: str = "",
    window: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """A preset, or the exact period the operator asked for.

    The daemon prefers since/until when both are present, so sending the
    preset alongside costs nothing and keeps a label in the answer.
    """

    params: Dict[str, Any] = {"range": range_key}
    if site:
        params["site"] = site
    if window and window.get("since") and window.get("until"):
        params["since"] = int(window["since"])
        params["until"] = int(window["until"])
    return params


def metricsd_health() -> Dict[str, Any]:
    return _get_json("/api/v1/metrics/health")


def metricsd_storage() -> Dict[str, Any]:
    return _get_json("/api/v1/metrics/storage")


def metricsd_sites() -> Dict[str, Any]:
    return _get_json("/api/v1/metrics/sites")


def metricsd_summary(range_key: str, site: str = "",
                     window: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    return _get_json(
        "/api/v1/metrics/summary",
        params=_window_params(range_key, site, window),
        timeout=15,
    )


def metricsd_servers(range_key: str,
                     window: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    """Traffic per backend server, for grouping into uplinks.

    Never scoped to one site: a link carries every site pointed at it.
    """

    return _get_json(
        "/api/v1/metrics/servers", params=_window_params(range_key, "", window)
    )


def metricsd_channel_labels_save(
    labels: Dict[str, str], hidden: Optional[list] = None
) -> Dict[str, Any]:
    """The operator's names for the links, and which ones they put away."""

    url = ("http+unix://" + quote(METRICSD_SOCKET_PATH, safe="")
           + "/api/v1/metrics/channel-labels")
    body: Dict[str, Any] = {"labels": labels}
    # Omitted rather than empty when unchanged: the daemon reads "absent" as
    # "leave it", so a caller that only renames cannot empty the list.
    if hidden is not None:
        body["hidden"] = list(hidden)
    try:
        response = _session().post(url, json=body, timeout=DEFAULT_TIMEOUT)
        # A rejected label is the operator's typo, and the daemon says which.
        if response.status_code == 400:
            raise ValueError((response.json() or {}).get("error") or "rejected")
        response.raise_for_status()
        data = response.json()
    except (MetricsdUnavailable, ValueError):
        raise
    except Exception as exc:  # pylint: disable=broad-except
        raise MetricsdUnavailable(str(exc)) from exc
    if not isinstance(data, dict):
        raise MetricsdUnavailable("metricsd returned an unexpected payload")
    return data


def metricsd_states(range_key: str, site: str = "") -> Dict[str, Any]:
    params: Dict[str, Any] = {"range": range_key}
    if site:
        params["site"] = site
    return _get_json("/api/v1/metrics/states", params=params, timeout=15)


def metricsd_series(chart: str, range_key: str, site: str = "") -> Dict[str, Any]:
    params: Dict[str, Any] = {"chart": chart, "range": range_key}
    if site:
        params["site"] = site
    return _get_json("/api/v1/metrics/series", params=params, timeout=15)
