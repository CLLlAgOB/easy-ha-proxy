# -*- coding: utf-8 -*-
"""Client of the root service easy-ha-proxy-metricsd over a Unix socket.

The daemon is read-only and reachable only over its socket; the timeouts are
short, so the monitoring page does not hang a worker while the collector is busy.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

from .daemon_transport import UnixHttp


METRICSD_SOCKET_PATH = os.environ.get(
    "METRICSD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-metricsd.sock"
).strip()

DEFAULT_TIMEOUT = 10


class MetricsdUnavailable(RuntimeError):
    """The collector does not answer: the page must degrade, not fail."""


def _metricsd() -> UnixHttp:
    return UnixHttp("metricsd", METRICSD_SOCKET_PATH, MetricsdUnavailable)


def _get_json(
    path: str,
    params: Optional[Dict[str, Any]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    return _metricsd().get(path, params=params, timeout=timeout)


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

    body: Dict[str, Any] = {"labels": labels}
    # Omitted rather than empty when unchanged: the daemon reads "absent" as
    # "leave it", so a caller that only renames cannot empty the list.
    if hidden is not None:
        body["hidden"] = list(hidden)
    # A rejected label is the operator's typo, and the daemon says which.
    return _metricsd().post("/api/v1/metrics/channel-labels", body, timeout=DEFAULT_TIMEOUT,
                            rejected_status=400, require_object=True)


def metricsd_monitors_save(changes: Dict[str, bool]) -> Dict[str, Any]:
    """Switch monitors on or off; the daemon says which name it refused."""

    return _metricsd().post("/api/v1/metrics/monitors", {"monitors": changes},
                            timeout=DEFAULT_TIMEOUT, rejected_status=400,
                            require_object=True)


def metricsd_states(range_key: str, site: str = "",
                    window: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    return _get_json(
        "/api/v1/metrics/states",
        params=_window_params(range_key, site, window),
        timeout=15,
    )


def metricsd_series(chart: str, range_key: str, site: str = "",
                    window: Optional[Dict[str, int]] = None,
                    components: bool = True) -> Dict[str, Any]:
    params = _window_params(range_key, site, window)
    params["chart"] = chart
    params["components"] = "1" if components else "0"
    return _get_json("/api/v1/metrics/series", params=params, timeout=15)
