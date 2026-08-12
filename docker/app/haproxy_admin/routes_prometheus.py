# routes_prometheus.py
#
# Необязательный эндпоинт /metrics. Prometheus не может пройти вход через
# Authelia, поэтому HAProxy пропускает этот путь для адресов из отдельного
# списка и помечает запрос собственной ограниченной личностью. Здесь стоит
# второй, независимый замок: bearer-токен.

from __future__ import annotations

import hmac
import logging
import os

from flask import Response, g, request

from .routes import bp
from .services_prometheus import collect

LOG = logging.getLogger("haproxy-admin")

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def _enabled() -> bool:
    return os.environ.get("METRICS_EXPORT_ENABLED", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def _token_ok() -> bool:
    """Compare the bearer token in constant time.

    An empty configured token means the endpoint has no second lock, which is
    a configuration mistake rather than a reason to serve the metrics: an
    allow-listed source is not by itself proof of who is asking.
    """
    expected = os.environ.get("METRICS_EXPORT_TOKEN", "").strip()
    if not expected:
        return False
    header = request.headers.get("Authorization", "")
    scheme, _, supplied = header.partition(" ")
    if scheme.lower() != "bearer":
        return False
    return hmac.compare_digest(supplied.strip(), expected)


@bp.get("/metrics")
def prometheus_metrics():
    """Serve the exposition, or say plainly why not.

    A 404 while disabled rather than a 403: an endpoint that is switched off
    should not confirm its own existence to something that cannot use it.
    """
    if not _enabled():
        return Response("", status=404, mimetype="text/plain")
    if not _token_ok():
        response = Response("", status=401, mimetype="text/plain")
        response.headers["WWW-Authenticate"] = 'Bearer realm="metrics"'
        return response

    try:
        body = collect()
    except Exception:  # pylint: disable=broad-except
        # A scrape failure must not look like a gateway failure, and the
        # scraper only needs to know this target is not answering.
        LOG.exception("prometheus exposition failed")
        return Response("", status=503, mimetype="text/plain")

    response = Response(body, mimetype=CONTENT_TYPE)
    response.headers["Cache-Control"] = "no-store"
    return response
