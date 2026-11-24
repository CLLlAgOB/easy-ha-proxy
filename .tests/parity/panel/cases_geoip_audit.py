"""GeoIP management through controld, and the change log API."""
import copy
import re

import yaml

REV = "a" * 64
SEL = {"countries": ["DE", "RU"], "access_filter_enabled": True, "revision": REV}
STATUS = {"ok": True, "selection": SEL, "schedule": "weekly", "database": {"built": "2026-11-01"}}
CONTROLD = {
    "geoip-status": {"b64json": STATUS},
    "geoip-update": {"b64json": {"ok": True, "status": STATUS}},
    "geoip-configure": {"b64json": {"ok": True, "status": dict(STATUS, selection=dict(SEL, countries=["DE", "FR", "RU"]))}},
    "geoip-schedule": {"b64json": {"ok": True, "status": dict(STATUS, schedule="daily")}},
    "config-transaction-status": {"b64json": {"ok": True, "state": "none"}},
}
BASE = {"controld": CONTROLD}
REPLIES = BASE


def setup():
    path = "/opt/haproxy-admin/config/vars.yml"
    data = yaml.safe_load(open(path)) or {}
    data["enable_geoip"] = True
    data["geoip_mode"] = " Allow "
    data["geoip_country_codes"] = ["ru", "de"]
    with open(path, "w") as fh:
        yaml.safe_dump(data, fh, allow_unicode=True, sort_keys=False)
    path = "/opt/haproxy-admin/config/websites.yml"
    data = yaml.safe_load(open(path)) or {}
    data["sites"][0]["geo_countries"] = ["fr", "DE"]
    data["sites"][1]["geo_countries"] = ["FR"]
    with open(path, "w") as fh:
        yaml.safe_dump(data, fh, allow_unicode=True, sort_keys=False)


def with_(key, value):
    r = copy.deepcopy(BASE)
    r["controld"][key] = value
    return r


def j(body, **kw):
    return dict({"json_body": body}, **kw)


def normalize_body(label, body):
    body = re.sub(r'"(ts|oldest_ts|newest_ts)": 1[0-9]{9}', r'"\1": T', body)
    body = re.sub(r'"bytes": [0-9]+', '"bytes": B', body)
    return body


STEPS = [
    ("csrf", "GET", "/system/alerts"),
    ("status", "GET", "/haproxy/geoip/status"),
    ("status out of sync", "GET", "/haproxy/geoip/status", {"replies": with_("geoip-status", {"b64json": dict(
        STATUS, selection=dict(SEL, access_filter_enabled=False))})}),
    ("status no selection", "GET", "/haproxy/geoip/status", {"replies": with_("geoip-status", {"b64json": {"ok": True}})}),
    ("status error", "GET", "/haproxy/geoip/status", {"replies": with_("geoip-status", {"b64json": {"error": "x"}, })}),
    ("status controld error", "GET", "/haproxy/geoip/status", {"replies": with_("geoip-status", "ERROR eyJmYWlsdXJlIjogImJ1c3kifQ==")}),
    ("update bad fields", "POST", "/haproxy/geoip/update", j({"force": True, "x": 1}, replies=BASE)),
    ("update list", "POST", "/haproxy/geoip/update", j([1])),
    ("update", "POST", "/haproxy/geoip/update", j({})),
    ("update force", "POST", "/haproxy/geoip/update", j({"force": "yes"})),
    ("update conflict", "POST", "/haproxy/geoip/update", j({}, replies=with_("geoip-update", {"b64json": {
        "ok": False, "conflict": True, "error": "an update is running"}}))),
    ("countries missing", "POST", "/haproxy/geoip/countries", j({"countries": ["DE"]}, replies=BASE)),
    ("countries not list", "POST", "/haproxy/geoip/countries", j({"countries": "DE", "revision": REV})),
    ("countries bad code", "POST", "/haproxy/geoip/countries", j({"countries": ["DEU"], "revision": REV})),
    ("countries int", "POST", "/haproxy/geoip/countries", j({"countries": [1], "revision": REV})),
    ("countries too many", "POST", "/haproxy/geoip/countries", j({"countries": ["DE"] * 250, "revision": REV})),
    ("countries site needs", "POST", "/haproxy/geoip/countries", j({"countries": ["DE"], "revision": REV})),
    ("countries bad revision", "POST", "/haproxy/geoip/countries", j({"countries": ["de", "FR"], "revision": "xyz"})),
    ("countries ok", "POST", "/haproxy/geoip/countries", j({"countries": [" fr ", "de", "DE"], "revision": " " + REV.upper() + " "})),
    ("countries pending", "POST", "/haproxy/geoip/countries", j({"countries": ["DE", "FR"], "revision": REV}, replies=with_(
        "config-transaction-status", {"b64json": {"ok": True, "state": "pending", "transaction_id": "t1"}}))),
    ("schedule missing", "POST", "/haproxy/geoip/schedule", j({}, replies=BASE)),
    ("schedule bad", "POST", "/haproxy/geoip/schedule", j({"schedule": 5})),
    ("schedule ok", "POST", "/haproxy/geoip/schedule", j({"schedule": " Daily "})),
    ("audit events", "GET", "/api/audit/events"),
    ("audit events filters", "GET", "/api/audit/events?range=all&action=geoip.countries&result=failure&limit=2&offset=1"),
    ("audit events bad", "GET", "/api/audit/events?range=bogus&result=nope&limit=x&offset=-5&actor=" + "a" * 200),
    ("audit filters", "GET", "/api/audit/filters"),
    ("audit status", "GET", "/api/audit/status"),
]
