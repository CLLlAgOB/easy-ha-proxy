"""A site's backend tuning is checked when it is saved, not when HAProxy reads it.

balance, cookie_name, cookie_attrs, http_reuse, session_timeout,
http_keepalive_timeout, err_size, rate_size and backend_alpn go into
haproxy.cfg as they are, from a site or from site_defaults. Nothing checked
them: a value HAProxy could not read failed the apply with a message that did
not name the field, and a '#' ended the line there -- on the default-server
line, backend_alpn is followed by the backend certificate check.

Every site in the file is checked on every save, so a rule that refused a
value already in use would stop the operator saving anything. The accepted
values below include every value of these fields found on two production
gateways, and the other forms HAProxy documents.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = ROOT / "docker" / "app" / "haproxy_admin"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


validation = load("site_backend_tuning_validation", PACKAGE_ROOT / "validation.py")


def site(**fields):
    return {"name": "shop", "domain": "shop.example.com", "backend_ip": "192.0.2.10",
            "backend_port": 80, **fields}


def check_site(**fields):
    validation.validate_config_data("websites", {"sites": [site(**fields)]})


def check_defaults(**fields):
    validation.validate_config_data("vars", {"site_defaults": fields})


class WhatIsInUseStaysValid(unittest.TestCase):
    def test_the_values_found_on_production_gateways(self):
        check_site(
            balance="source", sticky="cookie", cookie_name="RDPWEB",
            cookie_attrs="insert nocache", http_reuse="safe", session_timeout="15h",
            http_keepalive_timeout="2m", prefer_last_server=True, err_limit=250,
        )
        check_defaults(
            balance="roundrobin", sticky="none", err_limit=20, err_window="20s",
            rate_window="20s", http_request_timeout="5s", conn_rate_window="10s",
        )

    def test_unset_and_empty_fields_are_left_to_the_defaults(self):
        check_site()
        for key in ("balance", "cookie_name", "cookie_attrs", "http_reuse",
                    "session_timeout", "http_keepalive_timeout", "err_size",
                    "rate_size", "backend_alpn"):
            with self.subTest(key=key):
                check_site(**{key: ""})
                check_site(**{key: None})


class EveryFormHAProxyTakesIsAccepted(unittest.TestCase):
    ACCEPTED = {
        "balance": [
            "roundrobin", "static-rr", "leastconn", "first", "source", "random",
            "random(2)", "uri", "uri whole", "url_param userid", "url_param userid check_post",
            "hdr(host)", "hdr(X-Forwarded-For)", "rdp-cookie", "rdp-cookie(mstshash)",
            "hash req.cookie(sid)",
        ],
        "cookie_attrs": [
            "insert", "rewrite", "prefix", "insert indirect nocache",
            "insert nocache httponly secure postonly preserve dynamic",
            "insert nocache domain .example.com maxidle 30m maxlife 8h attr SameSite=Lax",
        ],
        "cookie_name": ["SRV", "RDPWEB", "app_id-1.v2"],
        "http_reuse": ["never", "safe", "aggressive", "always"],
        "session_timeout": ["30s", "15m", "1h", "500ms", "2d", "100us", "30000", 30000, "0"],
        "http_keepalive_timeout": ["2m", "10s", 10000],
        "err_size": ["50k", "1m", "1g", "200000", 100000, "50K"],
        "rate_size": ["200k"],
        "backend_alpn": ["h2", "http/1.1", "h2,http/1.1"],
    }

    def test_each_form_passes_on_a_site_and_in_site_defaults(self):
        for key, values in self.ACCEPTED.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    check_site(**{key: value})
                    check_defaults(**{key: value})


class WhatHAProxyCannotReadIsRefusedByName(unittest.TestCase):
    REFUSED = {
        "balance": ["bogus", "source # no", "roundrobin;", "hdr(host x)", "Source",
                    "uri " + "a " * 8],
        "cookie_attrs": ["insert nocache # x", "insert bogus", "insert domain",
                         "attr Same Site", "insert \"quoted\""],
        "cookie_name": ["SRV id", "a#b", "x" * 65],
        "http_reuse": ["sometimes", "SAFE"],
        "session_timeout": ["15 hours", "1h30m", "-5s", "5 s", "1y"],
        "http_keepalive_timeout": ["2min"],
        "err_size": ["50kb", "0", "-1", "1.5m"],
        "rate_size": ["lots"],
        "backend_alpn": ["h2 #", "h2, http/1.1", "h2,http/1.1 verify none", "h2;http/1.1"],
    }

    def test_each_value_is_refused_naming_the_site_field(self):
        for key, values in self.REFUSED.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    with self.assertRaisesRegex(ValueError, rf"^sites\[0\]\.{key}: "):
                        check_site(**{key: value})

    def test_site_defaults_are_checked_too(self):
        # Every site inherits them through the template.
        for key, values in self.REFUSED.items():
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, rf"^site_defaults\.{key}: "):
                    check_defaults(**{key: values[0]})

    def test_one_bad_site_is_named_among_many(self):
        data = {"sites": [site(), site(name="b", domain="b.example.com", http_reuse="nope")]}
        with self.assertRaisesRegex(ValueError, r"^sites\[1\]\.http_reuse: "):
            validation.validate_config_data("websites", data)


class TheMessagesReadInRussian(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fake_flask = types.ModuleType("flask")
        fake_flask.Request = object
        fake_flask.current_app = types.SimpleNamespace(json=types.SimpleNamespace(dumps=json.dumps))
        fake_flask.g = types.SimpleNamespace(language="ru")
        fake_flask.has_request_context = lambda: False
        fake_flask.request = types.SimpleNamespace()
        with mock.patch.dict(sys.modules, {"flask": fake_flask}):
            cls.i18n = load("site_backend_tuning_i18n", PACKAGE_ROOT / "i18n.py")

    def test_every_new_refusal_is_translated(self):
        messages = []
        for key, values in WhatHAProxyCannotReadIsRefusedByName.REFUSED.items():
            for value in values:
                try:
                    check_site(**{key: value})
                except ValueError as exc:
                    messages.append(str(exc))
        self.assertTrue(messages)
        for message in messages:
            with self.subTest(message=message):
                translated = self.i18n.translate(message, "ru")
                self.assertNotEqual(translated, message)
                self.assertRegex(translated, "[а-яА-Я]")


if __name__ == "__main__":
    unittest.main()
