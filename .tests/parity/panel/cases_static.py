"""Static files, the i18n catalogue script and the language switch."""

EXTRA_HEADERS = ("etag", "content-encoding", "last-modified")


def form(**kw):
    kw.setdefault("csrf_token", "CSRF")
    return {"form": kw}


STEPS = [
    ("csrf", "GET", "/system/alerts"),
    ("messages ru", "GET", "/i18n/messages.js?lang=ru"),
    ("messages en", "GET", "/i18n/messages.js?lang=en&v=x"),
    ("messages bogus", "GET", "/i18n/messages.js?lang=zz"),
    ("messages none", "GET", "/i18n/messages.js"),
    ("messages gzip", "GET", "/i18n/messages.js?lang=ru", {"headers": {"Accept-Encoding": "gzip, br"}}),
    ("messages etag", "GET", "/i18n/messages.js?lang=ru", {"headers": {"If-None-Match": "*"}}),
    ("static js", "GET", "/static/js/acme_email.js"),
    ("static css v", "GET", "/static/css/styles.css?v=abc"),
    ("static missing", "GET", "/static/js/nope.js"),
    ("static traversal", "GET", "/static/../__init__.py"),
    ("static dir", "GET", "/static/js/"),
    ("language ru", "POST", "/language", form(language="ru", next="/haproxy/sites")),
    ("language bad", "POST", "/language", form(language="xx")),
    ("language external next", "POST", "/language", form(language="en", next="https://evil.example/")),
    ("language scheme-relative", "POST", "/language", form(language="en", next="//evil.example/x")),
    ("language no next", "POST", "/language", form(language="EN")),
    ("page after switch", "GET", "/system/alerts"),
]


def normalize_body(label, body):
    if label == "messages gzip":
        return "GZIP"  # gzip bytes differ by compressor and mtime; the plain body is compared above
    return body
