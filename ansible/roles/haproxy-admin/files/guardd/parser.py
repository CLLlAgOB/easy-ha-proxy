"""Access-log parsing, path/query/UA classification, and protocol anomaly checks."""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, List, Optional, Tuple
from urllib.parse import unquote, unquote_plus, urlparse

if TYPE_CHECKING:
    from .tracking import IpActivity

from . import constants as _constants
from .constants import (
    ASSET_SUFFIXES,
    MAX_HOST_LENGTH,
    MAX_MATCHED_SEGMENTS,
    MAX_PATH_LENGTH,
    MAX_USER_AGENT_LENGTH,
    _ACCESS_HEAD,
    _ACCESS_TAIL,
    _BAD_REQUEST_TAIL,
    _BAN_REASON_FIELD,
    _CONTROL_CHARS,
    _HOST_FIELD,
    _ID_FIELD,
    _MULTI_SLASH,
    _SYSLOG_PREFIX,
    _UA_FIELD,
    authenticated_username,
    category_is_decisive,
    classify_query,
    parse_stamp,
)

def refusal_is_a_shield(request: ParsedRequest, activity: "IpActivity") -> bool:
    """Does the gateway's refusal make scoring this request pointless?

    Only while the address has never been past the gateway on anything.

    "It reaches nothing, so a ban changes nothing" was the original
    reasoning, and on a gateway serving more than one site it is false. The
    refusals are per host -- one rule for each gated site, plus geography
    over a named set of domains -- so an address turned away from one host
    is free to keep walking the others, and the Authelia host cannot be
    gated at all, because the login page has to be reachable to log in.

    Measured on a live gateway: of 173 addresses refused that day, 17 were
    answered on something else. One of them was collecting a 200 for
    /b374k-2.6.php, which is a webshell name. Every one of them sat at score
    0, state NORMAL, recommended action "nothing", and went on probing every
    hour for days.

    A ban is also not the same instrument as a 451. It is applied by
    tcp-request connection reject, across every host and every port, before
    the TLS handshake -- strictly more coverage, and far cheaper, than the
    per-site rule that refused the request.
    """

    return request.denied_by_gateway and not activity.reached_backend


DETECTION_PROFILES = {
    "web": {"methods": ["GET", "HEAD", "POST"], "routes": []},
    "api": {"methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], "routes": ["/api"]},
    "webdav": {"methods": ["PROPFIND", "PROPPATCH", "REPORT", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"],
               "routes": ["/remote.php/dav", "/ocs/v2.php", "/.well-known"]},
    "1c": {"methods": ["GET", "POST", "OPTIONS"], "routes": []},
    "docker": {"methods": ["GET", "POST", "DELETE"], "routes": ["/v1.47", "/containers", "/images", "/info", "/version", "/v2"]},
}


# No nested quantifiers, arbitrary user regexes or request bodies. Values are
# examined transiently by the log parser and only these names survive it.
OBSERVATION_QUERIES = {
    "observe:sql-injection": re.compile(r"\bunion\s+(?:all\s+)?select\b|['\"]\s*(?:or|and)\s+['\"\d]+\s*=|\b(?:sleep|benchmark)\s*\(", re.I),
    "observe:script-injection": re.compile(r"<\s*script\b|<[^>\r\n]{0,160}\bon(?:error|load)\s*=|javascript\s*:", re.I),
}
SERVICE_API_PROBE = re.compile(
    r"^/(?:v[0-9]{1,2}(?:\.[0-9]{1,2})?/(?:containers/(?:json|[^/]{1,80}/json)|images/json|info|version)"
    r"|v2/_catalog|latest/meta-data(?:/[^?]*)?|computemetadata/v1(?:/[^?]*)?"
    r"|actuator/(?:env|heapdump|configprops|mappings))(?:/|$)", re.I)

# Modern desktop/mobile browsers have not spoken HTTP/1.0 for over a decade;
# claiming a current Chrome/Firefox/Edge/Safari UA over HTTP/1.0 is a strong
# fingerprint of a naive HTTP client masquerading as a browser.
_MODERN_BROWSER_UA = re.compile(
    r"(?:Chrome|Firefox|Edg)/(?:[89]\d|[1-9]\d{2,})\."
    r"|Version/(?:1[4-9]|[2-9]\d)\.\d+[^/\r\n]{0,60}Safari/"
)
_ALWAYS_UNUSUAL_METHODS = frozenset({"TRACE", "TRACK", "CONNECT", "DEBUG"})
_WEBDAV_METHODS = frozenset(DETECTION_PROFILES["webdav"]["methods"])


def is_proto_ua_mismatch(protocol: str, user_agent: str) -> bool:
    return protocol == "HTTP/1.0" and bool(user_agent) and bool(_MODERN_BROWSER_UA.search(user_agent))


def is_unusual_method_probe(method: str, profile: str) -> bool:
    if not method:
        return False
    if method in _ALWAYS_UNUSUAL_METHODS:
        return True
    if method in _WEBDAV_METHODS:
        allowed = DETECTION_PROFILES.get(profile, DETECTION_PROFILES["web"])["methods"]
        return method not in allowed
    return False


def observation_flags(uri: str) -> Tuple[str, ...]:
    """Privacy boundary: return identifiers, never an input value."""
    text = uri[:4096]
    flags = []
    query = text.partition("?")[2].partition("#")[0][:2048]
    for part in query.split("&", 64) if query else ():
        value = part.partition("=")[2] if "=" in part else part
        for _ in range(2):
            value = unquote_plus(value)
        for name, pattern in OBSERVATION_QUERIES.items():
            if name not in flags and pattern.search(value):
                flags.append(name)
    raw_path = text.partition("?")[0].partition("#")[0]
    # Absolute HTTP/2 request targets are common in HAProxy's log format.
    path = raw_path
    if path.startswith(("http://", "https://")):
        with contextlib.suppress(ValueError):
            path = urlparse(path).path
    if SERVICE_API_PROBE.search(path[:200]):
        flags.append("observe:service-api-probe")
    if "%25" in raw_path.lower():
        first = normalize_path(raw_path)
        second = normalize_path(unquote(raw_path))
        if second != first and category_is_decisive(classify_path(second)):
            flags.append("observe:encoded-sensitive-path")
    return tuple(flags)


LOGGED_AGENT_OTHER = re.compile(r"[^a-z0-9./;:_-]")


# The admin panel's own backend. On a quiet gateway the page watching the
# traffic is most of it -- the panel polls -- so it is left out unless asked.
LIVE_ADMIN_BACKEND = "be_admin"
# The panel's own traffic: its pages, and the HAProxy statistics page it
# shows in a frame and refreshes every 30 seconds.
LIVE_ADMIN_BACKENDS: Tuple[str, ...] = (LIVE_ADMIN_BACKEND, "be_stats")


# Index of each field in a live record.
(L_TS, L_IP, L_STATUS, L_HOST, L_PATH, L_METHOD, L_BACKEND, L_BYTES,
 L_DURATION, L_TERM, L_REASON, L_REFUSAL, L_RESPONSE, L_TIMES, L_REQUEST_ID,
 L_AGENT, L_AUTH_USER) = range(17)


def live_refusal(status: int, backend: str, term: str, ban_reason: str) -> str:
    """Why the gateway itself turned this request away, or "".

    The codes are the gateway's own: a server never chose them, which is
    what <NOSRV> in the backend field says. An application's own 401 or 403
    is not a refusal by the gateway.
    """
    if status == 423 or ban_reason:
        return "banned"
    if status == 429:
        return "rate-limited"
    if not backend.endswith("/<NOSRV>"):
        return ""
    return {451: "geo", 401: "zero-trust", 403: "denied", 400: "invalid-request"}.get(
        status, "refused" if term.startswith("PR") else ""
    )


# ---------------------------------------------------------------------------
# Request sanitising
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParsedRequest:
    """One access-log line, reduced to what is safe to keep."""

    client_ip: str
    status: int
    frontend: str
    backend: str
    method: str
    path: str
    host: str
    bad_request: bool = False
    # The NAME of the injection rule the query matched, never the query. The
    # value is dropped for the same reason normalize_path drops it: the
    # access log really does contain ?token=..., and a security database is
    # the last place that belongs.
    query_flag: str = ""
    path_flag: str = ""
    observation_flags: Tuple[str, ...] = ()
    # Filled in only when the request log is on. They cost a little more
    # parsing per line, so they stay optional rather than always paid for.
    ts: int = 0
    request_id: str = ""
    bytes_out: int = 0
    duration_ms: int = 0
    # %Tr: from sending the request to the server to its response headers;
    # -1 when there was none. The figure HAProxy averages as rtime.
    response_ms: int = -1
    # The five timers as logged (%TR/%Tw/%Tc/%Tr/%Ta), for the live page's
    # details of one request.
    times: str = ""
    # HAProxy's termination state and the ban fragment's reason, for the live
    # activity page: what the gateway did with the request, and why.
    term: str = ""
    ban_reason: str = ""
    # Present when the template logs it (log_user_agent); "" on older lines.
    user_agent: str = ""
    authenticated_user: str = ""
    # HTTP version from the request line ("HTTP/1.0", "HTTP/1.1", "HTTP/2.0").
    protocol: str = ""

    # A refusal counts as "already handled" only when it was about who the
    # client is, not about what it sent. 451 is a geo block, 401 a failed IP
    # authorisation on a zero-trust site and 403 a per-site address rule: in
    # all three the address can reach nothing, so scoring it further changes
    # nothing.
    IDENTITY_REFUSALS = (401, 403, 451)

    @property
    def denied_by_gateway(self) -> bool:
        """HAProxy refused this one for who the client is, not what it sent.

        400 used to be in this set, and it is the opposite case: the gateway
        rejected one malformed request and carried on serving that same
        address everything else it asked for. Treating it as a shield threw
        away most of the evidence -- on a live gateway 77% of all security
        events scored nothing, including 85% of scanner findings, because a
        scanner's requests are malformed by nature. One address sent 134
        malformed requests while being served 5935 normal ones and scored
        zero for every one of them.
        """

        if self.status not in self.IDENTITY_REFUSALS:
            return False
        # 401 is also what an application answers a wrong password with, and
        # that is evidence, not a shield. Only the gateway's own 401 -- no
        # server was chosen -- is the zero-trust refusal.
        if self.status == 401:
            return self.backend.endswith("/<NOSRV>")
        return True


def normalize_path(value: str) -> str:
    """Reduce a request target to a comparable path, dropping the query.

    The query string is removed before anything is stored: the access log
    genuinely contains things like `?token=...`, and a security database is the
    last place a password-reset token should end up.
    """

    if not value:
        return "/"
    text = value.strip()
    # An HTTP/2 request line carries the absolute form, so the host travels
    # inside the target rather than in a captured header.
    if text.startswith(("http://", "https://")):
        text = urlparse(text).path or "/"
    for separator in ("?", "#"):
        index = text.find(separator)
        if index >= 0:
            text = text[:index]
    with contextlib.suppress(Exception):
        # One decoding pass only: decoding repeatedly invents paths that were
        # never requested.
        text = unquote(text)
    text = _CONTROL_CHARS.sub("", text)
    text = _MULTI_SLASH.sub("/", text)
    if not text.startswith("/"):
        text = "/" + text
    segments: List[str] = []
    for segment in text.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    normalized = "/" + "/".join(segments)
    return normalized[:MAX_PATH_LENGTH]


def is_asset(path: str) -> bool:
    """A missing stylesheet is a deploy artefact, not reconnaissance."""

    lowered = path.lower()
    return lowered.endswith(ASSET_SUFFIXES)


def classify_raw_path(uri: str) -> str:
    """Recognise a traversal to a sensitive target before canonicalisation.

    Only the rule name survives. Ordinary parent segments are not evidence
    of an attack; require repeated traversal and a specific sensitive target.
    """
    text = (uri or "").split("?", 1)[0].split("#", 1)[0][:2048]
    lower = text.lower()
    if ".." not in text and "%2e" not in lower and "%25" not in lower:
        return ""
    if text.startswith(("http://", "https://")):
        with contextlib.suppress(ValueError):
            text = urlparse(text).path
    for _ in range(2):
        text = unquote(text).replace("\\", "/").lower()
        if text.split("/").count("..") >= 2 and re.search(
            r"/(?:etc/(?:passwd|shadow)|proc/(?:self|1)/environ|windows/(?:win|system)\.ini)(?:/|$)", text
        ):
            return "path-traversal"
    return ""


# The gateway's own sign-in surface. These are paths this product serves in
# order to authenticate somebody, so a request to one is the product working,
# never reconnaissance against it.
#
# This exists because of a real ban. A visitor completing a second factor
# with a hardware key fetches /api/secondfactor/webauthn/credentials; the
# segment rule "credentials" -> secrets matched the last word, secrets is a
# decisive category, and one request from a legitimate user was worth an
# instant ban. Every other decisive match on this gateway over thirty days
# was genuine -- /.env across ninety-one addresses, /.git/config across a
# hundred and two -- so the rule stays and the sign-in paths are spared
# instead. Weakening "credentials" would have cost the eight addresses
# caught fetching /.aws/credentials to save one endpoint.
AUTHENTICATION_PATHS: Tuple[str, ...] = (
    "/api/firstfactor",
    "/api/secondfactor/",
    "/api/user/info",
    "/api/state",
    "/api/verify",
    "/api/logout",
    "/api/reset-password/",
    "/api/checks/",
)


def is_authentication_endpoint(path: str) -> bool:
    """Whether this is one of the sign-in paths the gateway serves itself.

    Matched by prefix and deliberately not as a blanket /api/: probes for
    /api/.env are real and frequent, and must go on being caught.
    """

    lowered = path.lower()
    return any(lowered == prefix.rstrip("/") or lowered.startswith(prefix.rstrip("/") + "/")
               for prefix in AUTHENTICATION_PATHS)


def _prefix_category(segment: str) -> str:
    lowered = segment.lower()
    for prefix, category in _constants.SCANNER_PREFIXES:
        if lowered.startswith(prefix):
            return category
    return ""


def classify_path(path: str) -> str:
    """Return the scanner category for a normalised path, or "".

    Every segment is checked, not only the first. The most common attack in
    the mined traffic -- CVE-2017-9841, the phpunit eval-stdin.php remote
    execution -- arrives as /laravel/vendor/phpunit/... and /lib/phpunit/...
    far more often than as /vendor/phpunit/..., and first-segment matching
    saw none of those. A path has few segments and the scan is bounded, so
    the cost of running this on every logged line is unchanged in practice.
    """

    if not path or path == "/":
        return ""
    exact = _constants.SCANNER_PATHS.get(path)
    if exact:
        return exact
    # The most confident match wins, not the leftmost. /vendor/phpunit/...
    # and /lib/phpunit/... are the same attack, and taking whichever segment
    # came first gave one of them "dependency" and the other "rce-probe".
    probable = ""
    for segment in path.split("/", MAX_MATCHED_SEGMENTS + 1)[1:]:
        if not segment:
            continue
        category = _constants.SCANNER_SEGMENTS.get(segment) or _constants.SCANNER_SEGMENTS.get(
            segment.lower()
        ) or _prefix_category(segment)
        if not category:
            continue
        if category_is_decisive(category):
            return category
        probable = probable or category
    # Asset and sign-in exceptions apply to ambiguous technology names, not
    # to sensitive files hidden under those routes or behind an extension.
    return "" if is_asset(path) or is_authentication_endpoint(path) else probable


def extract_host(value: str) -> str:
    """Host from an absolute-form target, empty when the line has none.

    HTTP/2 requests log the absolute URI, so the host is available; HTTP/1.1
    requests usually log the origin form and simply do not carry it.
    """

    if not value.startswith(("http://", "https://")):
        return ""
    host = (urlparse(value).hostname or "").strip().lower()
    return _CONTROL_CHARS.sub("", host)[:MAX_HOST_LENGTH]


def parse_access_line(line: str) -> Optional[ParsedRequest]:
    """Parse one HAProxy access-log line, or None if it is not one.

    HAProxy also writes health-check and warning lines to the same file; those
    are not access records and must not be mistaken for traffic.
    """

    if not line:
        return None
    text = _SYSLOG_PREFIX.sub("", line.strip())
    head = _ACCESS_HEAD.match(text)
    if head is None:
        return None

    client = head.group("client")
    if client.startswith("["):
        client = client[1:-1]
    status_text = head.group("status")
    status = 0 if status_text == "-" else int(status_text)

    remainder = text[head.end():]
    bytes_text = head.group("bytes")
    bytes_out = 0 if bytes_text == "-" else int(bytes_text)
    stamp = parse_stamp(head.group("stamp"))
    identifier = _ID_FIELD.search(remainder)
    request_id = identifier.group("id") if identifier else ""
    term = remainder.split(None, 1)[0] if remainder else ""
    ban_reason = ""
    if 'ban_reason="' in remainder:
        found = _BAN_REASON_FIELD.search(remainder)
        ban_reason = found.group("reason")[:160] if found else ""

    tail = _ACCESS_TAIL.search(remainder)
    if tail is None:
        if _BAD_REQUEST_TAIL.search(remainder):
            return ParsedRequest(
                client_ip=client,
                status=status,
                frontend=head.group("frontend"),
                backend=head.group("backend"),
                method="",
                path="",
                host="",
                bad_request=True,
                ts=stamp,
                request_id=request_id,
                bytes_out=bytes_out,
                term=term,
                ban_reason=ban_reason,
            )
        return None

    uri = tail.group("uri")
    # Only the part before the request line: the URI is the client's to write.
    agent_field = _UA_FIELD.search(remainder, 0, tail.start())
    user_agent = agent_field.group("ua")[:MAX_USER_AGENT_LENGTH] if agent_field else ""
    if user_agent == "-":
        user_agent = ""
    # The Host header, when the frontend captures it, is a labelled field; the
    # absolute-form URI is the fallback and is rare in practice.
    host_field = _HOST_FIELD.search(remainder)
    host = host_field.group("host") if host_field else extract_host(uri)
    if host in ("-", "{}"):
        host = ""
    return ParsedRequest(
        client_ip=client,
        status=status,
        frontend=head.group("frontend"),
        backend=head.group("backend"),
        method=tail.group("method"),
        path=normalize_path(uri),
        host=extract_host(uri) if not host else host[:MAX_HOST_LENGTH],
        query_flag=classify_query(uri),
        path_flag=classify_raw_path(uri),
        observation_flags=observation_flags(uri),
        ts=stamp,
        request_id=request_id,
        bytes_out=bytes_out,
        duration_ms=_total_time(head.group("times")),
        response_ms=_response_time(head.group("times")),
        times=head.group("times")[:40],
        term=term,
        ban_reason=ban_reason,
        user_agent=user_agent,
        authenticated_user=authenticated_username(remainder[:tail.start()]),
        protocol=tail.group("proto"),
    )


def _response_time(times: str) -> int:
    """The fourth field of %TR/%Tw/%Tc/%Tr/%Ta, or -1 when there was none.

    Not the total: that also holds the client downloading the body and a
    long poll waiting for news, which put a quiet site's median at eight
    seconds while its server answered in a fraction of one.
    """
    fields = (times or "").split("/")
    if len(fields) != 5:
        return -1
    try:
        return int(fields[3])
    except ValueError:
        return -1


def _total_time(times: str) -> int:
    """The last field of %TR/%Tw/%Tc/%Tr/%Tt is the total, or -1 when unknown."""
    tail = (times or "").rsplit("/", 1)[-1]
    try:
        value = int(tail)
    except ValueError:
        return 0
    return max(0, value)
