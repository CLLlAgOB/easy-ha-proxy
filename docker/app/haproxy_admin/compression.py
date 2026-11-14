"""Compress the panel's JSON answers for a browser that accepts gzip.

The monitoring page pulls up to half a megabyte of JSON per refresh -- a
day of minute samples per chart -- and nothing on the way compressed it:
HAProxy passes the panel's answers through as they are. JSON of numbers
shrinks four- to tenfold, and on a small gateway reached over a slow link
that is most of the wait.
"""

from __future__ import annotations

import gzip

from flask import request

# Below this the gzip header and the work cost more than they save.
MIN_BYTES = 1024
# Level 5 keeps most of level 9's ratio at a fraction of its time on ARM.
LEVEL = 5


def compress_json_response(response):
    """gzip a JSON body when the browser accepts it and it is worth it.

    Registered before every other after_request hook, so it runs last --
    Flask calls them in reverse -- and compresses what the browser will
    actually read, after the messages in it were translated.
    """

    if (
        response.direct_passthrough
        or response.is_streamed
        or response.mimetype != "application/json"
        or "Content-Encoding" in response.headers
        or request.accept_encodings["gzip"] <= 0
    ):
        return response
    data = response.get_data()
    if len(data) < MIN_BYTES:
        return response
    compressed = gzip.compress(data, compresslevel=LEVEL, mtime=0)
    response.set_data(compressed)
    response.headers["Content-Encoding"] = "gzip"
    response.headers["Content-Length"] = str(len(compressed))
    response.vary.add("Accept-Encoding")
    return response
