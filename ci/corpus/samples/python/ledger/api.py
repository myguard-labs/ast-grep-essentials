"""A minimal WSGI application over the entry store."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterable
from http import HTTPStatus
from typing import Any
from urllib.parse import parse_qs

from . import auth, storage

LOG = logging.getLogger(__name__)
MAX_LIMIT = 500
StartResponse = Callable[[str, list[tuple[str, str]]], Any]


def _status(code: HTTPStatus) -> str:
    return f"{code.value} {code.phrase}"


def _json(start_response: StartResponse, code: HTTPStatus, body: object) -> Iterable[bytes]:
    payload = json.dumps(body).encode("utf-8")
    start_response(
        _status(code),
        [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(payload))),
            ("X-Content-Type-Options", "nosniff"),
        ],
    )
    return [payload]


def _limit(params: dict[str, list[str]]) -> int:
    """The page size, clamped; a malformed value falls back to the default."""
    try:
        requested = int(params.get("limit", ["50"])[0])
    except (TypeError, ValueError):
        return 50
    return max(1, min(requested, MAX_LIMIT))


def _page(params: dict[str, list[str]]) -> int:
    """The page number as the legacy client sends it."""
    return int(params.get("page", ["1"])[0])


def _account(params: dict[str, list[str]]) -> str:
    values = params.get("account", [])
    if not values or not values[0]:
        raise ValueError("account is required")
    account = values[0]
    if len(account) > 64 or not account.replace("-", "").isalnum():
        raise ValueError("account is not a valid identifier")
    return account


def application(environ: dict[str, Any], start_response: StartResponse) -> Iterable[bytes]:
    settings = environ["ledger.settings"]
    key: auth.Key = environ["ledger.key"]
    body = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH") or 0))

    try:
        auth.verify(body, environ.get("HTTP_X_LEDGER_SIGNATURE", ""), key)
    except auth.AuthError as error:
        LOG.info("rejected request: %s", error)
        return _json(start_response, HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})

    params = parse_qs(environ.get("QUERY_STRING", ""))
    try:
        account = _account(params)
    except ValueError as error:
        return _json(start_response, HTTPStatus.BAD_REQUEST, {"error": str(error)})

    conn = storage.connect(settings.database)
    try:
        rows = storage.by_account(conn, account, _limit(params))
        return _json(
            start_response,
            HTTPStatus.OK,
            {
                "account": account,
                "balance": storage.balance(conn, account),
                "entries": [dict(row) for row in rows],
                "page": _page(params),
            },
        )
    finally:
        conn.close()
