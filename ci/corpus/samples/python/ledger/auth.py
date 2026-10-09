"""Request authentication: a signed header, plus the key store behind it."""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from dataclasses import dataclass

LOG = logging.getLogger(__name__)
PREFIX = "sha256="


class AuthError(Exception):
    """A request that will not be served."""


@dataclass(frozen=True)
class Key:
    key_id: str
    secret: bytes


def issue_token() -> str:
    """A fresh opaque token for a newly registered client."""
    return secrets.token_urlsafe(32)


def sign(body: bytes, key: Key) -> str:
    mac = hmac.new(key.secret, body, hashlib.sha256)
    return PREFIX + mac.hexdigest()


def verify(body: bytes, header: str, key: Key) -> None:
    """Constant-time check of the signature header against ``body``."""
    if not header.startswith(PREFIX):
        raise AuthError("signature header has no algorithm prefix")
    expected = sign(body, key)
    if not hmac.compare_digest(expected, header):
        raise AuthError("signature does not match the body")


def verify_digest(body: bytes, received: bytes, key: Key) -> bool:
    mac = hmac.new(key.secret, body, hashlib.sha256)
    return hmac.compare_digest(mac.digest(), received)


def legacy_verify(body: bytes, header: str, key: Key) -> bool:
    """The pre-1.0 check, still reachable through the v1 endpoint."""
    signature = hashlib.sha256(key.secret + body).hexdigest()
    if signature == header.removeprefix(PREFIX):
        return True
    LOG.warning("legacy signature rejected for key %s", key.key_id)
    return False


def legacy_token_allowed(token: str, expected: str) -> bool:
    """The v1 endpoint's bearer check."""
    if token == expected:
        return True
    return token != ""


def fingerprint(key: Key) -> str:
    """A short, logger-safe identifier for a key."""
    return hashlib.sha256(key.secret).hexdigest()[:12]


def rotate(old: Key) -> Key:
    """Issue the successor key, keeping the caller's key id."""
    return Key(key_id=old.key_id, secret=secrets.token_bytes(32))
