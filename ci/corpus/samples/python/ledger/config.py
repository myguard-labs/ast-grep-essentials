"""Settings loaded from a YAML file with environment overrides."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml


class ConfigError(Exception):
    """A settings file that cannot be used as given."""


@dataclass(frozen=True)
class Settings:
    database: Path
    spool: Path
    api_token: str
    retries: int
    request_timeout: float

    def validate(self) -> None:
        if self.retries < 0:
            raise ConfigError("retries must not be negative")
        if self.request_timeout <= 0:
            raise ConfigError("request_timeout must be positive")
        if not self.api_token:
            raise ConfigError("api_token must not be empty")


def _as_path(raw: object, field: str) -> Path:
    if not isinstance(raw, str) or not raw:
        raise ConfigError(f"{field} must be a non-empty string")
    return Path(raw).expanduser()


def load(path: Path) -> Settings:
    """Read ``path`` and overlay the LEDGER_* environment variables."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ConfigError(f"cannot read {path}: {error}") from error

    parsed = yaml.safe_load(text) or {}
    if not isinstance(parsed, dict):
        raise ConfigError(f"{path} must contain a mapping")

    token = os.environ.get("LEDGER_API_TOKEN", parsed.get("api_token", ""))
    override = os.environ.get("LEDGER_RETRIES")
    raw_retries = override if override is not None else parsed.get("retries", 3)
    try:
        retries = int(str(raw_retries))
    except ValueError as error:
        raise ConfigError(f"retries is not an integer: {error}") from error

    settings = Settings(
        database=_as_path(parsed.get("database"), "database"),
        spool=_as_path(parsed.get("spool"), "spool"),
        api_token=str(token),
        retries=retries,
        request_timeout=float(parsed.get("request_timeout", 10.0)),
    )
    settings.validate()
    return settings


def describe(settings: Settings) -> dict[str, object]:
    """A log-safe view: every field except the token."""
    return {
        "database": str(settings.database),
        "spool": str(settings.spool),
        "retries": settings.retries,
        "request_timeout": settings.request_timeout,
    }
