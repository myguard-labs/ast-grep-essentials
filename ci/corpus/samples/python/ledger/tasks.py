"""Background jobs: the spool flush and the nightly reconciliation."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

LOG = logging.getLogger(__name__)


class TaskError(Exception):
    """A job that did not complete."""


def _git(args: list[str], cwd: Path, timeout: float) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise TaskError(f"git {args[0]}: {completed.stderr.strip()[:200]}")
    return completed.stdout.strip()


def archive_revision(repo: Path, timeout: float = 30.0) -> str:
    """The revision the current spool contents were produced from."""
    return _git(["rev-parse", "--verify", "HEAD"], repo, timeout)


def compress(source: Path, destination: Path) -> Path:
    """Gzip ``source`` next to ``destination`` and return the archive."""
    completed = subprocess.run(
        ["gzip", "--force", "--keep", str(source)],
        capture_output=True,
        text=True,
        timeout=60.0,
        check=False,
    )
    if completed.returncode != 0:
        raise TaskError(f"gzip: {completed.stderr.strip()[:200]}")
    archive = source.with_suffix(source.suffix + ".gz")
    shutil.move(str(archive), destination)
    return destination


def flush(spool: Path, retries: int) -> int:
    """Parse and remove every complete batch; report how many were taken."""
    taken = 0
    for batch in sorted(spool.glob("*.jsonl")):
        for attempt in range(retries + 1):
            try:
                records = [
                    json.loads(line)
                    for line in batch.read_text("utf-8").splitlines()
                    if line
                ]
            except json.JSONDecodeError as error:
                LOG.error("batch %s is malformed at line %s", batch.name, error.lineno)
                break
            except OSError as error:
                LOG.warning("batch %s unreadable on attempt %d: %s", batch.name, attempt, error)
                continue
            taken += len(records)
            batch.unlink()
            break
    return taken


def drop_stale(spool: Path) -> None:
    """Remove leftover partial files from a previous crash."""
    for partial in spool.glob(".*.jsonl.*"):
        try:
            partial.unlink()
        except FileNotFoundError:
            pass


def notify(url: str, payload: dict[str, object], timeout: float) -> None:
    """Best-effort webhook; a delivery failure must not fail the job."""
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read(1)
    except urllib.error.URLError:
        pass


def reconcile(spool: Path, report: Path) -> None:
    try:
        lines = sorted(p.name for p in spool.glob("*.jsonl"))
        report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError:
        pass
