#!/usr/bin/env python3
"""Check that every non-PowerShell rule and global util loads on the oldest ast-grep.

Consumers scan with a host ast-grep that can be older than the version the
rules are authored with. ast-grep aborts the whole scan when a single rule
fails to load, so this gate stages every non-PowerShell rule into an isolated
config (plus the ``utils`` directory as ``utilDirs`` when present), scans an
empty tree with the pinned binary and fails on any non-zero exit. The tree holds no source files so an error-severity rule cannot match
and exit non-zero for a reason other than a load or parse error. PowerShell
rules need a built grammar and live in their own config, so they are excluded.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

MIN_VERSION = "0.45.2"
LANGUAGE = re.compile(r"(?m)^language:\s*['\"]?([A-Za-z0-9_+-]+)")
TIMEOUT = 600


class GateError(RuntimeError):
    """The host-loadability gate failed with a bounded reason."""


def _tail(result: subprocess.CompletedProcess[str]) -> str:
    output = (result.stderr + result.stdout).strip()
    return output[-1500:] or f"exit {result.returncode}"


def _run(command: Sequence[str | Path], cwd: Path) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [str(part) for part in command],
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise GateError(f"cannot run {command[0]}: {error}") from error


def is_powershell(relative: Path, path: Path) -> bool:
    if "powershell" in relative.parts:
        return True
    match = LANGUAGE.search(path.read_text(encoding="utf-8"))
    return match is not None and match.group(1).lower() == "powershell"


RULE_SUFFIXES = ("*.yml", "*.yaml")


def collect_rules(rules_dir: Path) -> list[Path]:
    """Return the non-PowerShell rule files under ``rules_dir``, sorted.

    ast-grep loads both ``.yml`` and ``.yaml`` rules from a ruleDir, so both
    suffixes are gated; the set removes any overlap between the globs.
    """
    candidates = {
        path
        for pattern in RULE_SUFFIXES
        for path in rules_dir.rglob(pattern)
        if path.is_file()
    }
    return sorted(
        path
        for path in candidates
        if not is_powershell(path.relative_to(rules_dir), path)
    )


UTILS_DIRNAME = "utils"


def stage(
    rules_dir: Path,
    rules: Sequence[Path],
    target: Path,
    utils_dir: Path | None = None,
) -> Path:
    """Copy ``rules`` and an empty source tree into ``target``; return config.

    When ``utils_dir`` is given it is copied to ``target/utils`` and declared
    as ``utilDirs`` so a global util that fails to load fails the gate too.
    """
    for rule in rules:
        destination = target / "rules" / rule.relative_to(rules_dir)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(rule, destination)
    (target / "tree").mkdir()
    config = target / "sgconfig.yml"
    text = "ruleDirs:\n  - rules\n"
    if utils_dir is not None:
        shutil.copytree(utils_dir, target / UTILS_DIRNAME)
        text += f"utilDirs:\n  - {UTILS_DIRNAME}\n"
    config.write_text(text, encoding="utf-8")
    return config


def check(root: Path, ast_grep: Sequence[str | Path]) -> int:
    """Load every non-PowerShell rule; return how many rules were loaded."""
    rules_dir = root / "rules"
    if not rules_dir.is_dir():
        raise GateError(f"no rules directory at {rules_dir}")
    rules = collect_rules(rules_dir)
    if not rules:
        raise GateError("no non-PowerShell rules found; refusing to pass")
    with tempfile.TemporaryDirectory(prefix="host-loadability-") as scratch:
        version = _run([*ast_grep, "--version"], Path(scratch))
        if version.returncode:
            raise GateError(
                f"ast-grep --version exited {version.returncode}: {_tail(version)}"
            )
        if version.stdout.strip().split()[-1:] != [MIN_VERSION]:
            raise GateError(f"expected ast-grep {MIN_VERSION}, got: {_tail(version)}")
        target = Path(scratch)
        utils_dir = root / UTILS_DIRNAME
        config = stage(
            rules_dir, rules, target, utils_dir if utils_dir.is_dir() else None
        )
        result = _run([*ast_grep, "scan", "-c", config, target / "tree"], cwd=target)
        if result.returncode:
            raise GateError(
                f"ast-grep {MIN_VERSION} failed to load the rules "
                f"(exit {result.returncode}): {_tail(result)}"
            )
    return len(rules)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--ast-grep",
        nargs="+",
        required=True,
        help=f"command that runs ast-grep {MIN_VERSION}",
    )
    args = parser.parse_args(argv)
    try:
        count = check(args.root.resolve(), args.ast_grep)
    except GateError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"ok: {count} non-PowerShell rules load on ast-grep {MIN_VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
