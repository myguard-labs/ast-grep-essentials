#!/usr/bin/env python3
"""Check that every non-PowerShell rule and declared global util loads on the oldest ast-grep.

Consumers scan with a host ast-grep that can be older than the version the
rules are authored with. ast-grep aborts the whole scan when a single rule
fails to load, so this gate stages every non-PowerShell rule into an isolated
config (plus each directory named under ``utilDirs`` in the root
``sgconfig.yml``, minus PowerShell utils), scans an empty tree with the pinned
binary and fails on any non-zero exit. A declared ``utilDirs`` entry that does
not exist, or is not a directory, fails the gate by name, as the engine does.
The tree holds no source files so an error-severity rule cannot match and exit
non-zero for a reason other than a load or parse error. PowerShell rules need
a built grammar and live in their own config, so they are excluded.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

import yaml

MIN_VERSION = "0.45.2"
LANGUAGE = re.compile(r"(?m)^language:\s*['\"]?([A-Za-z0-9_+-]+)")
TIMEOUT = 600
RULE_SUFFIXES = ("*.yml", "*.yaml")
SGCONFIG = "sgconfig.yml"
UTIL_DIRS_KEY = "utilDirs"
# Names the staged layout already uses; a util directory may not shadow them.
RESERVED_STAGE_NAMES = frozenset({"rules", "tree", SGCONFIG})


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


def _rule_files(directory: Path) -> set[Path]:
    """Return every ``.yml`` and ``.yaml`` file under ``directory``.

    ast-grep loads both suffixes from a ruleDir or utilDir, so both are gated;
    the set removes any overlap between the globs.
    """
    return {
        path
        for pattern in RULE_SUFFIXES
        for path in directory.rglob(pattern)
        if path.is_file()
    }


def collect_rules(rules_dir: Path) -> list[Path]:
    """Return the non-PowerShell rule files under ``rules_dir``, sorted."""
    return sorted(
        path
        for path in _rule_files(rules_dir)
        if not is_powershell(path.relative_to(rules_dir), path)
    )


def _contained(root: Path, entry: str) -> str:
    """Return ``entry`` when it names a directory strictly inside ``root``."""
    relative = Path(entry)
    if (
        not entry
        or not relative.parts
        or relative.is_absolute()
        or ".." in relative.parts
        or relative.parts[0] in RESERVED_STAGE_NAMES
    ):
        raise GateError(
            f"utilDirs entry escapes the repository or is reserved: {entry!r}"
        )
    target = (root / relative).resolve()
    if target == root or not target.is_relative_to(root):
        raise GateError(f"utilDirs entry escapes the repository: {entry!r}")
    return entry


def declared_util_dirs(root: Path) -> list[str]:
    """Return the ``utilDirs`` entries of ``root``'s sgconfig.yml, in order.

    The file is parsed with PyYAML under the BaseLoader, so every scalar stays a
    string and block lists, flow lists, quoted entries and comments read alike.
    A missing file, an empty file or a missing key declares nothing. Any other
    shape (a scalar or mapping, a nested list, an empty or non-string entry) is
    refused rather than guessed, so no util directory is silently left unchecked.
    """
    root = root.resolve()
    config = root / SGCONFIG
    if not config.is_file():
        return []
    try:
        data = yaml.load(config.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    except yaml.YAMLError as error:
        raise GateError(f"cannot parse {SGCONFIG}: {error}") from error
    if data is None:
        return []
    if not isinstance(data, dict):
        raise GateError(f"{SGCONFIG} must be a mapping at its top level")
    if UTIL_DIRS_KEY not in data:
        return []
    value = data[UTIL_DIRS_KEY]
    if not isinstance(value, list):
        raise GateError(f"{UTIL_DIRS_KEY} must be a list of strings in {SGCONFIG}")
    entries: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise GateError(
                f"{UTIL_DIRS_KEY} entries must be non-empty strings in {SGCONFIG}: "
                f"{item!r}"
            )
        entries.append(_contained(root, item))
    return entries


def collect_utils(root: Path, entries: Sequence[str]) -> list[tuple[Path, Path]]:
    """Return ``(staged, source)`` pairs for the non-PowerShell utils in ``entries``.

    ``staged`` is relative to the staging target and keeps the declared
    directory name, so the staged ``utilDirs`` entries resolve unchanged.
    """
    pairs: list[tuple[Path, Path]] = []
    for entry in entries:
        directory = root / entry
        for path in _rule_files(directory):
            relative = path.relative_to(directory)
            if not is_powershell(relative, path):
                pairs.append((Path(entry) / relative, path))
    return sorted(pairs)


def stage(
    rules_dir: Path,
    rules: Sequence[Path],
    target: Path,
    utils: Sequence[tuple[Path, Path]] = (),
    util_dirs: Sequence[str] = (),
) -> Path:
    """Copy ``rules``, ``utils`` and an empty source tree into ``target``.

    ``utils`` holds ``(staged, source)`` pairs with ``staged`` relative to
    ``target``. Every name in ``util_dirs`` is created under ``target`` and
    declared as ``utilDirs``. Returns the staged config path.
    """
    for rule in rules:
        destination = target / "rules" / rule.relative_to(rules_dir)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(rule, destination)
    (target / "tree").mkdir()
    for entry in util_dirs:
        (target / entry).mkdir(parents=True, exist_ok=True)
    for staged, source in utils:
        destination = target / staged
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    config = target / SGCONFIG
    text = "ruleDirs:\n  - rules\n"
    if util_dirs:
        # json.dumps yields a double-quoted scalar, which is valid YAML, so a
        # name such as "odd #dir" or "a: b" keeps its exact text.
        text += f"{UTIL_DIRS_KEY}:\n" + "".join(
            f"  - {json.dumps(entry)}\n" for entry in util_dirs
        )
    config.write_text(text, encoding="utf-8")
    return config


def check(root: Path, ast_grep: Sequence[str | Path]) -> int:
    """Load every non-PowerShell rule; return how many rules were loaded.

    Raises GateError when a declared utilDir is missing or not a directory.
    """
    rules_dir = root / "rules"
    if not rules_dir.is_dir():
        raise GateError(f"no rules directory at {rules_dir}")
    rules = collect_rules(rules_dir)
    if not rules:
        raise GateError("no non-PowerShell rules found; refusing to pass")
    declared = declared_util_dirs(root)
    for entry in declared:
        if not (root / entry).is_dir():
            raise GateError(
                f"declared utilDir {entry!r} in {SGCONFIG} does not exist "
                "or is not a directory"
            )
    utils = collect_utils(root, declared)
    with tempfile.TemporaryDirectory(prefix="host-loadability-") as scratch:
        version = _run([*ast_grep, "--version"], Path(scratch))
        if version.returncode:
            raise GateError(
                f"ast-grep --version exited {version.returncode}: {_tail(version)}"
            )
        if version.stdout.strip().split()[-1:] != [MIN_VERSION]:
            raise GateError(f"expected ast-grep {MIN_VERSION}, got: {_tail(version)}")
        target = Path(scratch)
        config = stage(rules_dir, rules, target, utils, declared)
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
