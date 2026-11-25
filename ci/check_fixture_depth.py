#!/usr/bin/env python3
"""Require >=3 valid and >=3 invalid fixture cases for every changed rule.

Mirrors the count part of the harness fixture-depth gate (issue #410). Rules
listed in ``ci/fixture-depth-grandfather.txt`` are exempt; every other changed
rule needs a mirrored fixture with at least MIN_CASES valid and invalid cases.

The id is candidate-controlled, so with a base revision a rule is exempt only
when the same rule path existed at the base with that same grandfathered id.
A new rule file, or an existing file whose id was changed to a grandfathered
one, gets no exemption. With explicit paths and no base the exemption keys on
the candidate id alone (local use only; CI always passes a base).
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate_changed_rules as gate  # pylint: disable=wrong-import-position

MIN_CASES = 3
GRANDFATHER = Path(__file__).resolve().parent / "fixture-depth-grandfather.txt"


def load_grandfather(path: Path = GRANDFATHER) -> frozenset[str]:
    ids = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if text and not text.startswith("#"):
            ids.add(text)
    return frozenset(ids)


def _load(path: Path) -> dict | None:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    return document if isinstance(document, dict) else None


def _rule_id(document: dict | None, rule: PurePosixPath) -> str:
    return str(document.get("id")) if document and document.get("id") else rule.stem


def _base_rule_id(root: Path, base: str, rule: PurePosixPath) -> str | None:
    """Id of the rule at the base revision, or None when absent or unreadable."""
    data = gate._base_blob(root, base, rule)  # pylint: disable=protected-access
    if data is None:
        return None
    try:
        document = yaml.safe_load(data)
    except yaml.YAMLError:
        return None
    return _rule_id(document if isinstance(document, dict) else None, rule)


def depth_failure(
    root: Path,
    rule: PurePosixPath,
    grandfathered: frozenset[str],
    base: str | None = None,
) -> str | None:
    """Return the failure reason for one rule, or None when it passes."""
    rule_id = _rule_id(_load(root / rule), rule)
    if rule_id in grandfathered and (
        base is None or _base_rule_id(root, base, rule) == rule_id
    ):
        return None
    fixture_path = root / gate.mirrored_fixture(rule)
    if not fixture_path.is_file():
        return f"no test file {gate.mirrored_fixture(rule)}"
    fixture = _load(fixture_path)
    if fixture is None:
        return f"test file {gate.mirrored_fixture(rule)} is not a readable mapping"
    reasons = []
    for key in ("valid", "invalid"):
        cases = fixture.get(key)
        count = len(cases) if isinstance(cases, list) else 0
        if count < MIN_CASES:
            reasons.append(f"needs >={MIN_CASES} {key} cases, has {count}")
    return "; ".join(reasons) or None


def check(
    root: Path,
    paths: Sequence[str],
    grandfathered: frozenset[str],
    base: str | None = None,
) -> list[str]:
    failures = []
    for rule in gate.changed_rule_paths(root, paths):
        if not (root / rule).is_file():
            continue  # removed rule
        reason = depth_failure(root, rule, grandfathered, base)
        if reason:
            failures.append(f"{rule}: {reason}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=os.environ.get("BASE_SHA"))
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--grandfather", type=Path, default=GRANDFATHER)
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args()
    if not args.paths and not args.base:
        parser.error("--base or explicit changed paths are required")
    try:
        root = args.root.resolve(strict=True)
        paths = args.paths or gate.changed_paths(root, args.base)
        failures = check(root, paths, load_grandfather(args.grandfather), args.base)
    except (OSError, gate.ValidationError) as error:
        print(f"check-fixture-depth: {error}", file=sys.stderr)
        return 1
    if failures:
        print("check-fixture-depth: fixture depth below minimum:", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("check-fixture-depth: changed rules meet fixture depth")
    return 0


if __name__ == "__main__":
    sys.exit(main())
