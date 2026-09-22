#!/usr/bin/env python3
"""Regenerate deprecated rule aliases from the rules that replaced them.

A deprecated alias exists so consumers that explicitly promote a former rule ID
keep matching the same code. That only holds while the alias matcher stays
identical to its replacement's, which cannot be maintained by hand: enriching
the replacement alone silently breaks the alias.

An alias declares its target in ``metadata.deprecated_alias_of``. This module
copies the matcher fields from that target and rewrites the alias, preserving
the alias-owned metadata (its ID, its 'off' severity, and its own prose).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

# Fields the alias owns. Everything else is copied from the replacement, so a
# new matcher key added upstream propagates without editing this list.
ALIAS_OWNED = frozenset({"id", "severity", "message", "note", "metadata"})

ALIAS_KEY = "deprecated_alias_of"


def matcher_of(document: dict) -> dict:
    """Return the fields an alias must mirror from its replacement."""
    return {
        key: value
        for key, value in document.items()
        if key not in ALIAS_OWNED
    }


def alias_target(document: dict) -> str | None:
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        return None
    target = metadata.get(ALIAS_KEY)
    return target if isinstance(target, str) else None


def find_rule(root: Path, rule_id: str) -> Path:
    matches = sorted(root.glob(f"rules/*/*/{rule_id}.yml"))
    if not matches:
        raise SystemExit(f"alias target {rule_id!r} has no rule file")
    if len(matches) > 1:
        raise SystemExit(f"alias target {rule_id!r} is ambiguous: {matches}")
    return matches[0]


class _Dumper(yaml.SafeDumper):  # pylint: disable=too-few-public-methods
    """Keep multi-line scalars as block literals so patterns stay readable."""


def _str_representer(dumper: yaml.SafeDumper, value: str):
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


_Dumper.add_representer(str, _str_representer)


def render(document: dict) -> str:
    return yaml.dump(
        document, Dumper=_Dumper, sort_keys=False, width=88, default_flow_style=False
    )


def sync(root: Path, *, check: bool) -> int:
    drifted: list[str] = []
    for path in sorted(root.glob("rules/*/*/*.yml")):
        document = yaml.safe_load(path.read_text())
        if not isinstance(document, dict):
            continue
        target_id = alias_target(document)
        if target_id is None:
            continue

        target = yaml.safe_load(find_rule(root, target_id).read_text())
        if not isinstance(target, dict):
            raise SystemExit(f"alias target {target_id!r} is not a mapping")

        rebuilt = {
            key: value for key, value in document.items() if key in ALIAS_OWNED
        }
        rebuilt.update(matcher_of(target))
        # Keep the alias-owned keys first so the file still reads as a rule.
        ordered = {
            key: rebuilt[key]
            for key in list(document.keys()) + list(rebuilt.keys())
            if key in rebuilt
        }

        if ordered == document:
            continue
        drifted.append(str(path.relative_to(root)))
        if not check:
            path.write_text(render(ordered))

    if check and drifted:
        for name in drifted:
            print(f"alias out of sync with its replacement: {name}", file=sys.stderr)
        return 1
    for name in drifted:
        print(f"synced {name}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail instead of rewriting when an alias has drifted",
    )
    args = parser.parse_args()
    return sync(args.root.resolve(), check=args.check)


if __name__ == "__main__":
    raise SystemExit(main())
