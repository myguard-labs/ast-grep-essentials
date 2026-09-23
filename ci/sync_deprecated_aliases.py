#!/usr/bin/env python3
"""Regenerate deprecated rule aliases from the rules that replaced them.

A deprecated alias exists so consumers that explicitly promote a former rule ID
keep matching the same code. That only holds while the alias matcher stays
identical to its replacement's, which cannot be maintained by hand: enriching
the replacement alone silently breaks the alias.

An alias declares its target in ``metadata.deprecated_alias_of``. This module
copies the matcher fields from that target by replacing only the alias's
matcher key blocks with the target's own source text, so the alias's banner,
ID, 'off' severity, prose, and metadata stay byte for byte as written.
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


def split_blocks(text: str) -> tuple[str, list[tuple[str, str]]]:
    """Split a rule file into its preamble and one text block per top-level key.

    A block starts at an unindented key line and runs until the next one, so it
    carries its nested lines, block scalars, and any comments or blank lines
    that trail it. The preamble is everything before the first key, such as the
    provenance banner. Raises SystemExit when the text cannot be split cleanly.
    """
    preamble: list[str] = []
    blocks: list[list[str]] = []
    for line in text.splitlines(keepends=True):
        starts_key = line[:1] not in ("", " ", "\t", "#", "\n", "\r")
        if starts_key:
            if line.startswith(("---", "...")):
                raise SystemExit("rule file uses YAML document markers")
            blocks.append([line])
        elif blocks:
            blocks[-1].append(line)
        else:
            preamble.append(line)

    keyed: list[tuple[str, str]] = []
    for lines in blocks:
        block = "".join(lines)
        if not block.endswith("\n"):
            block += "\n"
        parsed = yaml.safe_load(block)
        if not isinstance(parsed, dict) or len(parsed) != 1:
            raise SystemExit(f"cannot isolate top-level key in: {lines[0]!r}")
        keyed.append((next(iter(parsed)), block))
    return "".join(preamble), keyed


def rewrite_matcher(alias_text: str, target_text: str) -> str:
    """Replace the alias matcher blocks with the target's source text.

    The preamble and alias-owned blocks are kept byte for byte. A matcher key
    present in both files takes the target's block at the alias's position; a
    matcher key only the alias has is dropped; a matcher key only the target
    has follows the last matcher block (or the end, when there was none).
    """
    preamble, alias_blocks = split_blocks(alias_text)
    _, target_blocks = split_blocks(target_text)
    target_matcher = {
        key: block for key, block in target_blocks if key not in ALIAS_OWNED
    }

    out: list[str] = []
    placed: set[str] = set()
    insert_at = None
    for key, block in alias_blocks:
        if key in ALIAS_OWNED:
            out.append(block)
            continue
        if key in target_matcher:
            out.append(target_matcher[key])
            placed.add(key)
        insert_at = len(out)
    missing = [block for key, block in target_matcher.items() if key not in placed]
    if insert_at is None:
        insert_at = len(out)
    out[insert_at:insert_at] = missing
    return preamble + "".join(out)


def expected_alias(document: dict, target_path: Path, target_id: str) -> dict:
    """Return the alias as it must parse: its owned keys plus the target matcher."""
    target = yaml.safe_load(target_path.read_text())
    if not isinstance(target, dict):
        raise SystemExit(f"alias target {target_id!r} is not a mapping")
    expected = {key: value for key, value in document.items() if key in ALIAS_OWNED}
    expected.update(matcher_of(target))
    return expected


def sync(root: Path, *, check: bool) -> int:
    drifted: list[str] = []
    for path in sorted(root.glob("rules/*/*/*.yml")):
        document = yaml.safe_load(path.read_text())
        if not isinstance(document, dict):
            continue
        target_id = alias_target(document)
        if target_id is None:
            continue

        target_path = find_rule(root, target_id)
        expected = expected_alias(document, target_path, target_id)
        if expected == document:
            continue
        drifted.append(str(path.relative_to(root)))
        if not check:
            text = rewrite_matcher(path.read_text(), target_path.read_text())
            if yaml.safe_load(text) != expected:
                raise SystemExit(f"textual resync of {path} diverged from its target")
            path.write_text(text)

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
