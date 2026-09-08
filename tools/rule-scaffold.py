#!/usr/bin/env python3
"""rule-scaffold.py -- create the rule/fixture pair and the inventory bump for one rule.

Why: every new rule needs the same four mechanical edits -- rule YAML in
rules/<lang>/<category>/<id>.yml, a fixture with the same id under tests/, the
explicit rule-count guard in tests/test_diagnostics.py, and a layout that
tests/test_inventory.py accepts. A model retyping those is waste and drifts;
this script does them once so the model only writes the matcher and the
controls. Pipeline: .claude/skills/astgrep-rules/references/harvest-pipeline.md

Usage:
  rule-scaffold.py --proposal WORK/cluster/proposals.jsonl --id go-x-y \\
                   --category security --claim 'Check bounds before indexing' \\
                   [--matcher matcher.yml] [--dry-run]
  rule-scaffold.py --id c-x-y --language c --category correctness \\
                   --positive 'int f(){...}' --near-miss 'int f(){...}' \\
                   --claim 'Check the return value before use' [--dry-run]

Inputs:  a proposal (by --id from a proposals.jsonl) or explicit flags;
         optional --matcher, a YAML file whose top-level mapping becomes the
         rule's `rule:` body (else a TODO placeholder that will not parse as a
         rule, so an unfinished scaffold cannot pass the suite by accident).
Outputs: the two YAML files; tests/test_diagnostics.py count bumped by one.
Exit:    0 written, 1 refused (invalid/conflicting inputs or lock unavailable).
Side effects: writes into the repository; --dry-run prints instead but still
              acquires the coordination lock and may create its ignored file.
Limits:  message/note are drafts from the claim; the author rewrites them.
Extend:  CATEGORIES, LANGUAGES.
"""

import argparse
import errno
import json
import os
import re
import sys
import tempfile
from contextlib import ExitStack, contextmanager
from pathlib import Path
from time import monotonic, sleep
from typing import Literal

import yaml

WINDOWS = os.name == "nt"
WINDOWS_LOCK_RETRY_ERRNOS = {
    getattr(errno, name) for name in ("EACCES", "EDEADLK", "EDEADLOCK") if hasattr(errno, name)
}
POSIX_LOCK_RETRY_ERRNOS = {errno.EACCES, errno.EAGAIN}
LOCK_TIMEOUT_SECONDS = 60
LOCK_POLL_SECONDS = 0.1
CLEANUP_INTERRUPT_RETRIES = 3

ROOT = Path(__file__).resolve().parents[1]
CATEGORIES = ("security", "correctness")
LANGUAGES = ("go", "c", "php", "python", "javascript", "java", "lua", "bash")
# Unlike harvest-packets' Go/C proposal grammar, manual scaffolds support all
# LANGUAGES and one defect segment (for example go-check).
KEBAB = re.compile(r"^[a-z]+(-[a-z0-9]+)+$")


class LiteralStr(str):
    """Dump multi-line fixture sources as block scalars for readability."""


def _repr_literal(dumper, data):
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


yaml.add_representer(LiteralStr, _repr_literal)


def load_proposal(path: Path, rule_id: str) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        sys.exit(f"cannot read proposals file {path}: {error}")
    for line in text.splitlines():
        if line.strip():
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                sys.exit(f"malformed proposal line in {path}: {error}")
            if not isinstance(row, dict) or "id" not in row:
                sys.exit(f"proposal row must be an object with id in {path}")
            if row["id"] == rule_id:
                return row
    sys.exit(f"no proposal with id {rule_id!r} in {path}")


def bump_count(dry_run: bool) -> tuple[int, int]:
    """Bump every explicit rule-count guard in tests/test_diagnostics.py.

    The file asserts the count more than once (inventory and checked-count);
    all occurrences must agree, so they are read, checked equal, and rewritten
    together.
    """
    test = ROOT / "tests" / "test_diagnostics.py"
    try:
        with test.open(encoding="utf-8", newline="") as source:
            text = source.read()
    except (OSError, UnicodeError) as error:
        sys.exit(f"cannot read rule-count guard {test}: {error}")
    pattern = re.compile(r"(self\.assertEqual\((?:len\(rules\)|checked), )(\d+)")
    counts = {int(m.group(2)) for m in pattern.finditer(text)}
    if len(counts) != 1:
        sys.exit(f"rule-count guards disagree or are missing: {sorted(counts)}")
    old = counts.pop()
    new = old + 1
    if not dry_run:
        temporary = None
        temporary_identity = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=test.parent,
                                             newline="", delete=False,
                                             prefix=".rule-count-") as output:
                temporary = Path(output.name)
                temporary_identity = os.fstat(output.fileno())
                output.write(pattern.sub(lambda m: m.group(1) + str(new), text))
            temporary.chmod(test.stat().st_mode)
            temporary.replace(test)
            temporary = None
        finally:
            remove_owned_temp(temporary, temporary_identity)
    return old, new


def remove_owned_temp(path: Path | None, identity: os.stat_result | None) -> None:
    """Remove a count temp file only while its filesystem identity is unchanged."""
    if path is None:
        return
    if identity is None:
        warn_temp_retained(path, "ownership identity unavailable; left untouched")
        return
    try:
        current = path.lstat()
    except FileNotFoundError:
        return
    except BaseException as error:  # noqa: BLE001
        warn_temp_retained(path, f"cannot verify ownership: {error}")
        return
    if WINDOWS and (not identity.st_dev or not identity.st_ino
                    or not current.st_dev or not current.st_ino):
        warn_temp_retained(path, "filesystem identity unavailable; left untouched")
        return
    if not os.path.samestat(identity, current):
        warn_temp_retained(path, "path ownership changed; left untouched")
        return
    try:
        path.unlink(missing_ok=True)
    except BaseException as error:  # noqa: BLE001
        warn_temp_retained(path, f"cleanup failed: {error}")


def warn_temp_retained(path: Path, reason: str) -> bool:
    """Report a retained count temp; return whether stderr accepted the warning."""
    try:
        print(f"warning: retained count temp {path.name}: {reason}", file=sys.stderr)
    except BaseException:  # noqa: BLE001
        return False
    return True


def prepare_scaffold(args):
    """Resolve proposal fields and reject conflicting destinations before writing."""
    if not KEBAB.fullmatch(args.id):
        sys.exit(f"id {args.id!r} is not kebab-case")
    prop = load_proposal(args.proposal, args.id) if args.proposal else {}
    language = args.language or prop.get("language")
    positive = args.positive or prop.get("positive")
    near_miss = args.near_miss or prop.get("near_miss")
    claim = args.claim or prop.get("claim")
    if not (language and positive and near_miss and claim):
        sys.exit("need language, positive, near-miss and claim (flags or --proposal)")
    if language not in LANGUAGES:
        sys.exit(f"unsupported language {language!r}")
    prefixes = ("c-", "nginx-") if language == "c" else (f"{language}-",)
    if not args.id.startswith(prefixes):
        sys.exit(f"id {args.id!r} must be prefixed with its language")

    rule_path, fixture_path = scaffold_paths(args.id, language, args.category)
    rendered = render_scaffold(args, prop, language, positive, near_miss, claim)
    return rule_path, fixture_path, rendered


def scaffold_paths(rule_id, language, category):
    """Check both output paths and global ID uniqueness before generating files."""
    rule_path = ROOT / "rules" / language / category / f"{rule_id}.yml"
    fixture_path = ROOT / "tests" / language / category / f"{rule_id}.yml"
    for p in (rule_path, fixture_path):
        if p.exists():
            sys.exit(f"refusing to overwrite {p}")
    if any(p.stem == rule_id for p in (ROOT / "rules").rglob("*.yml")):
        sys.exit(f"id {rule_id!r} already exists under another category")
    return rule_path, fixture_path


def render_scaffold(args, prop, language, positive, near_miss, claim):
    """Serialize one rule and fixture, retaining a deliberately invalid TODO matcher."""

    if args.matcher:
        try:
            matcher = yaml.safe_load(args.matcher.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as error:
            sys.exit(f"cannot read --matcher {args.matcher}: {error}; "
                     "provide a readable YAML rule body")
        if not isinstance(matcher, dict):
            sys.exit("--matcher must be a YAML mapping (the rule body)")
    else:
        # A string here is rejected by ast-grep as "Cannot parse rule", so an
        # unfinished scaffold fails loudly instead of matching nothing.
        matcher = "TODO: replace with the matcher; see docs/authoring.md"

    rule = {
        "id": args.id, "language": language, "severity": args.severity,
        "message": claim,
        "note": prop.get("rationale", "TODO: when to dismiss, and the semantic limit."),
        "rule": matcher,
    }
    fixture = {"id": args.id,
               "valid": [LiteralStr(near_miss)],
               "invalid": [LiteralStr(positive)]}
    rule_text = yaml.dump(rule, sort_keys=False, width=80, allow_unicode=True)
    fixture_text = yaml.dump(fixture, sort_keys=False, width=1000, allow_unicode=True)
    return rule_text, fixture_text


def create_parent_dirs(directories: tuple[Path, ...], created_dirs: list[Path]) -> None:
    """Create missing ancestors, recording only directories this process owns."""
    for directory in directories:
        missing = []
        cursor = directory
        while not cursor.exists():
            missing.append(cursor)
            cursor = cursor.parent
        for path in reversed(missing):
            try:
                path.mkdir()
            except FileExistsError:
                if not path.is_dir():
                    raise
            else:
                created_dirs.append(path)


def remove_created_path(path: Path, *, directory: bool = False) -> bool:
    """Best-effort rollback that does not let a repeated Ctrl-C mask the first failure."""
    interrupts = 0
    while True:
        try:
            path.rmdir() if directory else path.unlink(missing_ok=True)
        except KeyboardInterrupt:
            interrupts += 1
            if interrupts >= CLEANUP_INTERRUPT_RETRIES:
                return False
            continue
        except FileNotFoundError:
            return True
        except OSError:
            return False
        return True


def warn_retained_paths(
        paths: list[Path], *, outcome: Literal["rollback", "unknown", "committed"] = "rollback",
) -> None:
    """Report preserved paths without allowing warning failure to mask the cause."""
    if not paths:
        return
    rendered: list[str] = []
    for path in paths:
        try:
            rendered.append(str(path.relative_to(ROOT)))
        except BaseException:  # noqa: BLE001
            try:
                rendered.append(str(path))
            except BaseException:  # noqa: BLE001
                rendered.append("<unprintable path>")
    if outcome == "unknown":
        message = ("warning: scaffold transaction state is unknown; kept paths: "
                   f"{', '.join(rendered)}; verify the count and tree before deleting")
    elif outcome == "committed":
        message = ("notice: scaffold outputs and count were committed before the interrupt: "
                   f"{', '.join(rendered)}")
    else:
        message = ("warning: scaffold rollback was incomplete; inspect retained paths "
                   f"(created parent directories may also remain): {', '.join(rendered)}")
    try:
        print(message, file=sys.stderr)
    except BaseException:  # noqa: BLE001
        return


def recover_scaffold(old: int, new: int, created: list[Path], created_dirs: list[Path]) -> None:
    """Reconcile outputs with the atomic count after an interrupted scaffold."""
    try:
        current, _ = bump_count(dry_run=True)
    except BaseException:  # noqa: BLE001
        # Preserve outputs when the count state is unknowable: deleting them
        # could leave an already committed count ahead of the tree.
        current = None
    retained: list[Path] = []
    if current == old:
        for path in reversed(created):
            if not remove_created_path(path):
                retained.append(path)
        for directory in reversed(created_dirs):
            if any(directory == path or directory in path.parents for path in retained):
                continue
            if not remove_created_path(directory, directory=True):
                retained.append(directory)
    elif current != new:
        retained.extend((*created, *created_dirs))
    if current == new:
        warn_retained_paths(created, outcome="committed")
    else:
        warn_retained_paths(retained, outcome="unknown" if current != old else "rollback")


def repository_lock_path() -> Path:
    """Keep the persistent lock outside tracked files when Git metadata exists."""
    metadata = ROOT / ".git"
    if metadata.is_dir():
        return metadata / "rule-scaffold.lock"
    if metadata.is_file():
        try:
            marker = metadata.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            marker = ""
        if marker.startswith("gitdir: "):
            gitdir = Path(marker.removeprefix("gitdir: "))
            gitdir = gitdir if gitdir.is_absolute() else ROOT / gitdir
            if gitdir.is_dir():
                return gitdir / "rule-scaffold.lock"
    return ROOT / ".rule-scaffold.lock"


@contextmanager
def scaffold_lock():
    """Serialize scaffolds so rule files and the inventory count stay consistent."""
    with repository_lock_path().open("a+b") as lock:
        if WINDOWS:
            import msvcrt
        else:
            import fcntl
        lock.seek(0)
        deadline = monotonic() + LOCK_TIMEOUT_SECONDS
        while True:
            try:
                if WINDOWS:
                    msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as error:
                retry_errnos = WINDOWS_LOCK_RETRY_ERRNOS if WINDOWS else POSIX_LOCK_RETRY_ERRNOS
                if error.errno not in retry_errnos:
                    raise
                remaining = deadline - monotonic()
                if remaining <= 0:
                    raise TimeoutError("timed out waiting for the scaffold lock") from error
                sleep(min(LOCK_POLL_SECONDS, remaining))
        try:
            yield
        finally:
            lock.seek(0)
            if WINDOWS:
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


@contextmanager
def cli_scaffold_lock():
    """Report lock contention as an ordinary CLI refusal instead of a traceback."""
    stack = ExitStack()
    try:
        stack.enter_context(scaffold_lock())
    except TimeoutError as error:
        sys.exit(str(error))
    except OSError as error:
        sys.exit(f"cannot acquire scaffold lock: {error}")
    with stack:
        yield


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    ap.add_argument("--id", required=True)
    ap.add_argument("--proposal", type=Path, help="proposals.jsonl to read --id from")
    ap.add_argument("--language", choices=LANGUAGES)
    ap.add_argument("--category", choices=CATEGORIES, required=True)
    ap.add_argument("--positive", help="source that must match")
    ap.add_argument("--near-miss", help="source that must not match")
    ap.add_argument("--claim", help="one-sentence syntactic claim (message draft)")
    ap.add_argument("--matcher", type=Path, help="YAML file: the `rule:` body")
    ap.add_argument("--severity", default="warning", choices=("error", "warning", "info"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.dry_run:
        with cli_scaffold_lock():
            rule_path, fixture_path, (rule_text, fixture_text) = prepare_scaffold(args)
            old, new = bump_count(dry_run=True)
        print(f"--- {rule_path.relative_to(ROOT)}\n{rule_text}")
        print(f"--- {fixture_path.relative_to(ROOT)}\n{fixture_text}")
        print(f"--- tests/test_diagnostics.py: rule count {old} -> {new}")
        return 0
    with cli_scaffold_lock():
        rule_path, fixture_path, (rule_text, fixture_text) = prepare_scaffold(args)
        old, new = bump_count(dry_run=True)
        created_dirs: list[Path] = []
        created: list[Path] = []
        try:
            create_parent_dirs((rule_path.parent, fixture_path.parent), created_dirs)
            for path, text in ((rule_path, rule_text), (fixture_path, fixture_text)):
                with path.open("x", encoding="utf-8", newline="") as output:
                    created.append(path)
                    output.write(text)
            old, new = bump_count(dry_run=False)
        except (OSError, UnicodeError, SystemExit, KeyboardInterrupt):
            recover_scaffold(old, new, created, created_dirs)
            raise
    print(f"wrote {rule_path.relative_to(ROOT)}, {fixture_path.relative_to(ROOT)}; "
          f"rule count {old} -> {new}. Next: tools/rule-probe.py {args.id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
