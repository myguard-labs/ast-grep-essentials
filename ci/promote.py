#!/usr/bin/env python3
"""Promote a reviewed ast-grep-essentials pack.

A reviewed pack is a commit carrying a signed annotated tag named
``reviewed-YYYYMMDD-N`` (N >= 1). This script owns the gates that must pass
before such a tag is created:

``check`` (default)
    1. full ``ast-grep test`` (snapshots included) and ``ci/tests``;
    2. every rule added or changed since the previous ``reviewed-*`` tag (all
       rules when there is none) has a mirrored ``tests/`` entry with both
       ``valid`` and ``invalid`` cases, otherwise it is withheld and fails;
    3. a scan of the pinned corpus (``ci/corpus``, digest in the baseline)
       counts findings per rule; a rule that exceeds its baseline count plus
       the threshold blocks unless acknowledged in the baseline file;
    4. the median wall time of the timed scans may not exceed the baseline
       median by more than the documented tolerance.
``baseline``
    Rewrite ``ci/baselines/promotion.json`` from the current tree.
``tag``
    On a clean tree whose HEAD equals the remote ``main``, run ``check`` on
    HEAD and create the signed annotated tag. The push command is printed;
    nothing is pushed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import re
import shutil
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
from collections import Counter
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

SCHEMA = 1
BASELINE = PurePosixPath("ci/baselines/promotion.json")
CORPUS = PurePosixPath("ci/corpus")
TAG_RE = re.compile(r"^reviewed-(\d{8})-([1-9]\d{0,5})$")
TEST_RESULT = re.compile(r"(?m)^test result: ok\. (\d+) passed; 0 failed;\s*$")
ENGINE_VERSION = re.compile(r"ast-grep (\d+\.\d+\.\d+)")
DEFAULT_RUNS = 3
MAX_RUNS = 20
LIST_LIMIT = 40
# A scan may be slower than the baseline median by this ratio plus this
# absolute slack before it blocks; both live in the baseline file.
DEFAULT_TOLERANCE_RATIO = 0.5
DEFAULT_TOLERANCE_SECONDS = 0.25
DEFAULT_NEW_RULE_THRESHOLD = 0
COMMAND_TIMEOUT = 1800


class PromotionError(RuntimeError):
    """A gate or precondition failed with a bounded operator-facing reason."""


def run(
    command: Sequence[str | Path],
    *,
    cwd: Path,
    check: bool = True,
    timeout: int = COMMAND_TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    """Run one argv command, raising a bounded error on failure."""
    try:
        result = subprocess.run(
            [str(part) for part in command],
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PromotionError(f"cannot run {command[0]}: {error}") from error
    if check and result.returncode:
        raise PromotionError(f"{Path(str(command[0])).name} failed: {tail(result)}")
    return result


def tail(result: subprocess.CompletedProcess[str], limit: int = 1500) -> str:
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    return output[-limit:] or f"exit {result.returncode}"


def bounded(items: Sequence[str], limit: int = LIST_LIMIT) -> list[str]:
    """Return at most ``limit`` lines plus a count of the omitted rest."""
    shown = list(items[:limit])
    if len(items) > limit:
        shown.append(f"... and {len(items) - limit} more")
    return shown


def git(root: Path, *args: str, check: bool = True) -> str:
    return run(["git", *args], cwd=root, check=check).stdout


# --------------------------------------------------------------------------
# Rules and controls
# --------------------------------------------------------------------------


def rule_files(tree: Path) -> list[PurePosixPath]:
    rules = tree / "rules"
    found = [
        PurePosixPath(path.relative_to(tree).as_posix())
        for path in rules.rglob("*")
        if path.suffix in {".yml", ".yaml"} and path.is_file()
    ]
    return sorted(found)


def load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        raise PromotionError(f"{path.name}: unreadable YAML: {error}") from error


def rule_id(tree: Path, path: PurePosixPath) -> str:
    data = load_yaml(tree / path)
    if not isinstance(data, dict) or not isinstance(data.get("id"), str):
        raise PromotionError(f"{path}: rule has no string id")
    return data["id"]


def rule_ids(tree: Path) -> list[str]:
    ids = [rule_id(tree, path) for path in rule_files(tree)]
    duplicates = sorted(key for key, count in Counter(ids).items() if count > 1)
    if duplicates:
        raise PromotionError(f"duplicate rule ids: {', '.join(bounded(duplicates))}")
    return sorted(ids)


def mirrored_fixture(path: PurePosixPath) -> PurePosixPath:
    return PurePosixPath("tests", *path.parts[1:])


def _non_empty_cases(value: object) -> bool:
    return isinstance(value, list) and any(
        isinstance(case, str) and case.strip() for case in value
    )


def control_problem(tree: Path, path: PurePosixPath) -> str | None:
    """Return why ``path`` lacks valid+invalid controls, or None."""
    fixture = mirrored_fixture(path)
    if not (tree / fixture).is_file():
        return f"{path}: no fixture at {fixture}"
    try:
        expected = rule_id(tree, path)
        data = load_yaml(tree / fixture)
    except PromotionError as error:
        return f"{path}: {error}"
    if not isinstance(data, dict):
        return f"{path}: fixture is not a mapping"
    if data.get("id") != expected:
        return f"{path}: fixture id does not match rule id {expected}"
    missing = [
        key for key in ("valid", "invalid") if not _non_empty_cases(data.get(key))
    ]
    if missing:
        return f"{path}: fixture lacks {' and '.join(missing)} cases"
    return None


def reviewed_tags(names: Iterable[str]) -> list[str]:
    """Well-formed reviewed tags, oldest first by (date, N)."""
    matched = [(TAG_RE.match(name), name) for name in names]
    valid = [(m.group(1), int(m.group(2)), name) for m, name in matched if m]
    return [name for _, _, name in sorted(valid)]


def verified_tag(repo: Path, name: str) -> bool:
    """True only for an annotated tag whose signature ``git tag -v`` accepts."""
    if (
        run(["git", "cat-file", "-t", name], cwd=repo, check=False).stdout.strip()
        != "tag"
    ):
        return False
    return run(["git", "tag", "-v", name], cwd=repo, check=False).returncode == 0


def previous_tag(repo: Path, rev: str) -> tuple[str | None, list[str]]:
    """Newest verified reviewed tag reachable from ``rev`` plus skipped names."""
    tags = git(repo, "tag", "--merged", rev, "--list", "reviewed-*").split()
    skipped: list[str] = []
    for name in reversed(reviewed_tags(tags)):
        if verified_tag(repo, name):
            return name, skipped
        skipped.append(name)
    return None, skipped


def _as_rule(name: str) -> PurePosixPath | None:
    path = PurePosixPath(name)
    if path.suffix not in {".yml", ".yaml"} or "__snapshots__" in path.parts:
        return None
    return PurePosixPath("rules", *path.parts[1:])


def changed_rules(
    repo: Path, tree: Path, rev: str | None, base: str | None
) -> list[PurePosixPath]:
    """Rules whose rule file or fixture changed since ``base``.

    Every rule is selected when there is no base. A deleted fixture selects its
    rule too, so the control gate reports it as missing.
    """
    if base is None:
        return rule_files(tree)
    spec = [base, rev] if rev else [base]
    names = git(
        repo, "diff", "-z", "--name-only", "--no-renames", *spec, "--", "rules", "tests"
    ).split("\0")
    if rev is None:
        names += git(
            repo,
            "ls-files",
            "-z",
            "--others",
            "--exclude-standard",
            "--",
            "rules",
            "tests",
        ).split("\0")
    paths = {path for name in names if (path := _as_rule(name))}
    return sorted(path for path in paths if (tree / path).is_file())


# --------------------------------------------------------------------------
# Engine, corpus, scans
# --------------------------------------------------------------------------


def pinned_engine_version(tree: Path) -> str:
    try:
        data = json.loads((tree / "package.json").read_text(encoding="utf-8"))
        version = data["devDependencies"]["@ast-grep/cli"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise PromotionError(
            f"package.json has no @ast-grep/cli pin: {error}"
        ) from error
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise PromotionError(f"@ast-grep/cli pin is not exact: {version!r}")
    return version


def find_engine(repo: Path, explicit: str | None) -> Path:
    if explicit:
        candidate = Path(explicit).absolute()
    else:
        local = repo / "node_modules" / ".bin" / "ast-grep"
        found = shutil.which("ast-grep")
        candidate = local if local.exists() else Path(found) if found else local
    if not os.access(candidate, os.X_OK):
        raise PromotionError(
            f"ast-grep engine not executable: {candidate}; run npm ci or pass --engine"
        )
    return candidate


def engine_version(engine: Path, tree: Path) -> str:
    match = ENGINE_VERSION.search(run([engine, "--version"], cwd=tree).stdout)
    if not match:
        raise PromotionError("ast-grep --version printed no version")
    return match.group(1)


def corpus_digest(tree: Path) -> tuple[str, int]:
    root = tree / CORPUS
    if not root.is_dir():
        raise PromotionError(f"pinned corpus missing: {CORPUS}")
    digest = hashlib.sha256()
    count = 0
    for path in sorted(p for p in root.rglob("*") if p.is_file() or p.is_symlink()):
        if path.is_symlink():
            raise PromotionError(f"corpus entry is a symlink: {path.relative_to(tree)}")
        rel = path.relative_to(root).as_posix()
        digest.update(rel.encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
        count += 1
    if not count:
        raise PromotionError(f"pinned corpus is empty: {CORPUS}")
    return f"sha256:{digest.hexdigest()}", count


def scan_once(engine: Path, tree: Path) -> tuple[Counter[str], float]:
    started = time.perf_counter()
    result = run([engine, "scan", "--json=stream", str(CORPUS)], cwd=tree, check=False)
    elapsed = time.perf_counter() - started
    if result.returncode not in (0, 1):
        raise PromotionError(f"corpus scan failed: {tail(result)}")
    counts: Counter[str] = Counter()
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        try:
            counts[json.loads(line)["ruleId"]] += 1
        except (ValueError, KeyError, TypeError) as error:
            raise PromotionError(
                f"corpus scan printed malformed JSON: {error}"
            ) from error
    return counts, elapsed


@dataclass
class Scan:
    counts: dict[str, int]
    median: float
    timings: list[float]


def timed_scan(engine: Path, tree: Path, runs: int) -> Scan:
    """One warm-up scan plus ``runs`` timed scans; counts must not vary."""
    reference, _ = scan_once(engine, tree)
    timings = []
    for _ in range(runs):
        counts, elapsed = scan_once(engine, tree)
        if counts != reference:
            raise PromotionError(
                "corpus scan is nondeterministic: finding counts differ between runs"
            )
        timings.append(elapsed)
    return Scan(dict(sorted(reference.items())), statistics.median(timings), timings)


# --------------------------------------------------------------------------
# Baseline
# --------------------------------------------------------------------------


def _number(value: object, name: str, *, integer: bool = False) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, int if integer else (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise PromotionError(
            f"baseline {name} must be a non-negative {'integer' if integer else 'number'}"
        )
    return value


def _count_map(value: object, name: str) -> dict[str, int]:
    if not isinstance(value, dict):
        raise PromotionError(f"baseline {name} must be an object")
    for key, count in value.items():
        _number(count, f"{name}.{key}", integer=True)
    return value


def load_baseline(tree: Path) -> dict[str, Any]:
    path = tree / BASELINE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise PromotionError(
            f"baseline missing: {BASELINE}; run `promote.py baseline`"
        ) from error
    except (OSError, ValueError) as error:
        raise PromotionError(f"baseline unreadable: {error}") from error
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise PromotionError(f"baseline schema must be {SCHEMA}")
    for key in ("engine", "corpus", "perf", "fp"):
        if key not in data:
            raise PromotionError(f"baseline lacks {key}")
    if not isinstance(data["engine"], str):
        raise PromotionError("baseline engine must be a string")
    corpus, perf, fp = data["corpus"], data["perf"], data["fp"]
    if not isinstance(corpus, dict) or not isinstance(corpus.get("digest"), str):
        raise PromotionError("baseline corpus.digest must be a string")
    if not isinstance(perf, dict) or not isinstance(fp, dict):
        raise PromotionError("baseline perf and fp must be objects")
    for key in ("median_seconds", "tolerance_ratio", "tolerance_seconds"):
        _number(perf.get(key), f"perf.{key}")
    _number(perf.get("runs"), "perf.runs", integer=True)
    _number(fp.get("new_rule_threshold"), "fp.new_rule_threshold", integer=True)
    _count_map(fp.get("counts"), "fp.counts")
    _count_map(fp.get("acknowledged"), "fp.acknowledged")
    rules = fp.get("rules")
    if not isinstance(rules, list) or not all(isinstance(item, str) for item in rules):
        raise PromotionError("baseline fp.rules must be a list of rule ids")
    return data


def build_baseline(
    tree: Path, engine: Path, runs: int, previous: dict[str, Any] | None
) -> dict[str, Any]:
    version = engine_version(engine, tree)
    pinned = pinned_engine_version(tree)
    if version != pinned:
        raise PromotionError(f"engine {version} differs from package.json pin {pinned}")
    digest, files = corpus_digest(tree)
    scan = timed_scan(engine, tree, runs)
    perf = (previous or {}).get("perf", {})
    fp = (previous or {}).get("fp", {})
    return {
        "schema": SCHEMA,
        "engine": version,
        "corpus": {"path": str(CORPUS), "digest": digest, "files": files},
        "perf": {
            "runs": runs,
            "median_seconds": round(scan.median, 3),
            "tolerance_ratio": perf.get("tolerance_ratio", DEFAULT_TOLERANCE_RATIO),
            "tolerance_seconds": perf.get(
                "tolerance_seconds", DEFAULT_TOLERANCE_SECONDS
            ),
        },
        "fp": {
            "new_rule_threshold": fp.get(
                "new_rule_threshold", DEFAULT_NEW_RULE_THRESHOLD
            ),
            "rules": rule_ids(tree),
            "counts": scan.counts,
            "acknowledged": {},
        },
    }


def write_baseline(tree: Path, data: dict[str, Any]) -> None:
    path = tree / BASELINE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------
# Gates
# --------------------------------------------------------------------------


@dataclass
class Report:
    failures: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.failures


def gate_tests(engine: Path, tree: Path, report: Report) -> None:
    result = run([engine, "test"], cwd=tree, check=False)
    match = TEST_RESULT.search(result.stdout)
    if result.returncode or not match or not int(match.group(1)):
        report.failures.append(f"ast-grep test failed: {tail(result, 800)}")
    else:
        report.summary["rule_tests"] = int(match.group(1))
    unit = run(
        [sys.executable, "-m", "unittest", "discover", "-s", "ci/tests"],
        cwd=tree,
        check=False,
    )
    if unit.returncode:
        report.failures.append(f"ci/tests failed: {tail(unit, 800)}")


def gate_controls(repo: Path, tree: Path, rev: str | None, report: Report) -> None:
    base, skipped = previous_tag(repo, rev or "HEAD")
    if skipped:
        report.notes.append("ignored unverified reviewed tags (not signed annotated):")
        report.notes.extend(f"  {name}" for name in bounded(skipped))
    candidates = changed_rules(repo, tree, rev, base)
    withheld = [
        problem for path in candidates if (problem := control_problem(tree, path))
    ]
    report.summary["previous_tag"] = base or "none"
    report.summary["promoted_rules"] = len(candidates) - len(withheld)
    if withheld:
        report.failures.append(
            f"{len(withheld)} rule(s) withheld for missing controls:"
        )
        report.failures.extend(f"  withheld {line}" for line in bounded(withheld))


def compare_findings(
    baseline: dict[str, Any], counts: dict[str, int], report: Report
) -> None:
    fp = baseline["fp"]
    known = set(fp["rules"])
    threshold = fp["new_rule_threshold"]
    flagged, unacked = [], []
    for rule, count in sorted(counts.items()):
        allowed = fp["counts"].get(rule, 0) if rule in known else 0
        if count <= allowed + threshold:
            continue
        label = "new rule" if rule not in known else f"was {allowed}"
        ack = fp["acknowledged"].get(rule)
        line = f"{rule}: {count} finding(s) ({label}, threshold {threshold})"
        if ack is not None and count <= ack:
            flagged.append(f"{line}, acknowledged up to {ack}")
        else:
            unacked.append(line)
    report.summary["corpus_findings"] = sum(counts.values())
    report.summary["corpus_rules_hit"] = len(counts)
    if flagged:
        report.notes.append("acknowledged corpus findings:")
        report.notes.extend(f"  {line}" for line in bounded(flagged))
    if unacked:
        report.failures.append(
            f"{len(unacked)} rule(s) exceed the corpus finding baseline; "
            f"review and acknowledge in {BASELINE}:"
        )
        report.failures.extend(f"  review {line}" for line in bounded(unacked))


def compare_perf(baseline: dict[str, Any], scan: Scan, report: Report) -> None:
    perf = baseline["perf"]
    limit = (
        perf["median_seconds"] * (1 + perf["tolerance_ratio"])
        + perf["tolerance_seconds"]
    )
    report.summary["scan_median_seconds"] = round(scan.median, 3)
    report.summary["scan_baseline_seconds"] = perf["median_seconds"]
    if scan.median > limit:
        report.failures.append(
            f"corpus scan regressed: median {scan.median:.3f}s > limit {limit:.3f}s "
            f"(baseline {perf['median_seconds']}s x {1 + perf['tolerance_ratio']} "
            f"+ {perf['tolerance_seconds']}s)"
        )


def gate_corpus(engine: Path, tree: Path, runs: int, report: Report) -> None:
    baseline = load_baseline(tree)
    version = engine_version(engine, tree)
    pinned = pinned_engine_version(tree)
    if version != pinned or version != baseline["engine"]:
        raise PromotionError(
            f"engine {version} differs from package.json pin {pinned} "
            f"or baseline {baseline['engine']}"
        )
    digest, files = corpus_digest(tree)
    if digest != baseline["corpus"]["digest"]:
        raise PromotionError(
            f"pinned corpus changed ({digest}); rerun `promote.py baseline` and review"
        )
    report.summary["corpus_files"] = files
    scan = timed_scan(engine, tree, runs)
    compare_findings(baseline, scan.counts, report)
    compare_perf(baseline, scan, report)


def run_checks(
    repo: Path, tree: Path, engine: Path, rev: str | None, runs: int
) -> Report:
    report = Report()
    report.summary["rules"] = len(rule_ids(tree))
    gate_tests(engine, tree, report)
    gate_controls(repo, tree, rev, report)
    try:
        gate_corpus(engine, tree, runs, report)
    except PromotionError as error:
        report.failures.append(str(error))
    return report


def print_report(report: Report) -> None:
    for key in sorted(report.summary):
        print(f"{key}: {report.summary[key]}")
    for line in report.notes:
        print(line)
    for line in report.failures:
        print(f"FAIL {line}" if not line.startswith("  ") else line)
    print("promotion check: " + ("PASS" if report.ok else "FAIL"))


# --------------------------------------------------------------------------
# Tree export and tagging
# --------------------------------------------------------------------------


@contextmanager
def exported(repo: Path, rev: str) -> Iterator[Path]:
    """Extract ``rev`` into a temporary directory, independent of the worktree."""
    commit = git(repo, "rev-parse", "--verify", f"{rev}^{{commit}}").strip()
    with tempfile.TemporaryDirectory(prefix="promote-") as tmp:
        archive = Path(tmp) / "tree.tar"
        with archive.open("wb") as handle:
            try:
                subprocess.run(
                    ["git", "archive", "--format=tar", commit],
                    cwd=repo,
                    stdout=handle,
                    check=True,
                    timeout=COMMAND_TIMEOUT,
                )
            except (OSError, subprocess.SubprocessError) as error:
                raise PromotionError(f"git archive {commit} failed: {error}") from error
        tree = Path(tmp) / "tree"
        tree.mkdir()
        with tarfile.open(archive) as tar:
            tar.extractall(tree, filter="data")
        archive.unlink()
        yield tree


def next_tag_name(names: Iterable[str], today: str) -> str:
    if not re.fullmatch(r"\d{8}", today):
        raise PromotionError(f"date must be YYYYMMDD: {today!r}")
    used = [
        int(m.group(2))
        for name in names
        if (m := TAG_RE.match(name)) and m.group(1) == today
    ]
    return f"reviewed-{today}-{max(used, default=0) + 1}"


def remote_tags(repo: Path, remote: str) -> dict[str, str]:
    """Remote reviewed tag names mapped to the commit each one peels to."""
    lines = git(
        repo, "ls-remote", "--tags", remote, "refs/tags/reviewed-*"
    ).splitlines()
    tags: dict[str, str] = {}
    for line in sorted(lines, key=lambda item: item.endswith("^{}")):
        sha, _, ref = line.partition("\trefs/tags/")
        tags[ref.removesuffix("^{}")] = sha
    return tags


def tag_message(name: str, report: Report) -> str:
    lines = [f"Reviewed ast-grep-essentials pack {name}", ""]
    lines += [f"{key}: {report.summary[key]}" for key in sorted(report.summary)]
    return "\n".join(lines) + "\n"


def tag_preconditions(
    repo: Path, head: str, remote: str, branch: str
) -> dict[str, str]:
    """Require HEAD == remote branch with no reviewed tag; return remote tags."""
    remote_line = git(repo, "ls-remote", remote, f"refs/heads/{branch}").split()
    if not remote_line or remote_line[0] != head:
        raise PromotionError(f"HEAD {head[:12]} is not {remote}/{branch}")
    published = remote_tags(repo, remote)
    already = reviewed_tags(
        git(repo, "tag", "--points-at", head, "--list", "reviewed-*").split()
        + [name for name, sha in published.items() if sha == head]
    )
    if already:
        raise PromotionError(f"HEAD already carries {already[-1]}")
    return published


def tag(  # pylint: disable=too-many-locals,too-many-arguments
    repo: Path, engine: Path, *, runs: int, remote: str, branch: str, today: str
) -> str:
    if git(repo, "status", "--porcelain").strip():
        raise PromotionError("working tree is not clean")
    head = git(repo, "rev-parse", "HEAD").strip()
    tag_preconditions(repo, head, remote, branch)
    with exported(repo, head) as tree:
        report = run_checks(repo, tree, engine, head, runs)
    print_report(report)
    if not report.ok:
        raise PromotionError("check failed; no tag created")
    # The check takes a while; the remote may have moved meanwhile.
    published = tag_preconditions(repo, head, remote, branch)
    local = git(repo, "tag", "--list", "reviewed-*").split()
    name = next_tag_name([*local, *published], today)
    handle, message_name = tempfile.mkstemp(prefix="promote-tag-")
    os.close(handle)
    message = Path(message_name)
    try:
        message.write_text(tag_message(name, report), encoding="utf-8")
        git(repo, "tag", "-s", "-F", str(message), name, head)
    finally:
        message.unlink()
    if not verified_tag(repo, name):
        git(repo, "tag", "-d", name)
        raise PromotionError(f"signature of {name} does not verify; tag removed")
    print(f"created signed tag {name} at {head}")
    print(f"push with: git push {remote} refs/tags/{name}")
    return name


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "command", nargs="?", default="check", choices=("check", "baseline", "tag")
    )
    parser.add_argument(
        "--repo",
        default=str(Path(__file__).resolve().parents[1]),
        help="repository root",
    )
    parser.add_argument("--rev", help="check this commit instead of the working tree")
    parser.add_argument(
        "--engine", help="ast-grep binary (default: node_modules/.bin/ast-grep)"
    )
    parser.add_argument(
        "--runs", type=int, default=DEFAULT_RUNS, help=f"timed scans, 1..{MAX_RUNS}"
    )
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--branch", default="main")
    parser.add_argument(
        "--date",
        default=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d"),
        help="tag date YYYYMMDD",
    )
    args = parser.parse_args(argv)
    if not 1 <= args.runs <= MAX_RUNS:
        parser.error(f"--runs must be 1..{MAX_RUNS}")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    repo = Path(args.repo).resolve()
    try:
        engine = find_engine(repo, args.engine)
        if args.command == "tag":
            tag(
                repo,
                engine,
                runs=args.runs,
                remote=args.remote,
                branch=args.branch,
                today=args.date,
            )
            return 0
        if args.command == "baseline":
            previous = None
            if (repo / BASELINE).exists():
                previous = load_baseline(repo)
            data = build_baseline(repo, engine, args.runs, previous)
            write_baseline(repo, data)
            print(
                f"wrote {BASELINE}: {len(data['fp']['rules'])} rules, "
                f"{sum(data['fp']['counts'].values())} corpus findings, "
                f"median {data['perf']['median_seconds']}s"
            )
            return 0
        if args.rev:
            commit = git(
                repo, "rev-parse", "--verify", f"{args.rev}^{{commit}}"
            ).strip()
            with exported(repo, commit) as tree:
                report = run_checks(repo, tree, engine, commit, args.runs)
        else:
            report = run_checks(repo, repo, engine, None, args.runs)
        print_report(report)
        return 0 if report.ok else 1
    except PromotionError as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
