#!/usr/bin/env python3
"""Reproduce plans, validate exact oracles/fixes, and compare scan corpora."""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "node_modules" / ".bin" / "ast-grep"
MAX_FILES = 20_000
MAX_FINDINGS = 65_534
MAX_CORPUS_BYTES = 256 * 1024 * 1024
MAX_SCAN_OUTPUT_BYTES = 64 * 1024 * 1024
DIFFERENTIAL_ROOT = ROOT / "tests" / "differential" / "v1"


def load_tool(name: str):
    path = ROOT / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load tool: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SCAFFOLD = load_tool("rule-scaffold")
PLAN = load_tool("rule-plan")


def plan_paths() -> list[Path]:
    root = ROOT / "plans"
    return sorted(root.rglob("*.yml")) if root.is_dir() else []


def compile_plan(path: Path, *, preflight: bool = True):
    plan, _matcher, rule_text, fixture_text = PLAN.compile_plan(path, run_checks=preflight)
    expected_plan = ROOT / "plans" / plan["language"] / plan["category"] / f"{plan['id']}.yml"
    if path.resolve() != expected_plan.resolve():
        raise RuntimeError(f"PLAN_LAYOUT: expected {expected_plan.relative_to(ROOT)}")
    relative = path.relative_to(ROOT).as_posix()
    marker = f"# Generated from: {relative}\n"
    if rule_text.startswith("# MyGuard rule: "):
        lines = rule_text.splitlines(keepends=True)
        header_end = next((index for index, line in enumerate(lines)
                           if not line.startswith("# ")), len(lines))
        rule_text = "".join([*lines[:header_end], marker, *lines[header_end:]])
    else:
        rule_text = marker + rule_text
    fixture_text = marker + fixture_text
    if preflight:
        check_oracles(plan, yaml.safe_load(rule_text))
    rule_path = ROOT / "rules" / plan["language"] / plan["category"] / f"{plan['id']}.yml"
    fixture_path = ROOT / "tests" / plan["language"] / plan["category"] / f"{plan['id']}.yml"
    collisions = [candidate for candidate in (ROOT / "rules").glob(f"*/*/{plan['id']}.yml")
                  if candidate != rule_path]
    if collisions:
        raise RuntimeError(f"PLAN_ID_COLLISION: {plan['id']}: {collisions[0]}")
    return rule_path, fixture_path, rule_text, fixture_text


def scan_rule(rule: dict, source: str, engine: Path = ENGINE) -> list[dict]:
    result = subprocess.run(
        [str(engine), "scan", "--inline-rules", yaml.safe_dump(rule),
         "--stdin", "--json=compact"], input=source, text=True,
        capture_output=True, timeout=20, check=False,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError((result.stderr or result.stdout)[-500:])
    findings = json.loads(result.stdout or "[]")
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        raise RuntimeError("invalid or excessive ast-grep finding output")
    return findings


def check_oracles(plan: dict, rule: dict) -> None:
    for source, expected in plan.get("oracles", {}).items():
        findings = scan_rule(rule, source)
        actual = {
            "count": len(findings),
            "texts": [finding.get("text") for finding in findings],
            "ranges": [[finding["range"]["byteOffset"]["start"],
                        finding["range"]["byteOffset"]["end"]]
                       for finding in findings],
            "message": findings[0].get("message") if findings else None,
            "note": findings[0].get("note") if findings else None,
            "severity": findings[0].get("severity") if findings else None,
            "labels": [label.get("text") for finding in findings
                       for label in finding.get("labels", [])],
        }
        for key, wanted in expected.items():
            if key == "fixed":
                continue
            if actual[key] != wanted:
                raise RuntimeError(f"ORACLE_MISMATCH: {plan['id']} {key}: "
                                   f"expected {wanted!r}, got {actual[key]!r}")


def write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                         prefix=f".{path.name}.", delete=False) as output:
            temporary = Path(output.name)
            output.write(content)
        temporary.chmod(mode)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def generated_owner(path: Path) -> str | None:
    """Return an ownership marker only from the leading comment header."""
    if not path.is_file():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("# "):
            return None
        if line.startswith("# Generated from: "):
            return line
    return None


def stale_generated_artifacts(paths: list[Path]) -> list[str]:
    """Find generated artifacts whose owner vanished or no longer targets them."""
    expected = {}
    for plan_path in paths:
        rule_path, fixture_path, _rule, _fixture = compile_plan(plan_path, preflight=False)
        owner = f"# Generated from: {plan_path.relative_to(ROOT).as_posix()}"
        expected[rule_path.resolve()] = owner
        expected[fixture_path.resolve()] = owner
    stale = []
    for root in (ROOT / "rules", ROOT / "tests"):
        for artifact in root.glob("*/*/*.yml"):
            found_owner = generated_owner(artifact)
            if found_owner is not None and expected.get(artifact.resolve()) != found_owner:
                stale.append(artifact.relative_to(ROOT).as_posix())
    return sorted(stale)


def validate_plan_id_ownership(paths: list[Path]) -> None:
    """Reject duplicate plan IDs and collisions with handcrafted rules."""
    owners: dict[str, str] = {}
    for plan_path in paths:
        plan = PLAN.load_plan(plan_path)
        rule_id = plan["id"]
        if rule_id in owners:
            raise RuntimeError(f"PLAN_ID_COLLISION: {rule_id}: {owners[rule_id]}")
        owners[rule_id] = plan_path.relative_to(ROOT).as_posix()
        expected = ROOT / "rules" / plan["language"] / plan["category"] / f"{rule_id}.yml"
        collisions = [path for path in (ROOT / "rules").glob(f"*/*/{rule_id}.yml")
                      if path != expected]
        if collisions:
            raise RuntimeError(f"PLAN_ID_COLLISION: {rule_id}: {collisions[0]}")


def _changed_plan_artifacts(paths: list[Path], write: bool):
    drift, updates = [], []
    for path in paths:
        rule_path, fixture_path, rule_text, fixture_text = compile_plan(path)
        owner = f"# Generated from: {path.relative_to(ROOT).as_posix()}"
        for target, content in ((rule_path, rule_text), (fixture_path, fixture_text)):
            if target.is_file() and target.read_text(encoding="utf-8") == content:
                continue
            drift.append(target.relative_to(ROOT).as_posix())
            if write and target.exists() and generated_owner(target) != owner:
                raise RuntimeError(f"refusing to overwrite non-generated {target}")
            if write:
                updates.append((target, content, owner))
    return drift, updates


def _write_plan_artifacts(updates: list[tuple[Path, str, str]]) -> None:
    for target, content, owner in updates:
        if target.exists() and generated_owner(target) != owner:
            raise RuntimeError(f"refusing to overwrite non-generated {target}")
        write_atomic(target, content)


def validate_plan_fixes(paths: list[Path], rendered_rules: dict[Path, str] | None = None) -> int:
    """Validate every exact fixed-output oracle owned by canonical plans."""
    checked = 0
    with tempfile.TemporaryDirectory(prefix="rule-plan-fixes-") as directory:
        for plan_path in paths:
            plan = PLAN.load_plan(plan_path)
            if "fix" not in plan:
                continue
            rule_path = (ROOT / "rules" / plan["language"] / plan["category"]
                         / f"{plan['id']}.yml")
            candidate = (rendered_rules or {}).get(rule_path.resolve())
            if candidate is not None:
                temporary = Path(directory) / f"{plan['id']}.yml"
                temporary.write_text(candidate, encoding="utf-8")
                rule_path = temporary
            valid_sources = set(plan["cases"]["valid"])
            for source, oracle in plan.get("oracles", {}).items():
                if "fixed" in oracle:
                    validate_fix(
                        rule_path, source, oracle["fixed"],
                        allow_no_change=source in valid_sources,
                    )
                    checked += 1
    return checked


def _plans_command(write: bool) -> int:
    paths = plan_paths()
    validate_plan_id_ownership(paths)
    stale = stale_generated_artifacts(paths)
    if stale:
        print("stale generated artifacts: " + ", ".join(stale), file=sys.stderr)
        return 1
    drift, updates = _changed_plan_artifacts(paths, write)
    if not write:
        count_changed = sync_diagnostic_count(False, {path.stem for path in paths})
        if count_changed:
            drift.append("tests/test_diagnostics.py")
    if not write and drift:
        print("generated drift: " + ", ".join(drift), file=sys.stderr)
        return 1
    rendered_rules = {target.resolve(): content for target, content, _owner in updates}
    fixed = validate_plan_fixes(paths, rendered_rules if write else None)
    if write:
        _write_plan_artifacts(updates)
        if sync_diagnostic_count(True, {path.stem for path in paths}):
            drift.append("tests/test_diagnostics.py")
    print(f"{'regenerated' if write else 'verified'} {len(paths)} canonical plan(s)"
          + (f"; {len(drift)} artifact(s) updated" if write else "")
          + f"; {fixed} exact fix oracle(s)")
    return 0


def plans_command(write: bool) -> int:
    """Check plans, locking the complete discovery-to-write transaction when mutating."""
    if not write:
        return _plans_command(False)
    with SCAFFOLD.cli_scaffold_lock():
        return _plans_command(True)


def sync_diagnostic_count(write: bool, planned_ids: set[str]) -> bool:
    """Keep the explicit diagnostic guard reproducible when plans add rules."""
    path = ROOT / "tests/test_diagnostics.py"
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(r"(self\.assertEqual\((?:len\(rules\)|checked), )(\d+)")
    observed = {int(match.group(2)) for match in pattern.finditer(text)}
    if len(observed) != 1:
        raise RuntimeError("diagnostic rule-count guards disagree or are missing")
    existing = {rule.stem for rule in (ROOT / "rules").glob("*/*/*.yml")
                if rule.relative_to(ROOT / "rules").parts[0] != "powershell"}
    desired = len(existing | planned_ids)
    changed = observed != {desired}
    if changed and write:
        write_atomic(path, pattern.sub(lambda match: match.group(1) + str(desired), text))
    return changed


def metamorphic_cases(source: str, language: str) -> list[dict]:
    """Emit review candidates only; no transformation invents an oracle."""
    candidates = []
    stripped = source.strip()
    if "\n" not in stripped:
        comment = "#" if language in {"python", "bash"} else "//"
        candidates.extend([
            {"name": "comment-lookalike", "source": f"{comment} {stripped}"},
            {"name": "string-lookalike", "source": json.dumps(stripped)},
            {"name": "parenthesized", "source": f"({stripped})"},
        ])
    if "(" in stripped and stripped.endswith(")"):
        candidates.append({"name": "extended-arity", "source": stripped[:-1] + ", extra)"})
    return [{**candidate, "expected": "review"} for candidate in candidates]


def metamorph_command(path: Path) -> int:
    plan = PLAN.load_plan(path)
    cases = PLAN.validate_cases(plan["cases"])
    output = {"version": 1, "id": plan.get("id"), "candidates": []}
    for classification in ("invalid", "valid"):
        for index, source in enumerate(cases[classification]):
            for candidate in metamorphic_cases(source, plan["language"]):
                output["candidates"].append(
                    {"from": f"{classification}[{index}]", **candidate})
    print(yaml.safe_dump(output, sort_keys=False), end="")
    return 0


def validate_fix(rule_path: Path, source: str, expected: str | None = None,
                 *, allow_no_change: bool = False) -> None:
    rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    if "fix" not in rule:
        return
    try:
        extension = PLAN.LANGUAGE_EXTENSIONS[rule["language"]]
    except KeyError as error:
        raise RuntimeError(f"unsupported fixer language: {rule['language']}") from error
    with tempfile.TemporaryDirectory(prefix="rule-fix-") as directory:
        target = Path(directory) / f"source.{extension}"
        target.write_text(source, encoding="utf-8")
        before = target.read_text(encoding="utf-8")
        result = subprocess.run([str(ENGINE), "scan", "--rule", str(rule_path),
                                 "--update-all", str(target)], text=True,
                                capture_output=True, timeout=20, check=False)
        if result.returncode not in (0, 1):
            raise RuntimeError(f"FIX_FAILED: {rule['id']}: {result.stderr[-400:]}")
        after = target.read_text(encoding="utf-8")
        if after == before and not allow_no_change:
            raise RuntimeError(f"FIX_NO_CHANGE: {rule['id']}")
        if expected is not None and after != expected:
            raise RuntimeError(f"FIX_OUTPUT_MISMATCH: {rule['id']}")
        if scan_rule(rule, after):
            raise RuntimeError(f"FIX_RETAINS_FINDING: {rule['id']}")
        second = subprocess.run([str(ENGINE), "scan", "--rule", str(rule_path),
                                 "--update-all", str(target)], text=True,
                                capture_output=True, timeout=20, check=False)
        if second.returncode not in (0, 1) or target.read_text(encoding="utf-8") != after:
            raise RuntimeError(f"FIX_NOT_IDEMPOTENT: {rule['id']}")
        parse = subprocess.run(
            [str(ENGINE), "run", "-l", rule["language"], "-p", after,
             "--debug-query=sexp", "--stdin"], input="", text=True,
            capture_output=True, timeout=20, check=False,
        )
        tree = parse.stdout + parse.stderr
        if parse.returncode not in (0, 1) or re.search(r"\((?:ERROR|MISSING)\b", tree):
            raise RuntimeError(f"FIX_PARSE_FAILED: {rule['id']}")


def fixes_command(rule_id: str | None, skip_planned: bool = False) -> int:
    paths = (list(ROOT.glob(f"rules/*/*/{rule_id}.yml")) if rule_id else
             sorted((ROOT / "rules").glob("*/*/*.yml")))
    if rule_id and not paths:
        raise RuntimeError(f"unknown rule id: {rule_id}")
    checked = 0
    for path in paths:
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        if "fix" not in rule:
            continue
        plan_path = ROOT / "plans" / path.relative_to(ROOT / "rules")
        if skip_planned and plan_path.is_file():
            continue
        fixture = yaml.safe_load((ROOT / "tests" / path.relative_to(ROOT / "rules")).read_text())
        fixed_oracles = {}
        if plan_path.is_file():
            plan = PLAN.load_plan(plan_path)
            fixed_oracles = {candidate: oracle["fixed"]
                             for candidate, oracle in plan.get("oracles", {}).items()
                             if "fixed" in oracle}
        for source in fixture["invalid"]:
            validate_fix(path, source, fixed_oracles.get(source))
            checked += 1
    print(f"validated {checked} fixer fixture(s)")
    return 0


def bounded_scan_output(command: list[str], timeout: float = 300) -> bytes:
    """Capture engine JSON while enforcing a hard output-byte ceiling."""
    with tempfile.TemporaryFile() as errors:
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors) as process:
            output = bytearray()
            assert process.stdout is not None
            deadline = time.monotonic() + timeout
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        process.kill()
                        process.wait(timeout=10)
                        raise RuntimeError(f"scan exceeded {timeout:g} seconds")
                    chunk = os.read(process.stdout.fileno(), 64 * 1024)
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > MAX_SCAN_OUTPUT_BYTES:
                        process.kill()
                        process.wait(timeout=10)
                        raise RuntimeError(f"scan output exceeds {MAX_SCAN_OUTPUT_BYTES} bytes")
            try:
                returncode = process.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as error:
                process.kill()
                process.wait(timeout=10)
                raise RuntimeError(f"scan exceeded {timeout:g} seconds") from error
        errors.seek(0)
        error_text = errors.read().decode("utf-8", errors="replace")
    if returncode not in (0, 1):
        raise RuntimeError(error_text[-500:])
    return bytes(output)


def _normalize_finding(finding, root: Path) -> tuple:
    """Validate and normalize one compact ast-grep finding."""
    try:
        if not isinstance(finding, dict):
            raise TypeError
        rule_id = finding["ruleId"]
        file_name = finding["file"]
        byte_offset = finding["range"]["byteOffset"]
        start, end = byte_offset["start"], byte_offset["end"]
        if not isinstance(rule_id, str) or not isinstance(file_name, str):
            raise TypeError
        if (any(not isinstance(value, int) or isinstance(value, bool)
                for value in (start, end))
                or start < 0 or end < start):
            raise TypeError
        relative = Path(file_name).resolve().relative_to(root).as_posix()
    except (KeyError, OSError, TypeError, ValueError) as error:
        raise RuntimeError("malformed or escaped differential finding") from error
    return (rule_id, relative, start, end, finding.get("text"),
            finding.get("message"), finding.get("severity"))


def normalized_findings(engine: Path, config: Path, corpus: Path) -> list[tuple]:
    files = [path for path in corpus.rglob("*") if path.is_file()]
    if len(files) > MAX_FILES:
        raise RuntimeError(f"corpus exceeds {MAX_FILES} files")
    size = sum(path.stat().st_size for path in files)
    if size > MAX_CORPUS_BYTES:
        raise RuntimeError(f"corpus exceeds {MAX_CORPUS_BYTES} bytes")
    output = bounded_scan_output(
        [str(engine), "scan", "-c", str(config), "--json=compact", "--threads", "1",
         "--max-results", str(MAX_FINDINGS + 1), str(corpus)],
    )
    try:
        findings = json.loads(output or b"[]")
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise RuntimeError("invalid scan JSON") from error
    if not isinstance(findings, list):
        raise TypeError("invalid scan JSON: expected a finding list")
    if len(findings) > MAX_FINDINGS:
        raise RuntimeError(f"scan exceeds {MAX_FINDINGS} findings")
    root = corpus.resolve()
    return sorted(_normalize_finding(finding, root) for finding in findings)


def baseline_command(config: Path, corpus: Path, expected: Path, write: bool) -> int:
    """Check or refresh a versioned normalized finding baseline."""
    findings = [list(finding) for finding in normalized_findings(ENGINE, config, corpus)]
    observed = {"version": 1, "findings": findings}
    rendered = json.dumps(observed, indent=2, ensure_ascii=False) + "\n"
    if write:
        write_atomic(expected, rendered)
        print(f"updated differential baseline with {len(findings)} finding(s)")
        return 0
    try:
        wanted = json.loads(expected.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"cannot read differential baseline: {error}") from error
    if (not isinstance(wanted, dict) or wanted.get("version") != 1
            or not isinstance(wanted.get("findings"), list)):
        raise RuntimeError("differential baseline must contain version 1 and a findings list")
    if wanted != observed:
        print(json.dumps({"expected_count": len(wanted.get("findings", [])),
                          "observed_count": len(findings),
                          "expected_sample": wanted.get("findings", [])[:10],
                          "observed_sample": [list(finding) for finding in findings[:10]]},
                         indent=1),
              file=sys.stderr)
        return 1
    print(f"verified differential baseline with {len(findings)} finding(s)")
    return 0


def differential_command(old: Path, new: Path, config: Path, corpus: Path) -> int:
    before = normalized_findings(old, config, corpus)
    after = normalized_findings(new, config, corpus)
    before_counts, after_counts = Counter(before), Counter(after)
    removed = [{"finding": finding, "count": count}
               for finding, count in sorted((before_counts - after_counts).items())]
    added = [{"finding": finding, "count": count}
             for finding, count in sorted((after_counts - before_counts).items())]
    print(json.dumps({"old_sha256": hashlib.sha256(old.read_bytes()).hexdigest(),
                      "new_sha256": hashlib.sha256(new.read_bytes()).hexdigest(),
                      "before": len(before), "after": len(after),
                      "removed_count": sum(item["count"] for item in removed),
                      "added_count": sum(item["count"] for item in added),
                      "removed": removed[:10], "added": added[:10]}, indent=1))
    return int(bool(removed or added))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check-plans")
    sub.add_parser("regenerate-all")
    metamorph = sub.add_parser("metamorph")
    metamorph.add_argument("plan", type=Path)
    fixes = sub.add_parser("validate-fixes")
    fixes.add_argument("--rule-id")
    fixes.add_argument("--unplanned-only", action="store_true")
    diff = sub.add_parser("differential")
    diff.add_argument("--old-engine", type=Path, required=True)
    diff.add_argument("--new-engine", type=Path, default=ENGINE)
    diff.add_argument("--config", type=Path, default=ROOT / "sgconfig.yml")
    diff.add_argument("--corpus", type=Path, required=True)
    for name in ("corpus-check", "corpus-update"):
        baseline = sub.add_parser(name)
        baseline.add_argument("--config", type=Path, default=ROOT / "sgconfig.yml")
        baseline.add_argument("--corpus", type=Path, default=DIFFERENTIAL_ROOT / "corpus")
        baseline.add_argument("--expected", type=Path,
                              default=DIFFERENTIAL_ROOT / "expected.json")
    args = parser.parse_args()
    if args.command == "check-plans":
        return plans_command(False)
    if args.command == "regenerate-all":
        return plans_command(True)
    if args.command == "metamorph":
        return metamorph_command(args.plan)
    if args.command == "validate-fixes":
        return fixes_command(args.rule_id, args.unplanned_only)
    if args.command in ("corpus-check", "corpus-update"):
        return baseline_command(args.config, args.corpus, args.expected,
                                args.command == "corpus-update")
    return differential_command(args.old_engine, args.new_engine, args.config, args.corpus)


if __name__ == "__main__":
    sys.exit(main())
