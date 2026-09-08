#!/usr/bin/env python3
"""rule-probe.py -- verify one rule in isolation, with the same gates as the suite.

Why: `npm test` runs every rule and every matcher-arm mutation (~40 s) and its
output is unbounded. A rule being drafted needs a per-rule verdict in seconds,
in a shape a cheap model or a grind loop can act on without reading logs. This
replicates the suite's per-rule contracts -- fixture layout, fixture run,
exact JSON finding counts per fixture, every `any` arm killed by a fixture,
literal diagnostics, and real-file discovery -- and prints one bounded report.
Passing here is necessary, not sufficient: the full suite still runs before
commit. Pipeline: .claude/skills/astgrep-rules/references/harvest-pipeline.md

Usage:
  rule-probe.py <rule-id>            # report + exit 0/1
  rule-probe.py <rule-id> --json     # machine-readable
  rule-probe.py <rule-id> --sexp     # also dump --debug-query=sexp of each pattern
  rule-probe.py <rule-id> --snapshot # write/refresh this rule's snapshot only,
                                     # then print it for inspection

Inputs:  rules/<lang>/<cat>/<id>.yml, tests/<lang>/<cat>/<id>.yml, optional
         tests/__snapshots__/<id>-snapshot.yml, node_modules/.bin/ast-grep.
Outputs: report on stdout; exit 0 only when every check passed. Subprocess
         timeouts are failed checks, including in --json reports.
Side effects: none, except --snapshot writes tests/__snapshots__/<id>-snapshot.yml
         (scoped with --filter so no other rule's snapshot is touched).
Limits:  arm survivors are reported, not fixed; a survivor needs either a new
         fixture or a witness in tests/arm_coverage.json (see docs/authoring.md).
         Witness classifications are equivalent, missing-fixture or weak-count-oracle;
         retained witnesses must have unique (rule, path, index) identities.
         Discovery uses one file extension per language (EXTENSIONS).
Extend:  check sequence in main(); EXTENSIONS.
"""

import argparse
import copy
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
AST_GREP = ROOT / "node_modules" / ".bin" / "ast-grep"
EXTENSIONS = {"go": "go", "c": "c", "php": "php", "python": "py", "javascript": "js",
              "java": "java", "lua": "lua", "bash": "sh"}
META = re.compile(r"\$\$?\$?[A-Z_][A-Z0-9_]*")


def find_rule(rule_id: str) -> tuple[Path, Path]:
    hits = [p for p in (ROOT / "rules").rglob("*.yml") if p.stem == rule_id]
    if len(hits) != 1:
        sys.exit(f"expected exactly one rule file for {rule_id!r}, found {len(hits)}")
    rule = hits[0]
    fixture = ROOT / "tests" / rule.relative_to(ROOT / "rules")
    return rule, fixture


def any_arms(node, path=()):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "any" and isinstance(value, list) and len(value) > 1:
                for index in range(len(value)):
                    yield path + (key,), index
            yield from any_arms(value, path + (key,))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from any_arms(value, path + (index,))


def delete_arm(rule, path, index):
    mutant = copy.deepcopy(rule)
    node = mutant["rule"]
    for component in path:
        node = node[component]
    del node[index]
    return mutant


def scan_stdin(rule: dict, source: str) -> tuple[int | None, str]:
    try:
        r = subprocess.run([AST_GREP, "scan", "--inline-rules", yaml.safe_dump(rule),
                            "--stdin", "--json=compact"],
                           input=source, text=True, capture_output=True, timeout=15, check=False)
    except subprocess.TimeoutExpired as error:
        return None, f"ast-grep timed out after {error.timeout}s"
    if r.returncode not in (0, 1):
        return None, r.stderr.strip()[:300] or f"ast-grep exited {r.returncode}"
    try:
        findings = json.loads(r.stdout or "[]")
    except json.JSONDecodeError:
        return None, r.stderr.strip()[:300]
    if not isinstance(findings, list) or any(
            not isinstance(f, dict) or f.get("ruleId") != rule["id"] for f in findings):
        return None, "findings for another rule id"
    return len(findings), ""


class Isolated:
    """A throwaway sgconfig with exactly one rule, fixture and optional snapshot."""

    def __init__(self, rule_path: Path, fixture_path: Path):
        self.tmp = tempfile.TemporaryDirectory(prefix="rule-probe-", dir=ROOT)
        d = Path(self.tmp.name)
        (d / "rules").mkdir()
        (d / "tests" / "__snapshots__").mkdir(parents=True)
        self.rule = d / "rules" / rule_path.name
        self.rule.write_bytes(rule_path.read_bytes())
        (d / "tests" / rule_path.name).write_bytes(fixture_path.read_bytes())
        snap = ROOT / "tests" / "__snapshots__" / f"{rule_path.stem}-snapshot.yml"
        self.has_snapshot = snap.exists()
        if self.has_snapshot:
            (d / "tests" / "__snapshots__" / snap.name).write_bytes(snap.read_bytes())
        self.config = d / "sgconfig.yml"
        self.config.write_text("ruleDirs: [rules]\ntestConfigs: [{testDir: tests}]\n")

    def test(self, rule: dict | None = None) -> tuple[int, str]:
        if rule is not None:
            self.rule.write_text(yaml.safe_dump(rule))
        cmd: list[str] = [str(AST_GREP), "test", "-c", str(self.config)]
        if not self.has_snapshot:
            cmd.append("--skip-snapshot-tests")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        except subprocess.TimeoutExpired as error:
            return 124, f"ast-grep timed out after {error.timeout}s"
        return r.returncode, r.stdout + r.stderr

    def close(self):
        self.tmp.cleanup()


def fixture_counts(rule, valid, invalid):
    """Check each fixture independently of earlier report failures."""
    counts, multiple, passed = [], [], True
    for kind, sources in (("invalid", invalid), ("valid", valid)):
        for index, source in enumerate(sources):
            count, error = scan_stdin(rule, source)
            passed &= count is not None and (count >= 1 if kind == "invalid" else count == 0)
            detail = f"{kind}[{index}]={'ERR ' + error if count is None else count}"
            counts.append(detail)
            if kind == "invalid" and count is not None and count > 1:
                multiple.append(detail)
    return passed, "; ".join(counts), multiple


def check_witness(rule, mutant, witness):
    """Re-run both counts; a missing, equal or stale count cannot prove an arm kill."""
    baseline, baseline_error = scan_stdin(rule, witness["source"])
    deleted, deleted_error = scan_stdin(mutant, witness["source"])
    passed = (baseline is not None and deleted is not None
              and baseline == witness["expected"]
              and deleted == witness["deleted_expected"] and baseline != deleted)
    detail = f"{witness['path']}[{witness['index']}]: {baseline} -> {deleted}"
    if not passed:
        detail += f": {baseline_error} {deleted_error}"
    return passed, detail


def validate_witness_case(case):
    """Validate fields before indexing a hand-edited arm witness record."""
    if not isinstance(case, dict):
        raise TypeError("each case must be an object")
    for field in ("rule", "classification"):
        if not isinstance(case.get(field), str) or not case[field].strip():
            raise ValueError(f"case {field} must be a nonempty string")
    if case["classification"] not in ("equivalent", "missing-fixture", "weak-count-oracle"):
        raise ValueError(f"unsupported witness classification: {case['classification']!r}")
    if case["classification"] == "equivalent":
        return  # Removed alternatives have no current index or count witness.
    for field in ("path", "source"):
        if not isinstance(case.get(field), str) or not case[field].strip():
            raise ValueError(f"witness {field} must be a nonempty string")
    for field in ("index", "expected", "deleted_expected"):
        if type(case.get(field)) is not int or case[field] < 0:
            raise ValueError(f"witness {field} must be a nonnegative integer")


def arm_witnesses(rule):
    """Index retained witnesses by their current arm path and integer index."""
    coverage = ROOT / "tests/arm_coverage.json"
    document = json.loads(coverage.read_text()) if coverage.is_file() else {"cases": []}
    if not isinstance(document, dict) or not isinstance(document.get("cases"), list):
        raise TypeError("expected an object with a cases list")
    cases = document["cases"]
    identities = set()
    for case in cases:
        validate_witness_case(case)
        if case["classification"] != "equivalent":
            identity = (case["rule"], case["path"], case["index"])
            if identity in identities:
                raise ValueError(f"duplicate witness identity: {identity!r}")
            identities.add(identity)
    return {(case["path"], case["index"]): case for case in cases
            if case["rule"] == rule.get("id") and case["classification"] != "equivalent"}


def check_arms(iso, rule):
    """Require a fixture failure or a validated count witness for each arm."""
    arms = list(any_arms(rule["rule"]))
    try:
        witnesses = arm_witnesses(rule)
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        return False, f"invalid arm_coverage.json: {str(error)[:300]}"
    survivors, invalid_mutants, validated = [], [], []
    for path, index in arms:
        mutant = delete_arm(rule, path, index)
        rc, out = iso.test(mutant)
        path_name = '/'.join(map(str, path))
        ident = f"{path_name}[{index}]"
        witness = witnesses.pop((path_name, index), None)
        witnessed = False
        if witness is not None:
            witnessed, detail = check_witness(rule, mutant, witness)
            if witnessed:
                validated.append(detail)
            else:
                invalid_mutants.append(f"invalid witness {detail}")
        if rc == 0 and "test result: ok. 1 passed; 0 failed;" in out:
            if not witnessed:
                survivors.append(ident)
        elif rc != 4 or "Error: test failed." not in out:
            invalid_mutants.append(f"{ident}: exit {rc}: {out.strip()[-200:]}")
    if witnesses:
        invalid_mutants.append(f"witnesses reference missing arms: {list(witnesses)}")
    detail = f"{len(arms)} arms; survivors: {survivors or 'none'}"
    if validated:
        detail += f"; count witnesses: {validated}"
    if invalid_mutants:
        detail += f"; invalid mutants or witnesses (not kills): {invalid_mutants}"
    if survivors:
        detail += "; a survivor needs a distinguishing fixture or an arm_coverage.json witness"
    return not survivors and not invalid_mutants, detail


def discover(rule_path, language, source):
    """Check discovery using a real source extension and a one-rule config."""
    ext = EXTENSIONS.get(language)
    if ext is None:
        return False, f"unsupported discovery language {language!r}; extend EXTENSIONS"
    with tempfile.TemporaryDirectory(prefix="rule-probe-disc-", dir=ROOT) as name:
        directory = Path(name)
        (directory / "rules").mkdir()
        (directory / "rules" / rule_path.name).write_bytes(rule_path.read_bytes())
        (directory / "sgconfig.yml").write_text("ruleDirs: [rules]\n")
        target = directory / f"positive.{ext}"
        target.write_text(source)
        try:
            result = subprocess.run(
                [AST_GREP, "scan", "-c", directory / "sgconfig.yml", "--json=compact", target],
                capture_output=True, text=True, timeout=15, check=False)
        except subprocess.TimeoutExpired as error:
            return False, f"ast-grep timed out after {error.timeout}s"
        try:
            found = len(json.loads(result.stdout or "[]"))
        except json.JSONDecodeError:
            found = -1
    return found >= 1, f"positive.{ext} via ruleDirs config: {found} finding(s)"


def patterns(node):
    """Yield string and contextual patterns from matcher and utility trees."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "pattern" and isinstance(value, str):
                yield value
            elif key == "pattern" and isinstance(value, dict) and "context" in value:
                yield value["context"]
            else:
                yield from patterns(value)
    elif isinstance(node, list):
        for value in node:
            yield from patterns(value)


def pattern_expressions(rule, check):
    """Return a bounded debug view; fragment ERROR nodes are diagnostic only."""
    expressions = []
    pats = [*patterns(rule.get("rule")), *patterns(rule.get("utils"))]
    for pat in pats[:6]:
        try:
            result = subprocess.run(
                [AST_GREP, "run", "-l", rule["language"], "-p", pat,
                 "--debug-query=sexp", "--stdin"], input="x", text=True,
                capture_output=True, timeout=15, check=False)
        except subprocess.TimeoutExpired as error:
            check("pattern-expressions", False, f"ast-grep timed out after {error.timeout}s")
            return expressions
        lines = [line for line in (result.stderr + result.stdout).splitlines()
                 if line and not line.startswith("[warn]") and "postinstall" not in line]
        expressions.append({"pattern": pat, "sexp": "\n".join(lines)[:600]})
    return expressions


def load_mapping(path, check, name):
    """Keep incomplete YAML inside the probe's machine-readable report."""
    try:
        value = yaml.safe_load(path.read_text())
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        check(name, False, str(error)[:300])
        return None
    if not isinstance(value, dict):
        check(name, False, "YAML must be a mapping")
        return None
    return value


def check_snapshot(rule_id, invalid, check):
    """Match the inventory contract: snapshot mapping keys equal invalid fixtures."""
    path = ROOT / "tests" / "__snapshots__" / f"{rule_id}-snapshot.yml"
    if not path.exists():
        return True  # New rules can still use --skip-snapshot-tests.
    document = load_mapping(path, check, "snapshot-shape")
    if document is None:
        return False
    snapshots = document.get("snapshots")
    passed = isinstance(snapshots, dict) and set(snapshots) == set(invalid)
    check("snapshot-keys", passed, "snapshot mapping keys must equal the current invalid fixtures")
    return passed


def fixture_shape(fixture, rule_id):
    """Validate source lists before concatenation, hashing or indexing."""
    valid, invalid = fixture.get("valid"), fixture.get("invalid")
    return (isinstance(valid, list) and isinstance(invalid, list)
            and bool(valid) and bool(invalid) and fixture.get("id") == rule_id
            and all(isinstance(source, str) and source.strip() for source in valid + invalid)
            and not set(valid) & set(invalid))


def load_inputs(rule_path, fixture_path, check):
    """Validate local rule/fixture shape before running external checks."""
    rule = load_mapping(rule_path, check, "rule-shape")
    if rule is None:
        return None
    parts = rule_path.relative_to(ROOT / "rules").parts
    layout_ok = (len(parts) == 3 and parts[0] == rule.get("language")
                 and rule_path.stem == rule.get("id"))
    check("layout", layout_ok,
          f"rules/<language>/<category>/<id>.yml with matching id/language; got {parts}")
    if not layout_ok:
        return None
    check("fixture-exists", fixture_path.is_file(), str(fixture_path.relative_to(ROOT)))
    if not fixture_path.is_file():
        return None
    fixture = load_mapping(fixture_path, check, "fixture-shape")
    if fixture is None:
        return None
    shape_ok = fixture_shape(fixture, rule["id"])
    check("fixture-shape", shape_ok, "nonempty valid/invalid source lists, matching id, no overlap")
    if not shape_ok:
        return None
    check("matcher-is-mapping", isinstance(rule.get("rule"), dict),
          "the `rule:` body must be a mapping (scaffold TODO placeholder is not)")
    if not isinstance(rule.get("rule"), dict):
        return None
    return rule, fixture["valid"], fixture["invalid"]


def update_snapshot(rule, report, check):
    """Require the scoped update to succeed before reporting snapshot contents."""
    try:
        result = subprocess.run([AST_GREP, "test", "-c", ROOT / "sgconfig.yml",
                                 "--filter", f"^{re.escape(rule['id'])}$", "-U"],
                                capture_output=True, text=True, timeout=60, check=False, cwd=ROOT)
    except subprocess.TimeoutExpired as error:
        check("snapshot-update", False, f"ast-grep timed out after {error.timeout}s")
        return
    snap = ROOT / "tests" / "__snapshots__" / f"{rule['id']}-snapshot.yml"
    if result.returncode == 0 and snap.is_file():
        try:
            contents = snap.read_text()
        except (OSError, UnicodeError) as error:
            check("snapshot-update", False, f"cannot read refreshed snapshot {snap}: {error}")
            return
        check("snapshot-update", True, "snapshot written")
        report["snapshot"] = contents
        return
    detail = f"exit {result.returncode}: {(result.stderr + result.stdout).strip()[-300:]}"
    if not snap.is_file():
        detail += "; expected snapshot missing"
    check("snapshot-update", False, detail)


def literal_diagnostic(value):
    """Require nonempty text before checking literal diagnostic placeholders."""
    return isinstance(value, str) and bool(value.strip()) and not META.search(value)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    ap.add_argument("rule_id")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--sexp", action="store_true")
    ap.add_argument("--snapshot", action="store_true")
    args = ap.parse_args()

    rule_path, fixture_path = find_rule(args.rule_id)
    report: dict = {"rule": str(rule_path.relative_to(ROOT)), "checks": []}
    ok = True

    def check(name: str, passed: bool, detail: str = ""):
        nonlocal ok
        ok &= passed
        report["checks"].append({"name": name, "ok": passed, "detail": detail})

    check("ast-grep-available", AST_GREP.is_file(), "run npm ci to install ast-grep")
    if not AST_GREP.is_file():
        return finish(report, ok, args.json)

    # 1. layout and parseability -- the inventory test's contract
    inputs = load_inputs(rule_path, fixture_path, check)
    if inputs is None:
        return finish(report, ok, args.json)
    rule, valid, invalid = inputs

    # 2. literal diagnostics -- test_diagnostics compares emitted text to the YAML
    for field in ("message", "note"):
        check(f"{field}-literal", literal_diagnostic(rule.get(field)),
              "present and no $METAVAR interpolation (snapshots do not store it)")
    check("severity", rule.get("severity") in ("error", "warning", "info"),
          str(rule.get("severity")))

    # 3. exact counts per fixture -- what the snapshot runner cannot assert
    passed, detail, multi = fixture_counts(rule, valid, invalid)
    check("fixture-counts", passed, detail)
    if multi:
        report["checks"].append({"name": "multi-match-note", "ok": True,
                                 "detail": "invalid fixtures with >1 finding: " + ", ".join(multi)
                                 + " -- snapshot keeps only the first; assert counts separately"})

    # Refresh before the isolated run so it validates the requested snapshot.
    if args.snapshot:
        update_snapshot(rule, report, check)

    if not check_snapshot(rule["id"], invalid, check):
        return finish(report, ok, args.json)

    # 4. isolated fixture run, then arm kills -- test_arm_coverage's contract
    iso = Isolated(rule_path, fixture_path)
    try:
        rc, out = iso.test()
        tail = out.strip()[-200:] or f"no output, exit {rc}"
        check("fixture-run", rc == 0 and "1 passed; 0 failed" in out,
              ("snapshot present" if iso.has_snapshot else "no snapshot: --skip-snapshot-tests")
              + ("" if rc == 0 else " :: " + tail))
        check("arm-kills", *check_arms(iso, rule))
    finally:
        iso.close()

    # 5. discovery through a real file and config, not a string fixture
    check("discovery", *discover(rule_path, rule["language"], invalid[0]))

    # 6. optional pattern S-expressions for the author's eyes
    if args.sexp:
        report["sexp"] = pattern_expressions(rule, check)

    return finish(report, ok, args.json)


def finish(report: dict, ok: bool, as_json: bool) -> int:
    report["ok"] = ok
    if as_json:
        print(json.dumps(report, indent=1))
    else:
        print(f"{report['rule']}: {'PASS' if ok else 'FAIL'}")
        for c in report["checks"]:
            print(f"  [{'ok' if c['ok'] else 'FAIL'}] {c['name']}: {c['detail']}")
        for s in report.get("sexp", []):
            print(f"  sexp {s['pattern']!r}:\n    " + s["sexp"].replace("\n", "\n    "))
        if "snapshot" in report:
            print("  snapshot:\n    " + report["snapshot"].replace("\n", "\n    "))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
