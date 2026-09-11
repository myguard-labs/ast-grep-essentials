#!/usr/bin/env python3
"""rule-scaffold.py -- create the rule/fixture pair and the inventory bump for one rule.

Why: every new rule needs the same four mechanical edits -- rule YAML in
rules/<lang>/<category>/<id>.yml, a fixture with the same id under tests/, the
explicit rule-count guard in tests/test_diagnostics.py, and a layout that
tests/test_inventory.py accepts. A model retyping those is waste and drifts;
this script compiles one plan, preflights its contrasts, and performs the
mechanical edits atomically. Pipeline:
.claude/skills/astgrep-rules/references/harvest-pipeline.md

Usage:
  rule-scaffold.py --synthesize-plan --language python \
                   --positive 'danger(user)' --near-miss 'danger("safe")' \
                   --archetype api-argument
  rule-scaffold.py --plan /tmp/go-check.yml --check
  rule-scaffold.py --plan /tmp/go-check.yml [--dry-run]
  rule-scaffold.py --proposal WORK/cluster/proposals.jsonl --id go-x-y \\
                   --category security --claim 'Check bounds before indexing' \\
                   [--matcher matcher.yml] [--dry-run]
  rule-scaffold.py --id c-x-y --language c --category correctness \\
                   --positive 'int f(){bad();}' --near-miss 'int f(){good();}' \\
                   --claim 'Check the return value before use' [--dry-run]

Inputs:  a proposal (by --id from a proposals.jsonl) or explicit flags;
         alternatively, --plan supplies the complete versioned rule contract;
         optional --matcher, a YAML file whose top-level mapping becomes the
         rule's `rule:` body (else a TODO placeholder that will not parse as a
         rule, so an unfinished scaffold cannot pass the suite by accident);
         optional --cases, a YAML mapping of additional valid/invalid strings.
Outputs: the two YAML files; tests/test_diagnostics.py count bumped by one.
Exit:    0 written, 1 refused (invalid/conflicting inputs or lock unavailable).
Side effects: writes into the repository; --dry-run prints instead but still
              acquires the coordination lock and may create its ignored file.
              --check validates a plan and prints only a compact verdict.
Limits:  legacy message/note flags are drafts; plan prose is emitted verbatim.
Extend:  CATEGORIES, LANGUAGES.
"""

import argparse
import errno
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from contextlib import ExitStack, contextmanager
from pathlib import Path
from time import monotonic, perf_counter, sleep
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
ENGINE = ROOT / "node_modules" / ".bin" / "ast-grep"
CATEGORIES = ("security", "correctness")
LANGUAGES = ("go", "c", "php", "python", "javascript", "java", "lua", "bash")
# Unlike harvest-packets' Go/C proposal grammar, manual scaffolds support all
# LANGUAGES and one defect segment (for example go-check).
KEBAB = re.compile(r"^[a-z]+(-[a-z0-9]+)+$")
UTILITY_ID = re.compile(r"^[a-z][a-z0-9-]*$")
PLAN_KEYS = {
    "version", "id", "language", "category", "severity", "message", "note",
    "source", "match", "rule", "utils", "constraints", "labels", "fix",
    "transform", "rewriters", "files", "ignores", "url", "metadata", "cases",
    "archetype", "mutation_limit",
}
RULE_CONFIG_KEYS = (
    "constraints", "utils", "transform", "fix", "rewriters", "labels", "files",
    "ignores", "url", "metadata",
)
ARCHETYPES = ("api-argument", "missing-option", "import-sensitive", "ordered-operation")
DEBUG_AST_CACHE: dict[tuple[str, str, str], str] = {}
ENGINE_VERSION_CACHE: str | None = None
MAX_MUTATIONS = 32


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


def load_cases(path: Path) -> dict[str, list[str]]:
    """Load additional contrast cases, rejecting ambiguous fixture contracts."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        sys.exit(f"cannot read --cases {path}: {error}")
    return validate_cases(data, "--cases")


def validate_cases(data, source="cases") -> dict[str, list[str]]:
    """Validate an in-memory valid/invalid contrast matrix."""
    if not isinstance(data, dict):
        sys.exit(f"{source} must be a YAML mapping with valid/invalid lists")
    unknown = sorted((key for key in data if key not in {"valid", "invalid"}), key=str)
    if unknown:
        sys.exit(f"{source} contains unknown keys: {', '.join(map(str, unknown))}")
    result = {}
    for key in ("valid", "invalid"):
        values = data.get(key, [])
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            sys.exit(f"{source} {key} must be a list of strings")
        result[key] = values
    return result


def load_plan(path: Path) -> dict:
    """Load one complete generation plan and reject schema drift."""
    try:
        plan = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        sys.exit(f"cannot read --plan {path}: {error}")
    if not isinstance(plan, dict):
        sys.exit("--plan must be a YAML mapping")
    unknown = sorted((key for key in plan if key not in PLAN_KEYS), key=str)
    if unknown:
        sys.exit(f"--plan contains unknown keys: {', '.join(map(str, unknown))}")
    if plan.get("version") != 1:
        sys.exit("--plan version must be 1")
    return plan


def compile_match(spec) -> dict:
    """Compile target/facts/exclusions/alternatives into an ordered rule object."""
    if not isinstance(spec, dict):
        sys.exit("--plan match must be a mapping")
    allowed = {"target", "require", "exclude", "any"}
    unknown = sorted((key for key in spec if key not in allowed), key=str)
    if unknown:
        sys.exit(f"--plan match contains unknown keys: {', '.join(map(str, unknown))}")
    target = spec.get("target")
    if not isinstance(target, dict) or not target:
        sys.exit("--plan match.target must be a non-empty rule mapping")
    clauses = [target]
    for key in ("require", "exclude", "any"):
        values = plan_rule_list(spec, key)
        if key == "require":
            clauses.extend(values)
        elif key == "exclude":
            clauses.extend({"not": value} for value in values)
        elif values:
            clauses.append({"any": [value.get("rule", value) for value in values]})
    return target if len(clauses) == 1 else {"all": clauses}


def plan_rule_list(spec: dict, key: str) -> list[dict]:
    """Return one validated list of rule objects from a match specification."""
    values = spec.get(key, [])
    valid = isinstance(values, list) and all(isinstance(value, dict) and value for value in values)
    if key == "any" and valid:
        rich = ["name" in value or "rule" in value or "witness" in value for value in values]
        if any(rich) and not all(rich):
            sys.exit("--plan match.any cannot mix named and unnamed branches")
        if any(rich):
            valid = all(
                set(value) == {"name", "rule", "witness"}
                and isinstance(value["name"], str) and UTILITY_ID.fullmatch(value["name"])
                and isinstance(value["rule"], dict) and value["rule"]
                and isinstance(value["witness"], str) and value["witness"]
                for value in values
            )
            names = [value.get("name") for value in values]
            if valid and len(names) != len(set(names)):
                sys.exit("--plan match.any branch names must be unique")
            if valid and len(values) < 2:
                sys.exit("--plan named match.any requires at least two branches")
    if not valid:
        sys.exit(f"--plan match.{key} must be a list of non-empty rule mappings")
    return values


def engine_version() -> str:
    """Return the pinned engine identity used in parser-cache keys."""
    global ENGINE_VERSION_CACHE
    if ENGINE_VERSION_CACHE is not None:
        return ENGINE_VERSION_CACHE
    try:
        result = subprocess.run(
            [str(ENGINE), "--version"], text=True, capture_output=True, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        sys.exit(f"cannot query pinned ast-grep engine: {error}")
    if result.returncode != 0:
        sys.exit("cannot query pinned ast-grep engine version")
    ENGINE_VERSION_CACHE = result.stdout.strip()
    return ENGINE_VERSION_CACHE


def debug_ast(language: str, source: str) -> str:
    """Parse source once per engine/language/digest and return bounded debug AST."""
    version = engine_version()
    digest = hashlib.sha256(source.encode()).hexdigest()
    key = (version, language, digest)
    if key in DEBUG_AST_CACHE:
        return DEBUG_AST_CACHE[key]
    with tempfile.TemporaryDirectory(prefix="rule-ast-") as directory:
        fixture = Path(directory) / "source"
        fixture.write_text(source, encoding="utf-8")
        try:
            result = subprocess.run(
                [str(ENGINE), "run", "-l", language, "-p", source, "--debug-query=ast",
                 str(fixture)], text=True, capture_output=True, timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            sys.exit(f"PAIR_PARSE_FAILED: {error}")
    output = result.stdout + result.stderr
    if result.returncode not in (0, 1) or "Debug AST:" not in output:
        sys.exit("PAIR_PARSE_FAILED: pinned engine returned no debug AST")
    DEBUG_AST_CACHE[key] = output[-64_000:]
    return DEBUG_AST_CACHE[key]


def ast_facts(debug: str) -> list[dict[str, str]]:
    """Extract ordered kind/field facts from ast-grep's stable debug tree format."""
    facts = []
    for line in debug.splitlines():
        match = re.match(r"\s*(?:(?P<field>[a-zA-Z_][\w-]*): )?(?P<kind>[A-Za-z_][\w-]*) \(", line)
        if match and match.group("kind") not in {"ERROR", "MISSING"}:
            fact = {"kind": match.group("kind")}
            if match.group("field"):
                fact["field"] = match.group("field")
            facts.append(fact)
    return facts


def synthesize_plan(language: str, positive: str, near_miss: str, archetype: str) -> dict:
    """Emit reviewable candidate facts from a positive/near-miss parser contrast."""
    if archetype not in ARCHETYPES:
        sys.exit(f"unsupported archetype {archetype!r}")
    positive_facts = ast_facts(debug_ast(language, positive))
    near_facts = ast_facts(debug_ast(language, near_miss))
    if not positive_facts or not near_facts:
        sys.exit("PAIR_PARSE_FAILED: source produced no named AST facts")
    near_pairs = {(fact.get("field"), fact["kind"]) for fact in near_facts}
    distinguishing = [
        fact for fact in positive_facts if (fact.get("field"), fact["kind"]) not in near_pairs
    ]
    common = [fact for fact in positive_facts
              if (fact.get("field"), fact["kind"]) in near_pairs]
    roots = {"module", "program", "source_file", "translation_unit", "chunk",
             "expression_statement"}
    call_kinds = {"call", "call_expression", "function_call", "invocation_expression"}
    target = next((fact for fact in common if fact["kind"] in call_kinds), None)
    target = target or next(
        (fact for fact in common if fact["kind"] not in roots), positive_facts[0]
    )
    contextual = {"context": positive, "selector": target["kind"]}
    require = []
    if archetype == "import-sensitive":
        imports = [fact for fact in positive_facts if "import" in fact["kind"]]
        if imports:
            require = [{"inside": {
                "kind": positive_facts[0]["kind"], "has": dict(imports[0]), "stopBy": "end",
            }}]
    elif archetype == "ordered-operation":
        require = [{"follows": {"pattern": near_miss, "stopBy": "neighbor"}}]
    elif archetype == "missing-option":
        require = [{"not": {"pattern": near_miss}}]
    return {
        "version": 1,
        "archetype": archetype,
        "match": {"target": {"pattern": contextual}, "require": require},
        "cases": {"invalid": [positive], "valid": [near_miss]},
        "metadata": {"candidateFacts": {
            "target": dict(target), "positiveOnly": [dict(fact) for fact in distinguishing[:8]],
        }},
    }


def named_any_branches(plan: dict) -> list[dict]:
    """Return generator-only named branches, if the v1 plan uses them."""
    match = plan.get("match", {})
    branches = match.get("any", []) if isinstance(match, dict) else []
    return branches if branches and all("name" in branch for branch in branches) else []


def validate_named_witnesses(plan: dict, cases: dict[str, list[str]]) -> None:
    """Require one distinct invalid fixture for every named alternative."""
    branches = named_any_branches(plan)
    witnesses = [branch["witness"] for branch in branches]
    if len(witnesses) != len(set(witnesses)):
        sys.exit("ANY_WITNESS_DUPLICATE: named branches require distinct witnesses")
    missing = [branch["name"] for branch in branches if branch["witness"] not in cases["invalid"]]
    if missing:
        sys.exit(f"ANY_WITNESS_MISSING: {', '.join(missing)}")


def iter_matches(value):
    """Yield local utility identifiers referenced by nested rule objects."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "matches":
                if not isinstance(child, str):
                    sys.exit("--plan supports string local utility references in matches")
                yield child
            else:
                yield from iter_matches(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_matches(child)


def validate_plan_utils(plan: dict, matcher: dict) -> None:
    """Reject malformed, reserved, or unresolved local utility rules."""
    utils = plan.get("utils", {})
    if not isinstance(utils, dict):
        sys.exit("--plan utils must be a mapping")
    invalid_ids = sorted(
        key for key in utils
        if not isinstance(key, str) or not UTILITY_ID.fullmatch(key)
    )
    if invalid_ids:
        sys.exit(f"--plan has invalid utility ids: {', '.join(map(str, invalid_ids))}")
    if any(not isinstance(rule, dict) or not rule for rule in utils.values()):
        sys.exit("--plan utility values must be non-empty rule mappings")
    references = set(iter_matches(matcher))
    for rule in utils.values():
        references.update(iter_matches(rule))
    missing = sorted(references - set(utils))
    if missing:
        sys.exit(f"--plan references undefined local utilities: {', '.join(missing)}")


def validate_plan_constraints(plan: dict, matcher: dict) -> None:
    """Reject malformed constraints and names the matcher never binds."""
    constraints = plan.get("constraints", {})
    if not isinstance(constraints, dict):
        sys.exit("--plan constraints must be a mapping")
    if any(not isinstance(key, str) or not key
           or not isinstance(value, dict) or not value
           for key, value in constraints.items()):
        sys.exit("--plan constraints require named, non-empty rule mappings")
    binding_rules = [matcher]
    utils = plan.get("utils", {})
    pending = list(iter_matches(matcher))
    visited = set()
    while pending:
        utility_id = pending.pop()
        if utility_id in visited or utility_id not in utils:
            continue
        visited.add(utility_id)
        binding_rules.append(utils[utility_id])
        pending.extend(iter_matches(utils[utility_id]))
    matcher_text = yaml.safe_dump(binding_rules, sort_keys=False)
    bindings = {
        key: re.compile(rf"(?<!\$)\${re.escape(key)}(?![A-Z0-9_])")
        for key in constraints
    }
    unbound = sorted(key for key, binding in bindings.items()
                     if binding.search(matcher_text) is None)
    if unbound:
        sys.exit(f"--plan constraints are not bound by rule: {', '.join(unbound)}")


def validate_plan_rules(plan: dict, matcher: dict) -> None:
    """Catch invalid utility references and unbound top-level constraints early."""
    validate_plan_utils(plan, matcher)
    validate_plan_constraints(plan, matcher)


def validate_plan_header(plan: dict) -> None:
    """Validate required plan metadata before compiling the matcher."""
    required = ("id", "language", "category", "message", "note", "cases")
    missing = [key for key in required if key not in plan]
    if missing:
        sys.exit(f"--plan missing required keys: {', '.join(missing)}")
    for key in ("id", "language", "category", "message", "note"):
        if not isinstance(plan[key], str) or not plan[key].strip():
            sys.exit(f"--plan {key} must be a non-empty string")
    if plan.get("severity", "warning") not in ("error", "warning", "info"):
        sys.exit("--plan severity must be error, warning or info")
    if "archetype" in plan and plan["archetype"] not in ARCHETYPES:
        sys.exit(f"--plan archetype must be one of {', '.join(ARCHETYPES)}")
    limit = plan.get("mutation_limit", 0)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 0 <= limit <= MAX_MUTATIONS:
        sys.exit(f"--plan mutation_limit must be an integer from 0 to {MAX_MUTATIONS}")


def plan_matcher(plan: dict) -> dict:
    """Select and validate the raw or fact-compiled main matcher."""
    if ("rule" in plan) == ("match" in plan):
        sys.exit("--plan requires exactly one of rule or match")
    matcher = plan["rule"] if "rule" in plan else compile_match(plan["match"])
    if not isinstance(matcher, dict) or not matcher:
        sys.exit("--plan rule must be a non-empty mapping")
    return matcher


def plan_cases(plan: dict) -> dict[str, list[str]]:
    """Validate the required complete contrast matrix."""
    cases = validate_cases(plan["cases"], "--plan cases")
    if not cases["valid"] or not cases["invalid"]:
        sys.exit("--plan cases requires at least one valid and one invalid source")
    for key in ("valid", "invalid"):
        if len(set(cases[key])) != len(cases[key]):
            sys.exit(f"--plan cases contains duplicate {key} sources")
    if set(cases["valid"]) & set(cases["invalid"]):
        sys.exit("the same source cannot be both valid and invalid")
    return cases


def apply_plan(args) -> None:
    """Populate normal scaffold arguments from a validated single-file plan."""
    plan_path = getattr(args, "plan", None)
    if not plan_path:
        args.plan_data = None
        args.matcher_data = None
        args.cases_data = None
        return
    conflicting = (
        args.id, args.proposal, args.language, args.category, args.positive,
        args.near_miss, args.claim, args.matcher, args.cases,
    )
    if any(value is not None for value in conflicting) or args.severity is not None:
        sys.exit("--plan cannot be combined with rule input flags")
    plan = load_plan(plan_path)
    validate_plan_header(plan)
    matcher = plan_matcher(plan)
    cases = plan_cases(plan)
    validate_named_witnesses(plan, cases)
    validate_plan_rules(plan, matcher)
    args.id = plan["id"]
    args.language = plan["language"]
    args.category = plan["category"]
    args.claim = plan["message"]
    args.severity = plan.get("severity", "warning")
    args.positive = cases["invalid"][0]
    args.near_miss = cases["valid"][0]
    args.matcher_data = matcher
    args.cases_data = {
        "invalid": cases["invalid"][1:], "valid": cases["valid"][1:]
    }
    args.plan_data = plan


def run_preflight(rule_text: str, cases: dict[str, list[str]], rule_id: str) -> tuple[bool, str]:
    """Run one isolated fixture suite and return its bounded result."""
    started = perf_counter()
    with tempfile.TemporaryDirectory(prefix="rule-plan-") as directory:
        root = Path(directory)
        (root / "rules").mkdir()
        (root / "tests").mkdir()
        (root / "rules" / f"{rule_id}.yml").write_text(rule_text, encoding="utf-8")
        (root / "tests" / f"{rule_id}.yml").write_text(
            yaml.safe_dump({"id": rule_id, **cases}, sort_keys=False), encoding="utf-8"
        )
        config = root / "sgconfig.yml"
        config.write_text(
            "ruleDirs: [rules]\ntestConfigs: [{testDir: tests}]\n", encoding="utf-8"
        )
        try:
            result = subprocess.run(
                [str(ENGINE), "test", "--include-off", "-c", str(config),
                 "--skip-snapshot-tests"], text=True, capture_output=True, timeout=15,
                 check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return False, f"engine-error={error}"
    output = result.stdout + result.stderr
    lines = [line for line in output.splitlines() if line and not line.startswith("[warn]")]
    detail = " | ".join(lines[-6:])[:600]
    elapsed_ms = int((perf_counter() - started) * 1000)
    metrics = f"processes=1 elapsed_ms={elapsed_ms} output_bytes={len(output)}"
    if result.returncode == 0:
        return True, f"{metrics} {detail}".strip()
    failure = "test-failure" if "Error: test failed." in output else "engine-error"
    return False, f"{metrics} {failure}={detail}".strip()


def render_rule_for_match(plan: dict, matcher: dict) -> str:
    """Render a temporary rule while retaining its complete configuration."""
    rule = {
        "id": plan["id"], "language": plan["language"],
        "severity": plan.get("severity", "warning"), "message": plan["message"],
        "note": plan["note"],
    }
    for key in RULE_CONFIG_KEYS:
        if key in plan:
            rule[key] = plan[key]
    rule["rule"] = matcher
    return yaml.safe_dump(rule, sort_keys=False)


def preflight_named_arms(plan: dict, cases: dict[str, list[str]]) -> None:
    """Delete each named arm and require its dedicated witness to fail."""
    branches = named_any_branches(plan)
    for index, branch in enumerate(branches):
        mutant = dict(plan["match"])
        mutant["any"] = [candidate["rule"] for offset, candidate in enumerate(branches)
                         if offset != index]
        matcher = compile_match(mutant)
        witness_cases = {"invalid": [branch["witness"]], "valid": cases["valid"][:1]}
        passed, detail = run_preflight(
            render_rule_for_match(plan, matcher), witness_cases, plan["id"],
        )
        if passed:
            sys.exit(f"ANY_ARM_SURVIVED: {branch['name']}")
        if "engine-error=" in detail:
            sys.exit(f"ANY_ARM_PREFLIGHT_ERROR: {branch['name']}: {detail}")


def mutation_candidates(value, path="rule"):
    """Yield bounded claim-bearing clause weakenings with stable path names."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"field", "stopBy"}:
                mutant = dict(value)
                del mutant[key]
                yield f"{path}.{key}", mutant
            elif key == "regex" and isinstance(child, str) and (
                    child.startswith("^") or child.endswith("$")):
                mutant = dict(value)
                mutant[key] = child.removeprefix("^").removesuffix("$")
                yield f"{path}.regex-anchor", mutant
            for child_path, child_mutant in mutation_candidates(child, f"{path}.{key}"):
                mutant = dict(value)
                mutant[key] = child_mutant
                yield child_path, mutant
    elif isinstance(value, list):
        for index, child in enumerate(value):
            for child_path, child_mutant in mutation_candidates(child, f"{path}[{index}]"):
                mutant = list(value)
                mutant[index] = child_mutant
                yield child_path, mutant


def preflight_clause_mutations(plan: dict, cases: dict[str, list[str]]) -> None:
    """Require selected regex/field/traversal clauses to be killed by contrasts."""
    limit = plan.get("mutation_limit", 0)
    if not limit:
        return
    matcher = plan_matcher(plan)
    candidates = list(mutation_candidates(matcher))[:limit]
    for path, mutant in candidates:
        passed, detail = run_preflight(
            render_rule_for_match(plan, mutant), cases, plan["id"],
        )
        if passed:
            sys.exit(f"MUTATION_SURVIVED: {path}")
        if "engine-error=" in detail:
            sys.exit(f"MUTATION_PREFLIGHT_ERROR: {path}: {detail}")


def preflight_plan(rule_text: str, cases: dict[str, list[str]], rule_id: str,
                   plan: dict | None = None) -> None:
    """Check the complete contrast matrix in one pinned-engine process."""
    if not ENGINE.is_file():
        sys.exit(f"pinned ast-grep engine is missing: {ENGINE}; run npm ci")
    passed, detail = run_preflight(rule_text, cases, rule_id)
    if not passed and "engine-error=" in detail:
        sys.exit(f"CONTRAST_PREFLIGHT_ERROR: {detail}")
    if not passed:
        sys.exit(f"CONTRAST_PREFLIGHT_FAILED: contrast preflight failed: {detail}")
    if plan is not None:
        preflight_named_arms(plan, cases)
        preflight_clause_mutations(plan, cases)


def merge_cases(primary: str, extras: list[str], label: str) -> list[LiteralStr]:
    """Preserve input order while rejecting duplicate fixture cases."""
    values = [primary, *extras]
    if len(set(values)) != len(values):
        sys.exit(f"duplicate {label} source in --cases")
    return [LiteralStr(value) for value in values]


def build_fixture(rule_id: str, positive: str, near_miss: str,
                  cases_path: Path | None, cases_data=None) -> dict:
    """Build an ordered fixture and reject duplicate or contradictory cases."""
    cases = cases_data if cases_data is not None else (
        load_cases(cases_path) if cases_path else {"valid": [], "invalid": []}
    )
    valid = merge_cases(near_miss, cases["valid"], "valid")
    invalid = merge_cases(positive, cases["invalid"], "invalid")
    if set(valid) & set(invalid):
        sys.exit("the same source cannot be both valid and invalid")
    return {"id": rule_id, "valid": valid, "invalid": invalid}


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
    if args.category not in CATEGORIES:
        sys.exit(f"unsupported category {args.category!r}")
    prefixes = ("c-", "nginx-") if language == "c" else (f"{language}-",)
    if not args.id.startswith(prefixes):
        sys.exit(f"id {args.id!r} must be prefixed with its language")

    rule_path, fixture_path = scaffold_paths(args.id, language, args.category)
    rendered = render_scaffold(args, prop, language, positive, near_miss, claim)
    if getattr(args, "plan_data", None):
        preflight_plan(rendered[0], args.plan_data["cases"], args.id, args.plan_data)
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

    matcher_data = getattr(args, "matcher_data", None)
    if matcher_data is not None:
        matcher = matcher_data
    elif args.matcher:
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

    plan = getattr(args, "plan_data", None) or {}
    rule = {
        "id": args.id, "language": language, "severity": args.severity,
        "message": claim,
        "note": plan.get(
            "note", prop.get("rationale", "TODO: when to dismiss, and the semantic limit.")
        ),
    }
    for key in RULE_CONFIG_KEYS:
        if key in plan:
            rule[key] = plan[key]
    rule["rule"] = matcher
    fixture = build_fixture(
        args.id, positive, near_miss, getattr(args, "cases", None),
        getattr(args, "cases_data", None),
    )
    origin_comment = (
        "# MyGuard rule: https://github.com/myguard-labs/ast-grep-essentials | "
        "https://deb.myguard.nl\n"
    )
    if plan.get("source"):
        source = plan["source"]
        expected = r"https://github\.com/coderabbitai/ast-grep-essentials(?:/[^\s]*)?"
        if not isinstance(source, str) or not re.fullmatch(expected, source):
            sys.exit("--plan source must be a CodeRabbit ast-grep-essentials URL")
        origin_comment += f"# CodeRabbit source: {source}\n"
    rule_text = origin_comment + yaml.dump(
        rule, sort_keys=False, width=80, allow_unicode=True
    )
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
    ap.add_argument("--plan", type=Path, help="versioned complete rule-generation plan")
    ap.add_argument("--synthesize-plan", action="store_true",
                    help="emit parser-assisted v1 candidate facts from one contrast pair")
    ap.add_argument("--archetype", choices=ARCHETYPES, default="api-argument")
    ap.add_argument("--id")
    ap.add_argument("--proposal", type=Path, help="proposals.jsonl to read --id from")
    ap.add_argument("--language", choices=LANGUAGES)
    ap.add_argument("--category", choices=CATEGORIES)
    ap.add_argument("--positive", help="source that must match")
    ap.add_argument("--near-miss", help="source that must not match")
    ap.add_argument("--claim", help="one-sentence syntactic claim (message draft)")
    ap.add_argument("--matcher", type=Path, help="YAML file: the `rule:` body")
    ap.add_argument("--cases", type=Path,
                    help="YAML mapping of extra valid/invalid fixture strings")
    ap.add_argument("--severity", choices=("error", "warning", "info"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--check", action="store_true",
                    help="validate --plan and print a compact verdict without writing")
    args = ap.parse_args()
    if getattr(args, "synthesize_plan", False):
        conflicts = (args.plan, args.id, args.proposal, args.category, args.claim, args.matcher,
                     args.cases, args.severity, args.dry_run, args.check)
        if any(conflicts) or not args.language or args.positive is None or args.near_miss is None:
            ap.error("--synthesize-plan requires only --language, --positive, --near-miss "
                     "and optional --archetype")
        print(yaml.safe_dump(
            synthesize_plan(args.language, args.positive, args.near_miss, args.archetype),
            sort_keys=False,
        ), end="")
        return 0
    apply_plan(args)
    if not getattr(args, "plan", None):
        if not args.id or not args.category:
            ap.error("--id and --category are required without --plan")
        args.severity = args.severity or "warning"
    if getattr(args, "check", False):
        if not getattr(args, "plan", None):
            ap.error("--check requires --plan")
        if args.dry_run:
            ap.error("--check cannot be combined with --dry-run")
        with cli_scaffold_lock():
            prepare_scaffold(args)
            bump_count(dry_run=True)
        cases = args.plan_data["cases"]
        print(f"plan ok: {args.id}; {len(cases['invalid'])} invalid, "
              f"{len(cases['valid'])} valid; no files written")
        return 0

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
