#!/usr/bin/env python3
"""Compile and preflight one canonical ast-grep rule plan."""

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from time import perf_counter

import yaml

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "node_modules" / ".bin" / "ast-grep"
LANGUAGE_EXTENSIONS = {
    "bash": "sh", "c": "c", "cpp": "cpp", "csharp": "cs", "go": "go",
    "html": "html", "java": "java", "javascript": "js", "kotlin": "kt",
    "lua": "lua", "php": "php", "python": "py", "ruby": "rb", "rust": "rs",
    "scala": "scala", "swift": "swift", "typescript": "ts",
}
LANGUAGES = tuple(LANGUAGE_EXTENSIONS)
CATEGORIES = ("security", "correctness")
MAX_MUTATIONS = 256
MAX_PREFLIGHT_SECONDS = 300
MAX_ENGINE_SECONDS = 20
UTILITY_ID = re.compile(r"^[a-z][a-z0-9-]*$")
PLAN_ID = re.compile(r"^[a-z][a-z0-9_-]*$")
PLAN_KEYS = {
    "version", "id", "language", "category", "severity", "message", "note",
    "match", "rule", "utils", "constraints", "labels", "fix",
    "transform", "rewriters", "files", "ignores", "url", "metadata", "cases",
    "mutation_limit", "mutation_exclusions", "oracles", "comments", "extensions",
}
RULE_CONFIG_KEYS = (
    "constraints", "utils", "transform", "fix", "rewriters", "labels", "files",
    "ignores", "url", "metadata",
)


class LiteralStr(str):
    """Render multiline fixture sources as readable YAML blocks."""


class FoldedStr(str):
    """Render diagnostic prose as readable folded YAML."""


def _literal(dumper, data):
    return dumper.represent_scalar(
        "tag:yaml.org,2002:str", data, style="|" if "\n" in data else None,
    )


yaml.add_representer(LiteralStr, _literal)
yaml.SafeDumper.add_representer(
    FoldedStr,
    lambda dumper, data: dumper.represent_scalar("tag:yaml.org,2002:str", data, style=">"),
)


def load_plan(path: Path) -> dict:
    """Load a closed v1 plan schema."""
    try:
        plan = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ValueError(f"cannot read plan {path}: {error}") from error
    if not isinstance(plan, dict):
        raise TypeError("plan must be a YAML mapping")
    unknown = sorted(set(plan) - PLAN_KEYS, key=str)
    if unknown:
        raise ValueError(f"plan contains unknown keys: {', '.join(map(str, unknown))}")
    if plan.get("version") != 1:
        raise ValueError("plan version must be 1")
    return plan


def _validate_comments_extensions(plan: dict) -> None:
    """Validate generated comments and non-native top-level rule keys."""
    comments = plan.get("comments", [])
    if (not isinstance(comments, list)
            or any(not isinstance(item, str) or not item.strip()
                   or item.splitlines() != [item]
                   for item in comments)):
        raise ValueError("comments must be single-line non-empty strings")
    extensions = plan.get("extensions", {})
    reserved = {"id", "language", "severity", "message", "note", "rule", *RULE_CONFIG_KEYS}
    if (not isinstance(extensions, dict)
            or any(not isinstance(key, str) or not key or key in reserved
                   for key in extensions)):
        raise ValueError("extensions must use non-reserved string keys")


def _validate_mutation_settings(plan: dict) -> None:
    """Validate bounded mutation selection and documented exclusions."""
    limit = plan.get("mutation_limit", MAX_MUTATIONS)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_MUTATIONS:
        raise ValueError(f"mutation_limit must be from 1 through {MAX_MUTATIONS}")
    exclusions = plan.get("mutation_exclusions", {})
    if (not isinstance(exclusions, dict)
            or any(not isinstance(key, str) or not key
                   or not isinstance(reason, str) or not reason.strip()
                   for key, reason in exclusions.items())):
        raise ValueError("mutation_exclusions must map paths to non-empty rationales")


def validate_header(plan: dict) -> None:
    """Validate required metadata and bounded mutation settings."""
    required = ("id", "language", "category", "message", "note", "cases")
    missing = [key for key in required if key not in plan]
    if missing:
        raise ValueError(f"plan missing required keys: {', '.join(missing)}")
    for key in ("id", "message", "note"):
        if not isinstance(plan[key], str) or not plan[key].strip():
            raise ValueError(f"plan {key} must be a non-empty string")
    if not PLAN_ID.fullmatch(plan["id"]):
        raise ValueError(
            "plan id must start with a lowercase letter and use only "
            "lowercase letters, digits, underscores and hyphens"
        )
    if plan["language"] not in LANGUAGES:
        raise ValueError(f"unsupported plan language: {plan['language']}")
    if plan["category"] not in CATEGORIES:
        raise ValueError(f"unsupported plan category: {plan['category']}")
    if plan.get("severity", "warning") not in ("error", "warning", "info"):
        raise ValueError("plan severity must be error, warning or info")
    _validate_comments_extensions(plan)
    _validate_mutation_settings(plan)


def validate_cases(data) -> dict[str, list[str]]:
    """Validate a complete, non-contradictory contrast matrix."""
    if not isinstance(data, dict) or set(data) != {"valid", "invalid"}:
        raise ValueError("cases must contain exactly valid and invalid lists")
    result = {}
    for key in ("valid", "invalid"):
        values = data[key]
        if (not isinstance(values, list) or not values
                or any(not isinstance(value, str) or not value.strip() for value in values)):
            raise ValueError(f"cases {key} must be a non-empty list of source strings")
        if len(values) != len(set(values)):
            raise ValueError(f"cases contains duplicate {key} sources")
        result[key] = values
    if set(result["valid"]) & set(result["invalid"]):
        raise ValueError("the same source cannot be valid and invalid")
    return result


def _validate_named_branch(value: dict) -> str:
    if set(value) != {"name", "rule", "witness"}:
        raise ValueError("named match.any branch has invalid shape")
    name, rule, witness = value["name"], value["rule"], value["witness"]
    if not isinstance(name, str) or not UTILITY_ID.fullmatch(name):
        raise ValueError("named match.any branch has invalid shape")
    if not isinstance(rule, dict) or not rule:
        raise ValueError("named match.any branch has invalid shape")
    if not isinstance(witness, str) or not witness:
        raise ValueError("named match.any branch has invalid shape")
    return name


def _validate_named_branches(values: list[dict]) -> None:
    rich = [bool({"name", "rule", "witness"} & set(value)) for value in values]
    if not all(rich):
        raise ValueError("match.any cannot mix named and unnamed branches")
    if len(values) < 2:
        raise ValueError("named match.any needs at least two branches")
    names = [_validate_named_branch(value) for value in values]
    if len(names) != len(set(names)):
        raise ValueError("match.any branch names must be unique")


def _rule_list(spec: dict, key: str) -> list[dict]:
    values = spec.get(key, [])
    if not isinstance(values, list) or any(not isinstance(value, dict) or not value
                                           for value in values):
        raise ValueError(f"match.{key} must be a list of non-empty rule mappings")
    if key == "any" and values:
        rich = any({"name", "rule", "witness"} & set(value) for value in values)
        if rich:
            _validate_named_branches(values)
    return values


def compile_match(spec: dict) -> dict:
    """Compile target/require/exclude/any facts into ordered matcher YAML."""
    if not isinstance(spec, dict) or set(spec) - {"target", "require", "exclude", "any"}:
        raise ValueError("match must use only target, require, exclude and any")
    target = spec.get("target")
    if not isinstance(target, dict) or not target:
        raise ValueError("match.target must be a non-empty rule mapping")
    clauses = [target]
    clauses.extend(_rule_list(spec, "require"))
    clauses.extend({"not": rule} for rule in _rule_list(spec, "exclude"))
    alternatives = _rule_list(spec, "any")
    if alternatives:
        clauses.append({"any": [value.get("rule", value) for value in alternatives]})
    return target if len(clauses) == 1 else {"all": clauses}


def plan_matcher(plan: dict) -> dict:
    """Resolve exactly one raw or fact-compiled matcher."""
    if ("rule" in plan) == ("match" in plan):
        raise ValueError("plan requires exactly one of rule or match")
    matcher = plan["rule"] if "rule" in plan else compile_match(plan["match"])
    if not isinstance(matcher, dict) or not matcher:
        raise ValueError("plan matcher must be a non-empty mapping")
    return matcher


def iter_matches(value):
    """Yield local utility identifiers referenced by a nested rule."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "matches":
                if not isinstance(child, str):
                    raise ValueError("matches must reference a string utility id")
                yield child
            else:
                yield from iter_matches(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_matches(child)


def validate_utilities(plan: dict, matcher: dict) -> None:
    """Reject invalid, missing, cyclic, and unreachable local utilities."""
    utilities = plan.get("utils", {})
    if not isinstance(utilities, dict):
        raise TypeError("utils must be a mapping")
    if any(not isinstance(key, str) or not UTILITY_ID.fullmatch(key)
           or not isinstance(value, dict) or not value for key, value in utilities.items()):
        raise ValueError("utils require valid ids and non-empty rule mappings")
    graph = {key: set(iter_matches(value)) for key, value in utilities.items()}
    constraint_roots = set(iter_matches(plan.get("constraints", {})))
    matcher_roots = set(iter_matches(matcher))
    references = matcher_roots | constraint_roots | {
        item for values in graph.values() for item in values
    }
    missing = sorted(references - set(utilities))
    if missing:
        raise ValueError(f"undefined local utilities: {', '.join(missing)}")
    reached, active = set(), set()

    def visit(key: str) -> None:
        if key in active:
            raise ValueError(f"utility dependency cycle at {key}")
        if key in reached:
            return
        active.add(key)
        for dependency in graph[key]:
            visit(dependency)
        active.remove(key)
        reached.add(key)

    for root in matcher_roots | constraint_roots:
        visit(root)
    unused = sorted(set(utilities) - reached)
    if unused:
        raise ValueError(f"unreachable local utilities: {', '.join(unused)}")


def validate_constraints(plan: dict, matcher: dict) -> None:
    """Require well-formed constraints bound by the reachable matcher tree."""
    constraints = plan.get("constraints", {})
    if not isinstance(constraints, dict) or any(
            not isinstance(key, str) or not key or not isinstance(value, dict) or not value
            for key, value in constraints.items()):
        raise ValueError("constraints require named, non-empty rule mappings")
    utilities = plan.get("utils", {})
    trees, pending, visited = [matcher], list(iter_matches(matcher)), set()
    while pending:
        key = pending.pop()
        if key in visited:
            continue
        visited.add(key)
        trees.append(utilities[key])
        pending.extend(iter_matches(utilities[key]))
    source = yaml.safe_dump(trees, sort_keys=False)
    unbound = [key for key in constraints
               if re.search(rf"(?<!\$)\${re.escape(key)}(?![A-Z0-9_])", source) is None]
    if unbound:
        raise ValueError(f"constraints are not bound by rule: {', '.join(sorted(unbound))}")


def _valid_offset(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _validate_string_list(expected: dict, key: str) -> None:
    value = expected.get(key)
    if key in expected and (not isinstance(value, list)
                            or any(not isinstance(item, str) for item in value)):
        raise ValueError(f"oracle {key} must be a list of strings")


def _validate_ranges(ranges) -> None:
    if ranges is None:
        return
    valid = isinstance(ranges, list) and all(
        isinstance(item, list) and len(item) == 2
        and all(_valid_offset(offset) for offset in item) for item in ranges
    )
    if not valid:
        raise ValueError("oracle ranges must be byte-offset pairs")


def _validate_oracle(source, expected, known: set[str]) -> None:
    allowed = {"count", "texts", "ranges", "message", "note", "severity", "labels", "fixed"}
    if source not in known or not isinstance(expected, dict) or not expected:
        raise ValueError("oracle needs a known source and non-empty mapping")
    unknown = sorted(set(expected) - allowed)
    if unknown:
        raise ValueError(f"oracle contains unknown keys: {', '.join(unknown)}")
    if "count" in expected and not _valid_offset(expected["count"]):
        raise ValueError("oracle count must be a nonnegative integer")
    for key in ("texts", "labels"):
        _validate_string_list(expected, key)
    _validate_ranges(expected.get("ranges"))
    for key in ("message", "note", "severity", "fixed"):
        if key in expected and not isinstance(expected[key], str):
            raise ValueError(f"oracle {key} must be a string")


def validate_oracles(plan: dict, cases: dict[str, list[str]]) -> None:
    """Validate exact finding/fix contracts keyed by fixture source."""
    oracles = plan.get("oracles", {})
    if not isinstance(oracles, dict):
        raise TypeError("oracles must be a mapping keyed by fixture source")
    known = set(cases["valid"] + cases["invalid"])
    for source, expected in oracles.items():
        _validate_oracle(source, expected, known)
    if "fix" in plan:
        missing = [source for source in cases["invalid"]
                   if "fixed" not in oracles.get(source, {})]
        if missing:
            raise ValueError("rules with fix require fixed output for every invalid source")


def named_branches(plan: dict) -> list[dict]:
    match = plan.get("match", {})
    branches = match.get("any", []) if isinstance(match, dict) else []
    return branches if branches and all("name" in branch for branch in branches) else []


def validate_plan(plan: dict) -> tuple[dict, dict[str, list[str]]]:
    """Validate the complete plan and return its matcher and cases."""
    validate_header(plan)
    cases = validate_cases(plan["cases"])
    matcher = plan_matcher(plan)
    validate_utilities(plan, matcher)
    validate_constraints(plan, matcher)
    validate_oracles(plan, cases)
    branches = named_branches(plan)
    witnesses = [branch["witness"] for branch in branches]
    if len(witnesses) != len(set(witnesses)):
        raise ValueError("named branches need distinct witnesses")
    missing = [branch["name"] for branch in branches if branch["witness"] not in cases["invalid"]]
    if missing:
        raise ValueError(f"named branch witnesses missing from invalid cases: {', '.join(missing)}")
    return matcher, cases


def render_rule(plan: dict, matcher: dict) -> str:
    """Render ordinary ast-grep rule YAML from a validated plan."""
    rule = {"id": plan["id"], "language": plan["language"],
            "severity": plan.get("severity", "warning"),
            "message": FoldedStr(plan["message"]), "note": FoldedStr(plan["note"])}
    rule.update(plan.get("extensions", {}))
    for key in RULE_CONFIG_KEYS:
        if key in plan:
            rule[key] = plan[key]
    rule["rule"] = matcher
    rendered = yaml.safe_dump(rule, sort_keys=False, width=80, allow_unicode=True)
    comments = "".join(f"# {comment}\n" for comment in plan.get("comments", []))
    return comments + rendered


def render_fixture(plan: dict, cases: dict[str, list[str]]) -> str:
    fixture = {"id": plan["id"],
               "valid": [LiteralStr(source) for source in cases["valid"]],
               "invalid": [LiteralStr(source) for source in cases["invalid"]]}
    return yaml.dump(fixture, sort_keys=False, width=1000, allow_unicode=True)


def run_preflight(rule_text: str, cases: dict[str, list[str]], rule_id: str,
                  *, deadline: float | None = None) -> tuple[bool, str]:
    """Run a bounded isolated upstream fixture suite."""
    started = perf_counter()
    with tempfile.TemporaryDirectory(prefix="rule-plan-") as directory:
        root = Path(directory)
        (root / "rules").mkdir()
        (root / "tests").mkdir()
        (root / "rules" / f"{rule_id}.yml").write_text(rule_text, encoding="utf-8")
        (root / "tests" / f"{rule_id}.yml").write_text(
            yaml.safe_dump({"id": rule_id, **cases}, sort_keys=False), encoding="utf-8")
        (root / "sgconfig.yml").write_text(
            "ruleDirs: [rules]\ntestConfigs: [{testDir: tests}]\n", encoding="utf-8")
        remaining: float = MAX_ENGINE_SECONDS
        if deadline is not None:
            remaining = min(remaining, deadline - perf_counter())
            if remaining <= 0:
                return False, "engine-error=preflight budget exhausted"
        try:
            result = subprocess.run(
                [str(ENGINE), "test", "--include-off", "-c", str(root / "sgconfig.yml"),
                 "--skip-snapshot-tests"], text=True, capture_output=True,
                timeout=remaining, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return False, f"engine-error={error}"
    output = result.stdout + result.stderr
    detail = " | ".join(output.splitlines()[-6:])[:600]
    metrics = (f"elapsed_ms={int((perf_counter() - started) * 1000)} "
               f"output_bytes={len(output)}")
    if result.returncode == 0:
        return True, f"{metrics} {detail}".strip()
    if "file is not a valid ast-grep rule" in output:
        kind = "invalid-mutant"
    else:
        kind = "test-failure" if "Error: test failed." in output else "engine-error"
    return False, f"{metrics} {kind}={detail}".strip()


def _qualified_pattern_mutations(pattern: str):
    qualified = re.fullmatch(
        r"([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\((.*)\)",
        pattern,
        flags=re.DOTALL,
    )
    if not qualified:
        return
    receiver, member, arguments = qualified.groups()
    yield "receiver", f"$_.{member}({arguments})"
    yield "member", f"{receiver}.$_({arguments})"


def _direct_mapping_mutations(value: dict, path: str):
    removable = {"field", "stopBy", "kind", "nthChild", "ofRule", "inside", "has",
                 "follows", "precedes", "not"}
    anchors = {"kind", "pattern", "regex", "all", "any", "matches"}
    for key, child in value.items():
        if key == "pattern" and isinstance(child, str):
            for identity, pattern in _qualified_pattern_mutations(child):
                yield f"{path}.pattern-{identity}", {**value, key: pattern}
        if key in removable and len(value) > 1:
            mutant = {candidate: item for candidate, item in value.items() if candidate != key}
            if set(mutant) & anchors:
                yield f"{path}.{key}", mutant
        if key == "regex" and isinstance(child, str) \
                and (child.startswith("^") or child.endswith("$")):
            yield f"{path}.regex-anchor", {
                **value, key: child.removeprefix("^").removesuffix("$"),
            }


def mutation_candidates(value, path="rule"):
    """Yield deterministic claim-weakening mutations with stable paths."""
    if isinstance(value, dict):
        yield from _direct_mapping_mutations(value, path)
        children = value.items()
    elif isinstance(value, list):
        if len(value) > 1 and path.endswith((".all", ".any")):
            for index in range(len(value)):
                yield f"{path}[{index}]-deleted", value[:index] + value[index + 1:]
        children = enumerate(value)
    else:
        return
    for key, child in children:
        child_path = f"{path}.{key}" if isinstance(value, dict) else f"{path}[{key}]"
        for mutant_path, child_mutant in mutation_candidates(child, child_path):
            mutant = dict(value) if isinstance(value, dict) else list(value)
            mutant[key] = child_mutant
            yield mutant_path, mutant


def _rule_with(plan: dict, matcher: dict, key=None, identity=None, mutant=None) -> str:
    changed = dict(plan)
    if key is not None:
        changed[key] = dict(plan.get(key, {}))
        changed[key][identity] = mutant
    return render_rule(changed, matcher)


def _rule_without(plan: dict, matcher: dict, key: str, identity: str) -> str:
    changed = dict(plan)
    changed[key] = dict(plan[key])
    del changed[key][identity]
    if not changed[key]:
        del changed[key]
    return render_rule(changed, matcher)


def _has_positive_anchor(value) -> bool:
    """Return whether a rule tree still supplies an affirmative AST matcher."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"kind", "pattern", "regex", "matches"}:
                return True
            if key == "not":
                continue
            if key in {"all", "any"} and _has_positive_anchor(child):
                return True
    elif isinstance(value, list):
        return any(_has_positive_anchor(child) for child in value)
    return False


def _branch_mutant(plan: dict, branches: list[dict], deleted: int) -> dict:
    spec = dict(plan["match"])
    remaining = [branch for index, branch in enumerate(branches) if index != deleted]
    if len(remaining) == 1:
        spec["require"] = [*spec.get("require", []), remaining[0]["rule"]]
        spec["any"] = []
    else:
        spec["any"] = remaining
    return compile_match(spec)


def _preflight_named_branches(plan: dict, cases: dict[str, list[str]],
                              deadline: float) -> None:
    branches = named_branches(plan)
    for index, branch in enumerate(branches):
        mutant = _branch_mutant(plan, branches, index)
        witness = {"invalid": [branch["witness"]], "valid": cases["valid"][:1]}
        survived, detail = run_preflight(
            render_rule(plan, mutant), witness, plan["id"], deadline=deadline)
        if survived:
            raise RuntimeError(f"ANY_ARM_SURVIVED: {branch['name']}")
        if "engine-error=" in detail:
            raise RuntimeError(f"ANY_ARM_PREFLIGHT_ERROR: {branch['name']}: {detail}")


def compiled_mutations(plan: dict, matcher: dict) -> list[tuple[str, str]]:
    candidates = [(path, _rule_with(plan, mutant))
                  for path, mutant in mutation_candidates(matcher)
                  if _has_positive_anchor(mutant)]
    for key in ("utils", "constraints"):
        if key == "constraints":
            candidates.extend(
                (f"constraints.{identity}-deleted",
                 _rule_without(plan, matcher, key, identity))
                for identity in plan.get(key, {})
            )
        candidates.extend(
            (path, _rule_with(plan, matcher, key, identity, mutant))
            for identity, value in plan.get(key, {}).items()
            for path, mutant in mutation_candidates(value, f"{key}.{identity}")
            if key == "constraints" or _has_positive_anchor(mutant)
        )
    return candidates


def preflight(plan: dict, matcher: dict, cases: dict[str, list[str]]) -> None:
    """Require contrasts and every selected mutant to fail closed."""
    deadline = perf_counter() + MAX_PREFLIGHT_SECONDS
    passed, detail = run_preflight(
        render_rule(plan, matcher), cases, plan["id"], deadline=deadline)
    if not passed:
        raise RuntimeError(f"CONTRAST_PREFLIGHT_FAILED: {detail}")
    _preflight_named_branches(plan, cases, deadline)
    candidates = compiled_mutations(plan, matcher)
    exclusions = set(plan.get("mutation_exclusions", {}))
    indexed = dict(candidates)
    unknown = sorted(exclusions - set(indexed))
    if unknown:
        raise RuntimeError(f"UNKNOWN_MUTATION_EXCLUSION: {', '.join(unknown)}")
    for path in sorted(exclusions):
        survived, exclusion_detail = run_preflight(
            indexed[path], cases, plan["id"], deadline=deadline)
        if (not survived or "engine-error=" in exclusion_detail
                or "invalid-mutant=" in exclusion_detail):
            raise RuntimeError(f"INVALID_MUTATION_EXCLUSION: {path}: {exclusion_detail}")
    candidates = [(path, rule) for path, rule in candidates if path not in exclusions]
    if len(candidates) > plan.get("mutation_limit", MAX_MUTATIONS):
        raise RuntimeError(
            f"MUTATION_BUDGET_EXCEEDED: {len(candidates)} exceeds "
            f"{plan.get('mutation_limit', MAX_MUTATIONS)}")
    for path, rule_text in candidates[:plan.get("mutation_limit", MAX_MUTATIONS)]:
        survived, mutation_detail = run_preflight(
            rule_text, cases, plan["id"], deadline=deadline)
        if survived:
            raise RuntimeError(f"MUTATION_SURVIVED: {path}")
        if "invalid-mutant=" in mutation_detail:
            continue
        if "engine-error=" in mutation_detail:
            raise RuntimeError(f"MUTATION_PREFLIGHT_ERROR: {path}: {mutation_detail}")


def compile_plan(path: Path, *, run_checks=True) -> tuple[dict, dict, str, str]:
    """Return validated plan, matcher, rule text and fixture text."""
    plan = load_plan(path)
    matcher, cases = validate_plan(plan)
    rule_text, fixture_text = render_rule(plan, matcher), render_fixture(plan, cases)
    if run_checks:
        if not ENGINE.is_file():
            raise RuntimeError(f"pinned engine missing: {ENGINE}; run npm ci")
        preflight(plan, matcher, cases)
    return plan, matcher, rule_text, fixture_text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", metavar="PLAN.yml", type=Path)
    args = parser.parse_args(argv)
    plan, _, _, _ = compile_plan(args.plan)
    print(f"plan ok: {plan['id']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
