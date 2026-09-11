#!/usr/bin/env python3
"""Track one rule's bounded probe loop and produce PASS, RETRY, or PARKED.

The exact bytes of every probe input identify a candidate. Only a completed
probe of a distinct candidate consumes one of four attempts. Rechecking
unchanged inputs is rejected without running the probe or consuming budget.
PASS and PARKED are terminal and idempotent. State and parked reports are
deterministic, atomic files under WORK/draft; malformed state fails closed.

Usage:
  rule-draft.py <rule-id> --work WORK [--sexp]

Exit: 0 PASS; 1 RETRY or PARKED; 2 invalid input/state/probe execution.
One drafter owns each state file; concurrent same-ID calls are unsupported.
Output: at most the state line plus the compact failed probe gates.
Side effects: WORK/draft/<id>.json, and <id>.md only on PARKED.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "tools" / "rule-probe.py"
PROBE_SPEC = importlib.util.spec_from_file_location("rule_probe_contract", PROBE)
if PROBE_SPEC is None or PROBE_SPEC.loader is None:
    raise RuntimeError("cannot load rule-probe timeout contract")
PROBE_STATE = importlib.util.module_from_spec(PROBE_SPEC)
PROBE_SPEC.loader.exec_module(PROBE_STATE)
MAX_ATTEMPTS = 4
KEBAB = re.compile(r"^[a-z]+(?:-[a-z0-9]+)+$")
TERMINAL = {"PASS", "PARKED"}


class DraftError(ValueError):
    """A draft cannot advance without repairing its inputs or state."""


def find_pair(rule_id: str) -> tuple[Path, Path]:
    """Resolve one globally unique rule and its mirrored fixture."""
    hits = [path for path in (ROOT / "rules").rglob("*.yml") if path.stem == rule_id]
    if len(hits) != 1:
        raise DraftError(f"expected one rule for {rule_id!r}, found {len(hits)}")
    rule = hits[0]
    fixture = ROOT / "tests" / rule.relative_to(ROOT / "rules")
    if not fixture.is_file():
        raise DraftError(f"missing fixture {fixture.relative_to(ROOT)}")
    return rule, fixture


def candidate_inputs(rule: Path, fixture: Path,
                     root: Path | None = None) -> dict[Path, bytes | None]:
    """Capture required and optional bytes consumed by one probe."""
    root = ROOT if root is None else root
    inputs: dict[Path, bytes | None] = {
        rule.relative_to(root): rule.read_bytes(),
        fixture.relative_to(root): fixture.read_bytes(),
    }
    supporting = (
        root / "tests" / "__snapshots__" / f"{rule.stem}-snapshot.yml",
        root / "tests" / "arm_coverage.json",
    )
    for source in supporting:
        try:
            inputs[source.relative_to(root)] = source.read_bytes()
        except FileNotFoundError:
            inputs[source.relative_to(root)] = None
    return inputs


def input_digest(inputs: dict[Path, bytes | None]) -> str:
    """Hash paths, presence, lengths, and bytes without concatenation ambiguity."""
    digest = hashlib.sha256()
    for path, contents in inputs.items():
        name = path.as_posix().encode()
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(b"\0" if contents is None else b"\1")
        if contents is not None:
            digest.update(len(contents).to_bytes(8, "big"))
            digest.update(contents)
    return digest.hexdigest()


def candidate(rule: Path, fixture: Path,
              root: Path | None = None) -> tuple[str, str, dict[Path, bytes | None]]:
    """Capture the exact probe inputs, their identity, and matcher."""
    root = ROOT if root is None else root
    inputs = candidate_inputs(rule, fixture, root)
    rule_bytes = inputs[rule.relative_to(root)]
    assert rule_bytes is not None  # Required inputs never use the absence marker.
    try:
        document = yaml.safe_load(rule_bytes)
    except yaml.YAMLError as error:
        raise DraftError(f"invalid rule YAML: {error}") from error
    if not isinstance(document, dict):
        raise DraftError("rule YAML must be a mapping")
    matcher = yaml.safe_dump(document.get("rule"), sort_keys=True).strip()
    return input_digest(inputs), matcher, inputs


def snapshot_candidate(inputs: dict[Path, bytes | None], target: Path) -> None:
    """Materialize immutable probe inputs from the bytes that were fingerprinted."""
    for relative, contents in inputs.items():
        if contents is None:
            continue
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(contents)


def probe_timeout(matcher: str, fixture_bytes: bytes, sexp: bool) -> int:
    """Parse captured inputs and apply rule-probe's shared timeout contract."""
    try:
        fixture = yaml.safe_load(fixture_bytes)
    except yaml.YAMLError:
        fixture = None
    return PROBE_STATE.probe_timeout(yaml.safe_load(matcher), fixture, sexp)


def load_state(path: Path, rule_id: str) -> dict:
    """Load and strictly validate the small persistent transition record."""
    if not path.exists():
        return {"schema": 1, "rule": rule_id, "status": "DRAFTING", "attempts": []}
    if path.stat().st_size > 1_048_576:
        raise DraftError("state exceeds 1 MiB")
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DraftError(f"cannot read state: {error}") from error
    if not isinstance(state, dict) or set(state) != {"schema", "rule", "status", "attempts"}:
        raise DraftError("state must contain schema, rule, status, and attempts")
    if state["schema"] != 1 or state["rule"] != rule_id:
        raise DraftError("state schema or rule id does not match")
    if (not isinstance(state["status"], str)
            or state["status"] not in {"DRAFTING", "RETRY", *TERMINAL}):
        raise DraftError(f"unknown state {state['status']!r}")
    validate_attempts(state["attempts"])
    validate_transition(state["status"], state["attempts"])
    return state


def validate_attempts(attempts: object) -> None:
    """Reject incomplete, duplicated, or unbounded attempt evidence."""
    if not isinstance(attempts, list) or len(attempts) > MAX_ATTEMPTS:
        raise DraftError("attempts must be a list within the four-attempt limit")
    for attempt in attempts:
        if not isinstance(attempt, dict) or set(attempt) != {"candidate", "matcher", "probe"}:
            raise DraftError("each attempt needs candidate, matcher, and probe")
        if not all(isinstance(attempt[field], str) for field in ("candidate", "matcher", "probe")):
            raise DraftError("attempt candidate, matcher, and probe must be strings")
    identities = [attempt["candidate"] for attempt in attempts]
    if any(not re.fullmatch(r"[0-9a-f]{64}", identity) for identity in identities):
        raise DraftError("attempt candidate must be a SHA-256 digest")
    if len(set(identities)) != len(identities):
        raise DraftError("attempt candidates must be distinct")


def probe_outcomes(attempts: list[dict]) -> list[str]:
    """Extract strictly formatted probe verdicts from attempt evidence."""
    outcomes = []
    for attempt in attempts:
        first = attempt["probe"].splitlines()[:1]
        if not first or not (first[0].endswith(": PASS") or first[0].endswith(": FAIL")):
            raise DraftError("attempt probe needs a PASS or FAIL verdict")
        outcomes.append(first[0].rsplit(": ", maxsplit=1)[1])
    return outcomes


def require_failures(outcomes: list[str], state: str) -> None:
    """Reject terminal histories containing an unexpected passing probe."""
    if any(outcome != "FAIL" for outcome in outcomes):
        raise DraftError(f"{state} state can contain only failed attempts")


def validate_transition(status: str, attempts: list[dict]) -> None:
    """Require evidence cardinality consistent with the recorded state."""
    outcomes = probe_outcomes(attempts)
    if status == "DRAFTING" and attempts:
        raise DraftError("DRAFTING state cannot contain attempts")
    if status == "RETRY":
        if not 1 <= len(attempts) < MAX_ATTEMPTS:
            raise DraftError("RETRY state needs one to three attempts")
        require_failures(outcomes, status)
    if status == "PASS":
        if not outcomes or outcomes[-1] != "PASS":
            raise DraftError("PASS state needs a passing final probe")
        require_failures(outcomes[:-1], status)
    if status == "PARKED":
        if len(attempts) != MAX_ATTEMPTS:
            raise DraftError("PARKED state needs four attempts")
        require_failures(outcomes, status)


def atomic_text(path: Path, contents: str) -> None:
    """Replace a state artifact without exposing a partially written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, newline="", delete=False,
            prefix=f".{path.name}.",
        ) as output:
            temporary = Path(output.name)
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def write_state(path: Path, state: dict) -> None:
    atomic_text(path, json.dumps(state, sort_keys=True, indent=2) + "\n")


def parked_report(rule_id: str, attempts: list[dict]) -> str:
    """Render the complete bounded evidence without session narrative."""
    lines = [f"# {rule_id} — PARKED after {len(attempts)} attempts", ""]
    for index, attempt in enumerate(attempts, 1):
        lines.extend((f"## Attempt {index}", "", "```yaml", attempt["matcher"], "```", "",
                      "```text", attempt["probe"].rstrip(), "```", ""))
    return "\n".join(lines)


def run_probe(rule_id: str, sexp: bool, input_root: Path,
              timeout: int) -> tuple[int, str]:
    """Run the bounded probe and accept only its exact first-line verdict schema."""
    command = [sys.executable, str(PROBE), rule_id, "--brief", "--input-root", str(input_root)]
    if sexp:
        command.append("--sexp")
    try:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        raise DraftError(f"probe timed out after {error.timeout}s") from error
    except (OSError, subprocess.SubprocessError) as error:
        raise DraftError(f"cannot run probe: {error}") from error
    output = result.stdout.strip()
    expected = f": {'PASS' if result.returncode == 0 else 'FAIL'}"
    first = output.splitlines()[:1]
    if result.returncode not in (0, 1) or not first or not first[0].endswith(expected):
        detail = (result.stderr or result.stdout).strip()[-300:]
        raise DraftError(f"probe returned an invalid verdict: {detail}")
    return result.returncode, output


def terminal_result(state: dict, rule_id: str, fingerprint: str,
                    report_path: Path) -> int | None:
    """Return a terminal verdict only when it belongs to the current bytes."""
    if state["status"] not in TERMINAL:
        return None
    attempts = state["attempts"]
    if not attempts or attempts[-1]["candidate"] != fingerprint:
        raise DraftError(
            "terminal state belongs to different probe inputs; "
            "remove it explicitly to start a new draft")
    if state["status"] == "PARKED" and not report_path.exists():
        atomic_text(report_path, parked_report(rule_id, attempts))
    suffix = f"; report=draft/{rule_id}.md" if state["status"] == "PARKED" else ""
    print(f"{rule_id}: {state['status']} {len(attempts)}/{MAX_ATTEMPTS}{suffix}")
    return 0 if state["status"] == "PASS" else 1


def advance(rule_id: str, work: Path, sexp: bool = False) -> int:
    """Advance one byte-identified candidate; terminal states require identical bytes."""
    if not KEBAB.fullmatch(rule_id):
        raise DraftError("rule id must be kebab-case")
    draft_dir = work.resolve() / "draft"
    state_path = draft_dir / f"{rule_id}.json"
    report_path = draft_dir / f"{rule_id}.md"
    state = load_state(state_path, rule_id)
    attempts = state["attempts"]
    rule, fixture = find_pair(rule_id)
    fingerprint, matcher, inputs = candidate(rule, fixture)
    terminal = terminal_result(state, rule_id, fingerprint, report_path)
    if terminal is not None:
        return terminal

    if any(attempt["candidate"] == fingerprint for attempt in attempts):
        print(f"{rule_id}: REPEATED {len(attempts)}/{MAX_ATTEMPTS}; edit rule or fixture")
        return 2

    with tempfile.TemporaryDirectory(prefix="rule-draft-input-") as directory:
        input_root = Path(directory)
        snapshot_candidate(inputs, input_root)
        fixture_bytes = inputs[fixture.relative_to(ROOT)]
        assert fixture_bytes is not None
        timeout = probe_timeout(matcher, fixture_bytes, sexp)
        returncode, output = run_probe(rule_id, sexp, input_root, timeout)
    attempts.append({"candidate": fingerprint, "matcher": matcher, "probe": output})
    if returncode == 0:
        state["status"] = "PASS"
    elif len(attempts) == MAX_ATTEMPTS:
        state["status"] = "PARKED"
    else:
        state["status"] = "RETRY"
    write_state(state_path, state)

    suffix = f"; report=draft/{rule_id}.md" if state["status"] == "PARKED" else ""
    print(f"{rule_id}: {state['status']} {len(attempts)}/{MAX_ATTEMPTS}{suffix}")
    gates = output.splitlines()[1:]
    if state["status"] != "PASS" and gates:
        print("\n".join(gates))
    if state["status"] == "PARKED":
        atomic_text(report_path, parked_report(rule_id, attempts))
    return 0 if state["status"] == "PASS" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    parser.add_argument("rule_id")
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--sexp", action="store_true")
    args = parser.parse_args()
    try:
        return advance(args.rule_id, args.work, args.sexp)
    except (DraftError, OSError, UnicodeError) as error:
        print(f"rule-draft: ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
