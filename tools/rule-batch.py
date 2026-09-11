#!/usr/bin/env python3
"""Plan a proposal batch and mechanically scaffold oracle-passing rule seeds.

Why: after proposal review, selecting syntactic/nonduplicate rows, testing seed
viability, scaffolding pairs, and recording the first probe are deterministic.
This tool leaves only matcher generality and semantic value to the drafter and
shipping reviewer. Contract: docs/authoring.md#harvest-and-draft-pipeline.

Usage:
  rule-batch.py --work WORK --category correctness [--dry-run] [--json]
  rule-batch.py --work WORK --category security --apply-seeded
  rule-batch.py --work WORK --category correctness --queue [--json]
  rule-batch.py --work WORK --category correctness --task RULE-ID
  rule-batch.py --work WORK --category correctness --mark-reviewed RULE-ID

Inputs: WORK/cluster/proposals.jsonl and WORK/dedupe.tsv.
Output: a bounded summary, plus WORK/draft-plan.tsv unless --dry-run. JSON mode
prints only the summary object. Queue mode lists only unfinished actionable
rows; task mode emits one compact, self-contained drafting packet. Exit 0 when
planning/apply succeeds, 1 if any candidate is blocked or an apply/probe fails,
2 for invalid inputs.
Side effects: default writes only the plan under WORK. --apply-seeded invokes
rule-scaffold.py and rule-draft.py for SEEDED-REVIEW rows; --mark-reviewed writes
a proposal- and candidate-bound acknowledgment under WORK. It has no network
and never edits semantic-only, duplicate, already-existing, or unseeded proposals.
Limits: fixture separation is not semantic correctness or shipping approval.
Extend: add routing states in assess(); keep subprocess output captured/bounded.
"""

import argparse
import csv
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAFFOLD = ROOT / "tools" / "rule-scaffold.py"
DRAFT = ROOT / "tools" / "rule-draft.py"
PLAN_FIELDS = ("id", "category", "classification", "duplicate", "proposal_digest",
               "candidate_digest", "action", "detail")
ACTIONABLE = {"AI-DRAFT", "SEEDED-PASS"}
STATE_SPEC = importlib.util.spec_from_file_location("rule_draft_state", DRAFT)
if STATE_SPEC is None or STATE_SPEC.loader is None:
    raise RuntimeError("cannot load rule-draft state contract")
DRAFT_STATE = importlib.util.module_from_spec(STATE_SPEC)
STATE_SPEC.loader.exec_module(DRAFT_STATE)


class BatchError(ValueError):
    """The batch cannot be assessed safely from its persisted artifacts."""


def read_jsonl(path: Path) -> list[dict]:
    """Read a bounded pipeline artifact or fail with one diagnostic."""
    try:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()]
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BatchError(f"cannot read {path}: {error}") from error


def proposal_digest(proposal: dict) -> str:
    """Match the canonical digest emitted by the complete-index dedupe stage."""
    encoded = json.dumps(proposal, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def candidate_digest(rule: Path, fixture: Path, root: Path | None = None) -> str | None:
    """Mirror rule-draft's complete probe-input identity when the pair exists."""
    root = ROOT if root is None else root
    try:
        inputs = DRAFT_STATE.candidate_inputs(rule, fixture, root)
    except OSError:
        return None
    return DRAFT_STATE.input_digest(inputs)


def read_dedupe_rows(path: Path) -> list[dict[str, str]]:
    """Read complete required TSV cells before interpreting the ledger."""
    try:
        with path.open(encoding="utf-8", newline="") as source:
            reader = csv.DictReader(source, delimiter="\t")
            rows = list(reader)
    except (OSError, UnicodeError, csv.Error) as error:
        raise BatchError(f"cannot read {path}: {error}") from error
    required = {"proposal", "proposal_digest", "flag"}
    if not reader.fieldnames or not required <= set(reader.fieldnames):
        raise BatchError(f"invalid dedupe table {path}")
    if any(any(not isinstance(row.get(field), str) for field in required) for row in rows):
        raise BatchError(f"dedupe table {path} has a truncated required field")
    return rows


def duplicate_ids(path: Path, expected: dict[str, str]) -> set[str]:
    """Return flagged IDs only when the dedupe ledger exactly covers proposals."""
    rows = read_dedupe_rows(path)
    ledger_ids = [row.get("proposal") for row in rows]
    if any(not isinstance(rule_id, str) or not rule_id for rule_id in ledger_ids):
        raise BatchError(f"dedupe table {path} has an empty proposal id")
    if len(set(ledger_ids)) != len(ledger_ids):
        raise BatchError(f"dedupe table {path} has duplicate proposal ids")
    if set(ledger_ids) != set(expected):
        raise BatchError(f"dedupe table {path} does not exactly cover current proposals")
    for row in rows:
        if row.get("proposal_digest") != expected[row["proposal"]]:
            raise BatchError(f"dedupe table {path} is stale for {row['proposal']!r}")
    return {row["proposal"] for row in rows if row["flag"]}


def proposal_ids(proposals: list[dict]) -> dict[str, str]:
    """Validate enough proposal identity to reconcile downstream artifacts."""
    ids = []
    for proposal in proposals:
        if not isinstance(proposal, dict) or not isinstance(proposal.get("id"), str):
            raise BatchError("proposal needs a string id")
        ids.append(proposal["id"])
    if any(not rule_id for rule_id in ids) or len(set(ids)) != len(ids):
        raise BatchError("proposal ids must be nonempty and unique")
    return {proposal["id"]: proposal_digest(proposal) for proposal in proposals}


def run(command: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    """Run one repository tool with captured output and a hard timeout."""
    try:
        return subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                              timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        raise BatchError(f"cannot run {Path(command[1]).name}: {error}") from error


def seed_status(proposal: Path, rule_id: str, category: str) -> tuple[str, str]:
    """Dry-run one seed and reduce its output to a review route."""
    if any(path.stem == rule_id for path in (ROOT / "rules").rglob("*.yml")):
        return "EXISTING-REVIEW", "rule id already exists"
    command = [sys.executable, str(SCAFFOLD), "--proposal", str(proposal), "--id", rule_id,
               "--category", category, "--seed", "--contrast", "--assess-seed"]
    try:
        result = run(command)
    except BatchError as error:
        return "BLOCKED", str(error)[:200]
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()[-1:]
        message = detail[0][:200] if detail else "scaffold returned no diagnostic"
        return "BLOCKED", message
    lines = result.stdout.splitlines()
    first = lines[:1]
    if first and first[0].startswith("SEED PASS fixture oracle;"):
        return "SEEDED-REVIEW", "fixture oracle passed; AI reviews claim and generality"
    if first and first[0].startswith("SEED NONE;"):
        contrast = next((line[:300] for line in lines[1:] if line.startswith("CONTRAST ")), "")
        seed_detail = contrast or "CONTRAST unavailable; rerun scaffold assessment"
        return "AI-DRAFT", f"no safe seed; {seed_detail}"
    return "BLOCKED", "scaffold omitted seed verdict"


def assess(proposals: list[dict], duplicates: set[str], proposal_path: Path,
           category: str) -> list[dict[str, str]]:
    """Route each proposal without allowing semantic rows into generation."""
    rows = []
    seen = set()
    for proposal in proposals:
        if not isinstance(proposal, dict):
            raise BatchError("proposal must be an object")
        rule_id = proposal.get("id")
        classification = proposal.get("classification")
        if not isinstance(rule_id, str) or not isinstance(classification, str):
            raise BatchError("proposal needs string id and classification")
        if rule_id in seen:
            raise BatchError(f"duplicate proposal id {rule_id!r}")
        seen.add(rule_id)
        duplicate = "yes" if rule_id in duplicates else "no"
        if duplicate == "yes":
            action, detail = "DUP-REVIEW", "dedupe flagged prior coverage"
        elif classification != "syntactic":
            action, detail = "SEMANTIC-REVIEW", f"{classification} needs rejection/ship judgment"
        else:
            action, detail = seed_status(proposal_path, rule_id, category)
        rows.append({"id": rule_id, "category": category, "classification": classification,
                     "duplicate": duplicate, "proposal_digest": proposal_digest(proposal),
                     "candidate_digest": "", "action": action, "detail": detail})
    return rows


def write_plan(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="",
                                         dir=path.parent, prefix=f".{path.name}.",
                                         delete=False) as output:
            temporary = Path(output.name)
            writer = csv.DictWriter(output, fieldnames=PLAN_FIELDS, delimiter="\t",
                                    lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def read_plan(path: Path) -> list[dict[str, str]]:
    """Load the exact current task ledger without exposing unrelated proposals."""
    try:
        with path.open(encoding="utf-8", newline="") as source:
            reader = csv.DictReader(source, delimiter="\t")
            rows = list(reader)
    except (OSError, UnicodeError, csv.Error) as error:
        raise BatchError(f"cannot read {path}: {error}") from error
    if tuple(reader.fieldnames or ()) != PLAN_FIELDS:
        raise BatchError(f"invalid draft plan {path}")
    if any(any(not isinstance(row.get(field), str) for field in PLAN_FIELDS) for row in rows):
        raise BatchError(f"draft plan {path} has a truncated field")
    ids = [row["id"] for row in rows]
    if any(not rule_id for rule_id in ids) or len(ids) != len(set(ids)):
        raise BatchError(f"draft plan {path} has empty or duplicate ids")
    return rows


def bind_candidate_digests(rows: list[dict[str, str]], proposals: list[dict],
                           category: str) -> None:
    """Snapshot the complete current probe-input identity into each plan row."""
    by_id = {proposal.get("id"): proposal for proposal in proposals}
    for row in rows:
        language = by_id[row["id"]].get("language")
        if not isinstance(language, str) or not language:
            row["candidate_digest"] = ""
            continue
        rule = ROOT / "rules" / language / category / f"{row['id']}.yml"
        fixture = ROOT / "tests" / language / category / f"{row['id']}.yml"
        row["candidate_digest"] = candidate_digest(rule, fixture) or ""


def preserve_actionable_routes(rows: list[dict[str, str]], plan_path: Path,
                               work: Path) -> None:
    """Keep only provenance-bound partial rules actionable across replanning."""
    if not plan_path.is_file():
        return
    previous = {row["id"]: row for row in read_plan(plan_path)}
    states = draft_states(work)
    for row in rows:
        prior = previous.get(row["id"])
        if prior is None or row["action"] != "EXISTING-REVIEW":
            continue
        same_eligibility = all(prior[field] == row[field]
                               for field in ("category", "classification", "duplicate",
                                             "proposal_digest"))
        attempts = states.get(row["id"], {}).get("attempts", [])
        state_candidate = attempts[-1]["candidate"] if attempts else ""
        current_candidate = row["candidate_digest"]
        provenance_matches = bool(current_candidate) and current_candidate in {
            prior["candidate_digest"], state_candidate}
        restorable = ACTIONABLE | {"PROBE-FAILED"}
        if same_eligibility and provenance_matches and prior["action"] in restorable:
            row["action"] = ("AI-DRAFT" if prior["action"] == "PROBE-FAILED"
                             else prior["action"])
            row["detail"] = prior["detail"]


def draft_states(work: Path) -> dict[str, dict]:
    """Reuse rule-draft's strict state contract; malformed state stays actionable."""
    states = {}
    for path in (work / "draft").glob("*.json"):
        try:
            state = DRAFT_STATE.load_state(path, path.stem)
        except (DRAFT_STATE.DraftError, OSError, UnicodeError):
            continue
        states[path.stem] = state
    return states


def reviewed_state(work: Path, rule_id: str) -> dict | None:
    """Load one bounded review acknowledgment; malformed data is not completion."""
    path = work / "draft-reviewed" / f"{rule_id}.json"
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    expected = {"rule", "proposal_digest", "candidate_digest"}
    return state if isinstance(state, dict) and set(state) == expected else None


def draft_tasks(work: Path, category: str) -> list[dict]:
    """Join plan and proposals into minimal per-rule authoring packets."""
    proposals = read_jsonl(work / "cluster" / "proposals.jsonl")
    by_id = {proposal["id"]: proposal for proposal in proposals
             if isinstance(proposal, dict) and isinstance(proposal.get("id"), str)}
    if len(by_id) != len(proposals):
        raise BatchError("proposals need unique string ids before task emission")
    current_duplicates = duplicate_ids(work / "dedupe.tsv", proposal_ids(proposals))
    rows = read_plan(work / "draft-plan.tsv")
    if {row["id"] for row in rows} != set(by_id):
        raise BatchError("draft plan does not exactly cover current proposals")
    states = draft_states(work)
    tasks = []
    for row in rows:
        proposal = by_id[row["id"]]
        if row["category"] != category:
            raise BatchError("draft plan category is stale; rerun rule-batch planning")
        expected_duplicate = "yes" if row["id"] in current_duplicates else "no"
        if row["duplicate"] != expected_duplicate \
                or row["classification"] != proposal.get("classification"):
            raise BatchError("draft plan is stale; rerun rule-batch planning")
        if row["action"] in ACTIONABLE and (expected_duplicate != "no"
                                             or proposal["classification"] != "syntactic"):
            raise BatchError("draft plan assigns generation to an ineligible proposal")
        state = states.get(row["id"], {})
        status = state.get("status")
        language = proposal.get("language")
        if not isinstance(language, str) or not language:
            raise BatchError(f"proposal {row['id']!r} needs a language")
        rule = ROOT / "rules" / language / category / f"{row['id']}.yml"
        fixture = ROOT / "tests" / language / category / f"{row['id']}.yml"
        proposal_hash = proposal_digest(proposal)
        if row["proposal_digest"] != proposal_hash:
            raise BatchError("draft plan proposal identity is stale; rerun rule-batch planning")
        fingerprint = candidate_digest(rule, fixture)
        attempts = state.get("attempts")
        state_fingerprint = attempts[-1].get("candidate") \
            if isinstance(attempts, list) and attempts and isinstance(attempts[-1], dict) else None
        current_terminal = isinstance(status, str) and status in {"PASS", "PARKED"} \
            and fingerprint is not None and state_fingerprint == fingerprint
        review = reviewed_state(work, row["id"])
        current_review = fingerprint is not None and review == {
            "rule": row["id"], "proposal_digest": proposal_hash,
            "candidate_digest": fingerprint}
        complete = current_terminal and current_review
        if row["action"] not in ACTIONABLE or complete:
            continue
        tasks.append({
            "id": row["id"], "action": row["action"],
            "claim": proposal.get("claim"), "classification": proposal.get("classification"),
            "positive": proposal.get("positive"), "near_miss": proposal.get("near_miss"),
            "rationale": proposal.get("rationale"),
            "focus": ("review parked attempts and acknowledge or reset explicitly"
                      if status == "PARKED" and current_terminal else
                      "review provisional seed matcher generality and semantic value"
                      if row["action"] == "SEEDED-PASS" else "author and probe the matcher"),
            "proposal_digest": proposal_hash, "candidate_digest": fingerprint,
            "rule": str(rule), "fixture": str(fixture),
            "draft_command": [sys.executable, str(DRAFT), row["id"], "--work", str(work)],
        })
        tasks[-1]["reviewed_command"] = [
            sys.executable, str(Path(__file__).resolve()), "--work", str(work),
            "--category", category, "--mark-reviewed", row["id"]]
    return tasks


def mark_reviewed(work: Path, category: str, rule_id: str) -> int:
    """Acknowledge review of any actionable current PASS or PARKED task."""
    task = next((row for row in draft_tasks(work, category) if row["id"] == rule_id), None)
    states = draft_states(work)
    state = states.get(rule_id)
    attempts = state.get("attempts") if isinstance(state, dict) else None
    fingerprint = attempts[-1].get("candidate") \
        if isinstance(attempts, list) and attempts and isinstance(attempts[-1], dict) else None
    if task is None or not isinstance(state, dict) \
            or state.get("status") not in {"PASS", "PARKED"} \
            or fingerprint != task["candidate_digest"]:
        print(f"rule-batch: no reviewable terminal task {rule_id!r}", file=sys.stderr)
        return 1
    review_path = work / "draft-reviewed" / f"{rule_id}.json"
    review_path.parent.mkdir(parents=True, exist_ok=True)
    review = {"rule": rule_id, "proposal_digest": task["proposal_digest"],
              "candidate_digest": task["candidate_digest"]}
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=review_path.parent,
                                         prefix=f".{review_path.name}.", delete=False) as output:
            temporary = Path(output.name)
            json.dump(review, output, separators=(",", ":"), sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(review_path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    print(f"reviewed\t{rule_id}")
    return 0


def emit_tasks(work: Path, category: str, rule_id: str | None, json_output: bool) -> int:
    """Print a compact queue or one self-contained authoring task."""
    tasks = draft_tasks(work, category)
    if rule_id:
        task = next((row for row in tasks if row["id"] == rule_id), None)
        if task is None:
            print(f"rule-batch: no actionable task {rule_id!r}", file=sys.stderr)
            return 1
        print(json.dumps(task, separators=(",", ":"), sort_keys=True))
        return 0
    queue_tasks = [{"id": row["id"], "action": row["action"]} for row in tasks]
    queue = {"tasks": queue_tasks,
             "task_command": [sys.executable, str(Path(__file__).resolve()),
                              "--work", str(work), "--category", category, "--task", "<id>"]}
    if json_output:
        print(json.dumps(queue, separators=(",", ":"), sort_keys=True))
    else:
        for task in queue_tasks:
            print(f"{task['action']}\t{task['id']}")
        print(f"queue: actionable={len(tasks)}", file=sys.stderr)
    return 0


def probe_passed(work: Path, rule_id: str, probe: subprocess.CompletedProcess[str]) -> bool:
    """Require both the bounded CLI verdict and its persisted terminal state."""
    first = probe.stdout.splitlines()[:1]
    if probe.returncode != 0 or not first or f"{rule_id}: PASS " not in first[0]:
        return False
    try:
        state = json.loads((work / "draft" / f"{rule_id}.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(state, dict):
        return False
    attempts = state.get("attempts")
    return state.get("rule") == rule_id and state.get("status") == "PASS" \
        and isinstance(attempts, list) and bool(attempts)


def apply_seeded(rows: list[dict[str, str]], proposal_path: Path, work: Path,
                 category: str) -> int:
    """Generate and probe only rows that already passed the dry-run oracle."""
    failures = 0
    for row in rows:
        if row["action"] != "SEEDED-REVIEW":
            continue
        try:
            scaffold = run([sys.executable, str(SCAFFOLD), "--proposal", str(proposal_path),
                            "--id", row["id"], "--category", category,
                            "--seed", "--contrast"])
        except BatchError as error:
            row["action"] = "APPLY-FAILED"
            row["detail"] = str(error)[:200]
            failures += 1
            continue
        if scaffold.returncode != 0:
            row["action"] = "APPLY-FAILED"
            row["detail"] = (scaffold.stderr or scaffold.stdout).strip()[-200:]
            failures += 1
            continue
        try:
            probe = run([sys.executable, str(DRAFT), row["id"], "--work", str(work)])
        except BatchError as error:
            row["action"] = "PROBE-FAILED"
            row["detail"] = str(error)[:200]
            failures += 1
            continue
        if not probe_passed(work, row["id"], probe):
            row["action"] = "PROBE-FAILED"
            detail = (probe.stderr or probe.stdout).strip()[-160:]
            row["detail"] = "scaffolded pair and rule count retained; " + (
                f"probe/state mismatch: {detail}" if detail
                else "probe/state mismatch without diagnostic")
            failures += 1
        else:
            # The apply probe proves only fixture separation. Do not make that
            # provisional input terminal: the reviewer must be able to edit it
            # and run rule-draft from a fresh state before acknowledging it.
            (work / "draft" / f"{row['id']}.json").unlink(missing_ok=True)
            row["action"] = "SEEDED-PASS"
            row["detail"] = "provisional pair passed probe; generality review required"
    return failures


def main() -> int:
    """Run the plan/apply CLI and emit one bounded status record."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--category", required=True, choices=("security", "correctness"))
    parser.add_argument("--apply-seeded", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    task_mode = parser.add_mutually_exclusive_group()
    task_mode.add_argument("--queue", action="store_true",
                           help="list only actionable, nonterminal draft ids")
    task_mode.add_argument("--task", metavar="ID",
                           help="emit one self-contained authoring task as compact JSON")
    task_mode.add_argument("--mark-reviewed", metavar="ID",
                           help="acknowledge review of an actionable PASS or PARKED task")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.apply_seeded and (args.dry_run or args.queue or args.task or args.mark_reviewed):
        parser.error("--apply-seeded cannot be combined with another mode")
    if args.dry_run and (args.queue or args.task or args.mark_reviewed):
        parser.error("--dry-run cannot be combined with another mode")
    args.work = args.work.resolve()
    if args.mark_reviewed:
        try:
            return mark_reviewed(args.work, args.category, args.mark_reviewed)
        except (BatchError, OSError, UnicodeError) as error:
            print(f"rule-batch: ERROR: {error}", file=sys.stderr)
            return 2
    if args.queue or args.task:
        try:
            return emit_tasks(args.work, args.category, args.task, args.json)
        except (BatchError, OSError, UnicodeError) as error:
            print(f"rule-batch: ERROR: {error}", file=sys.stderr)
            return 2
    proposal_path = args.work / "cluster" / "proposals.jsonl"
    try:
        proposals = read_jsonl(proposal_path)
        rows = assess(proposals, duplicate_ids(args.work / "dedupe.tsv",
                                               proposal_ids(proposals)), proposal_path,
                      args.category)
        bind_candidate_digests(rows, proposals, args.category)
        preserve_actionable_routes(rows, args.work / "draft-plan.tsv", args.work)
        failures = apply_seeded(rows, proposal_path, args.work, args.category) \
            if args.apply_seeded else 0
        bind_candidate_digests(rows, proposals, args.category)
        if not args.dry_run:
            write_plan(args.work / "draft-plan.tsv", rows)
    except (BatchError, OSError, UnicodeError) as error:
        print(f"rule-batch: ERROR: {error}", file=sys.stderr)
        return 2
    counts = Counter(row["action"] for row in rows)
    summary = {"proposals": len(rows), "actions": dict(sorted(counts.items())),
               "failures": failures}
    if args.json:
        print(json.dumps(summary, separators=(",", ":"), sort_keys=True))
    else:
        actions = " ".join(f"{key}={value}" for key, value in sorted(counts.items()))
        print(f"draft-plan: proposals={len(rows)} {actions}; failures={failures}")
    return 1 if failures or counts.get("BLOCKED", 0) else 0


if __name__ == "__main__":
    sys.exit(main())
