import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("rule_batch", ROOT / "tools/rule-batch.py")
assert SPEC and SPEC.loader
BATCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BATCH)


def completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def pass_state(rule_id, candidate):
    return {"schema": 1, "rule": rule_id, "status": "PASS", "attempts": [{
        "candidate": candidate, "matcher": "pattern: bad($X)",
        "probe": f"{rule_id}: PASS"}]}


def parked_state(rule_id, candidate):
    attempts = [{"candidate": char * 64, "matcher": f"pattern: bad{index}($X)",
                 "probe": f"{rule_id}: FAIL"}
                for index, char in enumerate("abc", 1)]
    attempts.append({"candidate": candidate, "matcher": "pattern: bad4($X)",
                     "probe": f"{rule_id}: FAIL"})
    return {"schema": 1, "rule": rule_id, "status": "PARKED", "attempts": attempts}


class RuleBatchTests(unittest.TestCase):
    def test_header_only_dedupe_is_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dedupe.tsv"
            path.write_text("proposal\tproposal_digest\tflag\n", encoding="utf-8")
            self.assertEqual(BATCH.duplicate_ids(path, {}), set())

    def test_dedupe_must_exactly_cover_current_proposals(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dedupe.tsv"
            digest = "a" * 64
            for rows in (f"go-one\t{digest}\t\n",
                         f"go-one\t{digest}\t\ngo-one\t{digest}\tDUP?\n",
                         f"go-one\t{digest}\t\ngo-stale\t{digest}\t\n"):
                with self.subTest(rows=rows):
                    path.write_text("proposal\tproposal_digest\tflag\n" + rows,
                                    encoding="utf-8")
                    with self.assertRaisesRegex(BATCH.BatchError, "dedupe table"):
                        BATCH.duplicate_ids(path, {"go-one": digest, "go-two": digest})

    def test_dedupe_rejects_stale_proposal_content(self):
        proposal = {"id": "go-one", "classification": "syntactic", "claim": "new"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dedupe.tsv"
            path.write_text("proposal\tproposal_digest\tflag\n"
                            f"go-one\t{'0' * 64}\t\n", encoding="utf-8")
            with self.assertRaisesRegex(BATCH.BatchError, "stale"):
                BATCH.duplicate_ids(path, BATCH.proposal_ids([proposal]))

    def test_dedupe_rejects_truncated_row_but_accepts_empty_flag(self):
        proposal = {"id": "go-one", "classification": "syntactic"}
        digest = BATCH.proposal_digest(proposal)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dedupe.tsv"
            header = "proposal\tproposal_digest\tflag\n"
            path.write_text(header + f"go-one\t{digest}\n", encoding="utf-8")
            with self.assertRaisesRegex(BATCH.BatchError, "truncated"):
                BATCH.duplicate_ids(path, {"go-one": digest})
            path.write_text(header + f"go-one\t{digest}\t\n", encoding="utf-8")
            self.assertEqual(BATCH.duplicate_ids(path, {"go-one": digest}), set())

    def test_assess_routes_duplicates_and_semantic_rows_without_scaffolding(self):
        proposals = [
            {"id": "go-duplicate-rule", "classification": "syntactic"},
            {"id": "go-dataflow-rule", "classification": "taint"},
            {"id": "go-syntax-rule", "classification": "syntactic"},
        ]
        with patch.object(BATCH, "seed_status", return_value=("AI-DRAFT", "contrast")) as seed:
            rows = BATCH.assess(proposals, {"go-duplicate-rule"}, Path("proposals"),
                                "correctness")
        self.assertEqual([row["action"] for row in rows],
                         ["DUP-REVIEW", "SEMANTIC-REVIEW", "AI-DRAFT"])
        seed.assert_called_once_with(Path("proposals"), "go-syntax-rule", "correctness")

    def test_assess_rejects_malformed_and_duplicate_proposals(self):
        for proposals, message in (([[]], "object"),
                                   ([{"id": "go-x", "classification": 1}], "string"),
                                   ([{"id": "go-x", "classification": "noise"},
                                     {"id": "go-x", "classification": "noise"}], "duplicate")):
            with self.subTest(message=message), self.assertRaisesRegex(BATCH.BatchError, message):
                BATCH.assess(proposals, set(), Path("proposals"), "correctness")

    def test_seed_status_requires_explicit_oracle_verdict(self):
        cases = (
            (completed(stdout="SEED PASS fixture oracle; review\n"), "SEEDED-REVIEW", None),
            (completed(stdout="SEED NONE; author matcher\n"), "AI-DRAFT",
             "no safe seed; CONTRAST unavailable; rerun scaffold assessment"),
            (completed(stdout="no verdict\n"), "BLOCKED", None),
            (completed(1, stderr="invalid proposal\n"), "BLOCKED", None),
        )
        for result, expected, expected_detail in cases:
            with self.subTest(expected=expected), patch.object(BATCH, "run", return_value=result):
                action, detail = BATCH.seed_status(Path("p.jsonl"), "go-test-rule", "security")
                self.assertEqual(action, expected)
                if expected_detail is not None:
                    self.assertEqual(detail, expected_detail)
        with patch.object(BATCH, "run", side_effect=BATCH.BatchError("scaffold timed out")):
            action, detail = BATCH.seed_status(Path("p.jsonl"), "go-test-rule", "security")
        self.assertEqual(action, "BLOCKED")
        self.assertIn("timed out", detail)

    def test_seed_status_routes_from_first_line_and_bounds_contrast(self):
        contrast = 'CONTRAST near-only=["SEED PASS fixture oracle"]; ' + "x" * 300 + "TAIL"
        spoofed = completed(stdout=f"SEED NONE; author matcher\n{contrast}\n")
        with patch.object(BATCH, "run", return_value=spoofed):
            action, detail = BATCH.seed_status(Path("p.jsonl"), "go-test-rule", "security")
        self.assertEqual(action, "AI-DRAFT")
        self.assertEqual(detail, f"no safe seed; {contrast[:300]}")
        self.assertNotIn("TAIL", detail)

    def test_seed_status_short_circuits_existing_rule_without_subprocess(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(BATCH, "ROOT", Path(directory)):
            rule = Path(directory) / "rules/go/security/go-test-rule.yml"
            rule.parent.mkdir(parents=True)
            rule.write_text("id: go-test-rule\n")
            with patch.object(BATCH, "run") as runner:
                action, _ = BATCH.seed_status(Path("p"), "go-test-rule", "security")
            self.assertEqual(action, "EXISTING-REVIEW")
            runner.assert_not_called()

    def test_apply_seeded_records_probe_pass_and_bounds_failures(self):
        rows = [
            {"id": "go-seeded-rule", "action": "SEEDED-REVIEW", "detail": ""},
            {"id": "go-manual-rule", "action": "AI-DRAFT", "detail": ""},
        ]
        proposal = {"id": "go-seeded-rule"}
        with patch.object(BATCH, "read_jsonl", return_value=[proposal]), \
                patch.object(BATCH, "run", side_effect=[
                completed(stdout="wrote pair\n"),
                completed(stdout="go-seeded-rule: PASS 1/4\n")]) as runner, \
                patch.object(BATCH, "probe_passed", return_value=True):
            self.assertEqual(BATCH.apply_seeded(rows, Path("p"), Path("w"), "correctness"), 0)
        self.assertEqual(runner.call_args_list, [
            call([sys.executable, str(BATCH.SCAFFOLD), "--proposal", "p",
                  "--id", "go-seeded-rule", "--category", "correctness",
                  "--seed", "--contrast"]),
            call([sys.executable, str(BATCH.DRAFT), "go-seeded-rule", "--work", "w"]),
        ])
        self.assertEqual(rows[0]["action"], "SEEDED-PASS")
        self.assertEqual(rows[1]["action"], "AI-DRAFT")

        rows[0]["action"] = "SEEDED-REVIEW"
        with patch.object(BATCH, "read_jsonl", return_value=[proposal]), \
                patch.object(BATCH, "run", side_effect=[completed(), completed(stdout="")]), \
                patch.object(BATCH, "probe_passed", return_value=False):
            self.assertEqual(BATCH.apply_seeded(rows, Path("p"), Path("w"), "correctness"), 1)
        self.assertEqual(rows[0]["action"], "PROBE-FAILED")
        self.assertIn("scaffolded pair and rule count retained", rows[0]["detail"])

    def test_apply_seeded_clears_provisional_terminal_state(self):
        rows = [{"id": "go-seeded-rule", "action": "SEEDED-REVIEW", "detail": ""}]
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            state = work / "draft/go-seeded-rule.json"
            state.parent.mkdir()
            state.write_text('{"rule":"go-seeded-rule","status":"PASS"}\n')
            with patch.object(BATCH, "read_jsonl",
                              return_value=[{"id": "go-seeded-rule"}]), \
                    patch.object(BATCH, "run", side_effect=[completed(), completed()]), \
                    patch.object(BATCH, "probe_passed", return_value=True):
                self.assertEqual(BATCH.apply_seeded(
                    rows, Path("proposals"), work, "correctness"), 0)
            self.assertFalse(state.exists())
            self.assertEqual(rows[0]["action"], "SEEDED-PASS")

    def test_apply_seeded_records_subprocess_exceptions_per_candidate(self):
        for results, expected in (
                ([BATCH.BatchError("scaffold timed out")], "APPLY-FAILED"),
                ([completed(stdout="wrote pair\n"), BATCH.BatchError("probe timed out")],
                 "PROBE-FAILED")):
            rows = [{"id": "go-seeded-rule", "action": "SEEDED-REVIEW", "detail": ""}]
            with self.subTest(expected=expected), \
                    patch.object(BATCH, "read_jsonl",
                                 return_value=[{"id": "go-seeded-rule"}]), \
                    patch.object(BATCH, "run", side_effect=results):
                failures = BATCH.apply_seeded(
                    rows, Path("p"), Path("w"), "correctness")
            self.assertEqual(failures, 1)
            self.assertEqual(rows[0]["action"], expected)
            self.assertIn("timed out", rows[0]["detail"])

    def test_probe_pass_requires_matching_terminal_state(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            state = work / "draft/go-test-rule.json"
            state.parent.mkdir()
            verdict = completed(stdout="go-test-rule: PASS 1/4\n")
            state.write_text(json.dumps({"rule": "go-test-rule", "status": "PASS",
                                         "attempts": [{}]}))
            self.assertTrue(BATCH.probe_passed(work, "go-test-rule", verdict))
            state.write_text(json.dumps({"rule": "go-test-rule", "status": "RETRY",
                                         "attempts": [{}]}))
            self.assertFalse(BATCH.probe_passed(work, "go-test-rule", verdict))
            for malformed in ([], None, "state"):
                with self.subTest(malformed=malformed):
                    state.write_text(json.dumps(malformed), encoding="utf-8")
                    self.assertFalse(BATCH.probe_passed(work, "go-test-rule", verdict))

    def test_relative_work_is_resolved_before_child_tools_run(self):
        if not (ROOT / "node_modules/.bin/ast-grep").is_file():
            self.skipTest("pinned ast-grep engine is not installed")
        proposal = {"id": "go-relative-work-rule", "language": "go",
                    "claim": "Report bad calls", "classification": "syntactic",
                    "positive": "package p\nfunc f(){ bad(x) }",
                    "near_miss": "package p\nfunc f(){ good(x) }",
                    "rationale": "syntactic contrast", "supporting": ["abc123"],
                    "overlaps": []}
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            work = parent / "work"
            (work / "cluster").mkdir(parents=True)
            (work / "cluster/proposals.jsonl").write_text(
                json.dumps(proposal) + "\n", encoding="utf-8")
            digest = BATCH.proposal_digest(proposal)
            (work / "dedupe.tsv").write_text(
                "proposal\tproposal_digest\tflag\n"
                f"go-relative-work-rule\t{digest}\t\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/rule-batch.py"), "--work", "work",
                 "--category", "correctness", "--dry-run"], cwd=parent,
                capture_output=True, text=True, check=False, timeout=180)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_main_dry_run_json_is_bounded_and_does_not_write_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            proposals = work / "cluster/proposals.jsonl"
            proposals.parent.mkdir()
            proposals.write_text(json.dumps({
                "id": "go-test-rule", "classification": "syntactic"}) + "\n")
            proposal = {"id": "go-test-rule", "classification": "syntactic"}
            digest = BATCH.proposal_digest(proposal)
            (work / "dedupe.tsv").write_text(
                f"proposal\tproposal_digest\tflag\ngo-test-rule\t{digest}\t\n")
            args = ["rule-batch", "--work", str(work), "--category", "correctness",
                    "--dry-run", "--json"]
            with patch("sys.argv", args), patch.object(
                    BATCH, "seed_status", return_value=("SEEDED-REVIEW", "passed")), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(BATCH.main(), 0)
            self.assertEqual(json.loads(output.getvalue())["actions"], {"SEEDED-REVIEW": 1})
            self.assertFalse((work / "draft-plan.tsv").exists())

    def test_write_plan_is_reproducible(self):
        rows = [{"id": "go-test-rule", "category": "correctness",
                 "classification": "syntactic", "duplicate": "no",
                 "action": "AI-DRAFT", "detail": "needs matcher"}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "draft-plan.tsv"
            BATCH.write_plan(path, rows)
            first = path.read_bytes()
            BATCH.write_plan(path, rows)
            self.assertEqual(path.read_bytes(), first)

    def test_replanning_preserves_batch_owned_actionable_rule(self):
        proposal = {"id": "go-test-rule", "language": "go",
                    "classification": "syntactic"}
        for action in BATCH.ACTIONABLE:
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                root = work / "repo"
                (work / "cluster").mkdir()
                (work / "cluster/proposals.jsonl").write_text(
                    json.dumps(proposal) + "\n", encoding="utf-8")
                (work / "dedupe.tsv").write_text(
                    "proposal\tproposal_digest\tflag\n"
                    f"go-test-rule\t{BATCH.proposal_digest(proposal)}\t\n", encoding="utf-8")
                BATCH.write_plan(work / "draft-plan.tsv", [{
                    "id": "go-test-rule", "category": "correctness",
                    "classification": "syntactic", "duplicate": "no",
                    "proposal_digest": BATCH.proposal_digest(proposal),
                    "candidate_digest": "", "action": action,
                    "detail": "batch-owned partial rule"}])
                rule = root / "rules/go/correctness/go-test-rule.yml"
                fixture = root / "tests/go/correctness/go-test-rule.yml"
                rule.parent.mkdir(parents=True)
                fixture.parent.mkdir(parents=True)
                rule.write_text("rule: {pattern: bad($X)}\n")
                fixture.write_text("valid: [good(x)]\ninvalid: [bad(x)]\n")
                fingerprint = BATCH.candidate_digest(rule, fixture, root)
                plan = BATCH.read_plan(work / "draft-plan.tsv")
                plan[0]["candidate_digest"] = fingerprint
                BATCH.write_plan(work / "draft-plan.tsv", plan)
                argv = ["rule-batch", "--work", str(work), "--category", "correctness"]
                with patch.object(BATCH, "ROOT", root), patch("sys.argv", argv), \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(BATCH.main(), 0)
                replanned = BATCH.read_plan(work / "draft-plan.tsv")
                self.assertEqual(replanned[0]["action"], action)
                self.assertEqual(replanned[0]["detail"], "batch-owned partial rule")

    def test_replanning_rejects_stale_actionable_provenance(self):
        prior = {"id": "go-test-rule", "category": "correctness",
                 "classification": "syntactic", "duplicate": "no",
                 "proposal_digest": "a" * 64, "candidate_digest": "b" * 64,
                 "action": "AI-DRAFT", "detail": "old route"}
        cases = (
            ("a" * 64, "", "deleted candidate"),
            ("a" * 64, "c" * 64, "replaced candidate"),
            ("d" * 64, "b" * 64, "revised proposal"),
        )
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            plan = work / "draft-plan.tsv"
            BATCH.write_plan(plan, [prior])
            for proposal_hash, candidate_hash, label in cases:
                with self.subTest(label=label):
                    rows = [{**prior, "proposal_digest": proposal_hash,
                             "candidate_digest": candidate_hash,
                             "action": "EXISTING-REVIEW", "detail": "existing"}]
                    BATCH.preserve_actionable_routes(rows, plan, work)
                    self.assertEqual(rows[0]["action"], "EXISTING-REVIEW")

    def test_replanning_accepts_current_candidate_from_valid_draft_state(self):
        prior = {"id": "go-test-rule", "category": "correctness",
                 "classification": "syntactic", "duplicate": "no",
                 "proposal_digest": "a" * 64, "candidate_digest": "b" * 64,
                 "action": "AI-DRAFT", "detail": "continue drafting"}
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            BATCH.write_plan(work / "draft-plan.tsv", [prior])
            state = work / "draft/go-test-rule.json"
            state.parent.mkdir()
            state.write_text(json.dumps({
                "schema": 1, "rule": "go-test-rule", "status": "RETRY",
                "attempts": [{"candidate": "c" * 64, "matcher": "pattern: bad($X)",
                              "probe": "go-test-rule: FAIL"}],
            }), encoding="utf-8")
            rows = [{**prior, "candidate_digest": "c" * 64,
                     "action": "EXISTING-REVIEW", "detail": "existing"}]
            BATCH.preserve_actionable_routes(rows, work / "draft-plan.tsv", work)
            self.assertEqual(rows[0]["action"], "AI-DRAFT")
            self.assertEqual(rows[0]["detail"], "continue drafting")

    def test_replanning_converts_bound_probe_failure_to_ai_draft(self):
        prior = {"id": "go-test-rule", "category": "correctness",
                 "classification": "syntactic", "duplicate": "no",
                 "proposal_digest": "a" * 64, "candidate_digest": "b" * 64,
                 "action": "PROBE-FAILED", "detail": "probe failed"}
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            plan = work / "draft-plan.tsv"
            BATCH.write_plan(plan, [prior])
            rows = [{**prior, "action": "EXISTING-REVIEW", "detail": "existing"}]
            BATCH.preserve_actionable_routes(rows, plan, work)
            self.assertEqual(rows[0]["action"], "AI-DRAFT")
            self.assertEqual(rows[0]["detail"], "probe failed")

    def test_main_binds_candidate_created_by_seed_apply(self):
        proposal = {"id": "go-test-rule", "language": "go",
                    "classification": "syntactic"}
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            root = work / "repo"
            (work / "cluster").mkdir()
            (work / "cluster/proposals.jsonl").write_text(
                json.dumps(proposal) + "\n", encoding="utf-8")
            (work / "dedupe.tsv").write_text(
                "proposal\tproposal_digest\tflag\n"
                f"go-test-rule\t{BATCH.proposal_digest(proposal)}\t\n", encoding="utf-8")

            def create_seed(rows, _proposal_path, _work, _category):
                rule = root / "rules/go/correctness/go-test-rule.yml"
                fixture = root / "tests/go/correctness/go-test-rule.yml"
                rule.parent.mkdir(parents=True)
                fixture.parent.mkdir(parents=True)
                rule.write_text("rule: {pattern: bad($X)}\n")
                fixture.write_text("valid: [good(x)]\ninvalid: [bad(x)]\n")
                rows[0]["action"] = "SEEDED-PASS"
                return 0

            argv = ["rule-batch", "--work", str(work), "--category", "correctness",
                    "--apply-seeded"]
            with patch.object(BATCH, "ROOT", root), patch("sys.argv", argv), \
                    patch.object(BATCH, "seed_status", return_value=("SEEDED-REVIEW", "seed")), \
                    patch.object(BATCH, "apply_seeded", side_effect=create_seed), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(BATCH.main(), 0)
            row = BATCH.read_plan(work / "draft-plan.tsv")[0]
            self.assertEqual(row["action"], "SEEDED-PASS")
            self.assertEqual(row["candidate_digest"], BATCH.candidate_digest(
                root / "rules/go/correctness/go-test-rule.yml",
                root / "tests/go/correctness/go-test-rule.yml", root))

    def test_task_emission_rejects_revised_proposal_with_refreshed_dedupe(self):
        proposal = {"id": "go-test-rule", "language": "go", "claim": "old",
                    "classification": "syntactic"}
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "cluster").mkdir()
            BATCH.write_plan(work / "draft-plan.tsv", [{
                "id": "go-test-rule", "category": "correctness",
                "classification": "syntactic", "duplicate": "no",
                "proposal_digest": BATCH.proposal_digest(proposal),
                "candidate_digest": "", "action": "AI-DRAFT", "detail": "draft"}])
            proposal["claim"] = "revised"
            (work / "cluster/proposals.jsonl").write_text(
                json.dumps(proposal) + "\n", encoding="utf-8")
            (work / "dedupe.tsv").write_text(
                "proposal\tproposal_digest\tflag\n"
                f"go-test-rule\t{BATCH.proposal_digest(proposal)}\t\n", encoding="utf-8")
            with self.assertRaisesRegex(BATCH.BatchError, "proposal identity is stale"):
                BATCH.draft_tasks(work, "correctness")

    def test_candidate_digest_tracks_every_probe_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rule = root / "rules/go/correctness/go-test-rule.yml"
            fixture = root / "tests/go/correctness/go-test-rule.yml"
            rule.parent.mkdir(parents=True)
            fixture.parent.mkdir(parents=True)
            rule.write_text("rule: {pattern: bad($X)}\n")
            fixture.write_text("valid: [good(x)]\ninvalid: [bad(x)]\n")
            baseline = BATCH.candidate_digest(rule, fixture, root)
            supporting = (
                root / "tests/__snapshots__/go-test-rule-snapshot.yml",
                root / "tests/arm_coverage.json",
            )
            for path in supporting:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("probe input\n")
                with self.subTest(path=path):
                    self.assertNotEqual(BATCH.candidate_digest(rule, fixture, root), baseline)
                path.unlink()

    def test_queue_and_task_hide_unrelated_proposals_and_terminal_drafts(self):
        proposals = [
            {"id": "go-first-rule", "language": "go", "claim": "first claim",
             "classification": "syntactic", "positive": "bad(x)",
             "near_miss": "good(x)", "rationale": "first reason"},
            {"id": "go-finished-rule", "language": "go", "claim": "finished claim",
             "classification": "syntactic", "positive": "old(x)",
             "near_miss": "new(x)", "rationale": "finished reason"},
            {"id": "go-semantic-rule", "language": "go", "claim": "semantic claim",
             "classification": "taint", "positive": "sink(x)",
             "near_miss": "sink(safe)", "rationale": "semantic reason"},
        ]
        rows = [
            {"id": "go-first-rule", "category": "correctness",
             "classification": "syntactic", "duplicate": "no",
             "action": "AI-DRAFT", "detail": "needs matcher"},
            {"id": "go-finished-rule", "category": "correctness",
             "classification": "syntactic", "duplicate": "no",
             "action": "SEEDED-PASS", "detail": "seeded"},
            {"id": "go-semantic-rule", "category": "correctness",
             "classification": "taint", "duplicate": "no",
             "action": "SEMANTIC-REVIEW", "detail": "needs judgment"},
        ]
        for row, proposal in zip(rows, proposals, strict=True):
            row["proposal_digest"] = BATCH.proposal_digest(proposal)
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            root = work / "repo"
            (work / "cluster").mkdir()
            (work / "cluster/proposals.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in proposals), encoding="utf-8")
            (work / "dedupe.tsv").write_text(
                "proposal\tproposal_digest\tflag\n" + "".join(
                    f"{row['id']}\t{BATCH.proposal_digest(row)}\t\n" for row in proposals),
                encoding="utf-8")
            BATCH.write_plan(work / "draft-plan.tsv", rows)
            (work / "draft").mkdir()
            rule = root / "rules/go/correctness/go-finished-rule.yml"
            fixture = root / "tests/go/correctness/go-finished-rule.yml"
            rule.parent.mkdir(parents=True)
            fixture.parent.mkdir(parents=True)
            rule.write_text("rule: {pattern: bad($X)}\n")
            fixture.write_text("valid: [good(x)]\ninvalid: [bad(x)]\n")
            finished = proposals[1]
            finished_fingerprint = BATCH.candidate_digest(rule, fixture, root)
            finished_state = work / "draft/go-finished-rule.json"
            finished_state.write_text(json.dumps(pass_state(
                "go-finished-rule", finished_fingerprint)), encoding="utf-8")
            (work / "draft/go-first-rule.json").write_text(json.dumps({
                "rule": "go-first-rule", "status": []}), encoding="utf-8")
            with patch.object(BATCH, "ROOT", root), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(BATCH.emit_tasks(work, "correctness", None, True), 0)
            self.assertNotIn("go-first-rule", BATCH.draft_states(work),
                             "partial state must fail the authoritative schema")
            queue = json.loads(output.getvalue())
            self.assertEqual(queue["tasks"], [
                {"action": "AI-DRAFT", "id": "go-first-rule"},
                {"action": "SEEDED-PASS", "id": "go-finished-rule"},
            ])
            with patch.object(BATCH, "ROOT", root), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(BATCH.emit_tasks(
                    work, "correctness", "go-first-rule", True), 0)
            task = json.loads(output.getvalue())
            self.assertEqual(task["claim"], "first claim")
            self.assertEqual(task["focus"], "author and probe the matcher")
            self.assertNotIn("finished claim", output.getvalue())
            self.assertNotIn("semantic claim", output.getvalue())
            self.assertEqual(task["draft_command"][-3:],
                             ["go-first-rule", "--work", str(work)])
            with patch.object(BATCH, "ROOT", root), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(BATCH.emit_tasks(
                    work, "correctness", "go-finished-rule", True), 0)
            seeded = json.loads(output.getvalue())
            self.assertIn("review provisional seed matcher", seeded["focus"])
            self.assertEqual(seeded["reviewed_command"][-2:],
                             ["--mark-reviewed", "go-finished-rule"])
            with patch.object(BATCH, "ROOT", root), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(BATCH.mark_reviewed(
                    work, "correctness", "go-finished-rule"), 0)
            reviewed = json.loads((work / "draft-reviewed/go-finished-rule.json").read_text())
            self.assertEqual(reviewed["proposal_digest"], BATCH.proposal_digest(finished))
            with patch.object(BATCH, "ROOT", root):
                self.assertEqual(
                    [task["id"] for task in BATCH.draft_tasks(work, "correctness")],
                    ["go-first-rule"])
            finished_state.write_text(json.dumps(parked_state(
                "go-finished-rule", finished_fingerprint)), encoding="utf-8")
            with patch.object(BATCH, "ROOT", root):
                self.assertEqual(
                    [task["id"] for task in BATCH.draft_tasks(work, "correctness")],
                    ["go-first-rule"], "acknowledged PARKED state should be terminal")
            first_rule = root / "rules/go/correctness/go-first-rule.yml"
            first_fixture = root / "tests/go/correctness/go-first-rule.yml"
            first_rule.write_text("rule: {pattern: bad($X)}\n")
            first_fixture.write_text("valid: [good(x)]\ninvalid: [bad(x)]\n")
            first_fingerprint = BATCH.candidate_digest(first_rule, first_fixture, root)
            (work / "draft/go-first-rule.json").write_text(json.dumps(pass_state(
                "go-first-rule", first_fingerprint)), encoding="utf-8")
            with patch.object(BATCH, "ROOT", root):
                self.assertEqual(
                    [task["id"] for task in BATCH.draft_tasks(work, "correctness")],
                    ["go-first-rule"], "a PASS still needs explicit review acknowledgment")
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(BATCH.mark_reviewed(
                        work, "correctness", "go-first-rule"), 0)
                self.assertEqual(BATCH.draft_tasks(work, "correctness"), [])
            saved_state = finished_state.read_text()
            finished_state.unlink()
            with patch.object(BATCH, "ROOT", root):
                self.assertEqual(
                    [task["id"] for task in BATCH.draft_tasks(work, "correctness")],
                    ["go-finished-rule"], "acknowledgment cannot replace PASS evidence")
            finished_state.write_text(saved_state)
            finished["claim"] = "revised finished claim"
            (work / "cluster/proposals.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in proposals), encoding="utf-8")
            (work / "dedupe.tsv").write_text(
                "proposal\tproposal_digest\tflag\n" + "".join(
                    f"{row['id']}\t{BATCH.proposal_digest(row)}\t\n" for row in proposals),
                encoding="utf-8")
            rows[1]["proposal_digest"] = BATCH.proposal_digest(finished)
            BATCH.write_plan(work / "draft-plan.tsv", rows)
            with patch.object(BATCH, "ROOT", root):
                self.assertEqual(
                    [task["id"] for task in BATCH.draft_tasks(work, "correctness")],
                    ["go-finished-rule"])

    def test_task_emission_rejects_stale_plan_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "cluster").mkdir()
            (work / "cluster/proposals.jsonl").write_text(json.dumps({
                "id": "go-test-rule", "language": "go"}) + "\n", encoding="utf-8")
            proposal = {"id": "go-test-rule", "language": "go"}
            (work / "dedupe.tsv").write_text(
                "proposal\tproposal_digest\tflag\n"
                f"go-test-rule\t{BATCH.proposal_digest(proposal)}\t\n", encoding="utf-8")
            BATCH.write_plan(work / "draft-plan.tsv", [])
            with self.assertRaisesRegex(BATCH.BatchError, "does not exactly cover"):
                BATCH.draft_tasks(work, "security")

    def test_task_emission_rejects_stale_proposal_content(self):
        proposal = {"id": "go-test-rule", "language": "go",
                    "classification": "syntactic"}
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "cluster").mkdir()
            (work / "cluster/proposals.jsonl").write_text(
                json.dumps(proposal) + "\n", encoding="utf-8")
            (work / "dedupe.tsv").write_text(
                "proposal\tproposal_digest\tflag\n"
                f"go-test-rule\t{'0' * 64}\t\n", encoding="utf-8")
            BATCH.write_plan(work / "draft-plan.tsv", [{
                "id": "go-test-rule", "category": "security",
                "classification": "syntactic",
                "duplicate": "no", "action": "AI-DRAFT", "detail": "draft"}])
            with self.assertRaisesRegex(BATCH.BatchError, "stale"):
                BATCH.draft_tasks(work, "security")

    def test_task_emission_rechecks_actionable_eligibility(self):
        for classification, duplicate in (("taint", "no"), ("syntactic", "yes")):
            with self.subTest(classification=classification, duplicate=duplicate), \
                    tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                (work / "cluster").mkdir()
                proposal = {"id": "go-test-rule", "language": "go",
                            "classification": classification}
                (work / "cluster/proposals.jsonl").write_text(
                    json.dumps(proposal) + "\n", encoding="utf-8")
                flag = "DUP?" if duplicate == "yes" else ""
                (work / "dedupe.tsv").write_text(
                    "proposal\tproposal_digest\tflag\n"
                    f"go-test-rule\t{BATCH.proposal_digest(proposal)}\t{flag}\n",
                    encoding="utf-8")
                BATCH.write_plan(work / "draft-plan.tsv", [{
                    "id": "go-test-rule", "category": "security",
                    "classification": classification,
                    "duplicate": duplicate, "action": "AI-DRAFT", "detail": "tampered"}])
                with self.assertRaisesRegex(BATCH.BatchError, "ineligible"):
                    BATCH.draft_tasks(work, "security")

    def test_task_emission_rejects_plan_category_replay(self):
        proposal = {"id": "go-test-rule", "language": "go",
                    "classification": "syntactic"}
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "cluster").mkdir()
            (work / "cluster/proposals.jsonl").write_text(
                json.dumps(proposal) + "\n", encoding="utf-8")
            (work / "dedupe.tsv").write_text(
                "proposal\tproposal_digest\tflag\n"
                f"go-test-rule\t{BATCH.proposal_digest(proposal)}\t\n", encoding="utf-8")
            BATCH.write_plan(work / "draft-plan.tsv", [{
                "id": "go-test-rule", "category": "correctness",
                "classification": "syntactic", "duplicate": "no",
                "action": "AI-DRAFT", "detail": "draft"}])
            with self.assertRaisesRegex(BATCH.BatchError, "category is stale"):
                BATCH.draft_tasks(work, "security")

    def test_main_bounds_plan_write_failure(self):
        argv = ["rule-batch", "--work", "work", "--category", "correctness"]
        with patch("sys.argv", argv), \
                patch.object(BATCH, "read_jsonl", return_value=[]), \
                patch.object(BATCH, "proposal_ids", return_value=set()), \
                patch.object(BATCH, "duplicate_ids", return_value=set()), \
                patch.object(BATCH, "assess", return_value=[]), \
                patch.object(BATCH, "write_plan", side_effect=OSError("read only")), \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(BATCH.main(), 2)
        self.assertIn("rule-batch: ERROR: read only", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
