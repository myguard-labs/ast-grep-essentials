import contextlib
import io
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import yaml

from tests.mechanics_test_support import ROOT, load_tool, minimal_plan

PLAN = load_tool("rule-plan")
MECHANICS = load_tool("rule-mechanics")


class RuleMechanicsTests(unittest.TestCase):
    def test_bounded_scan_interrupt_kills_reaps_and_reraises(self):
        for failure in (KeyboardInterrupt(), RuntimeError("interrupted")):
            process = MagicMock(pid=4242)
            process.__enter__.return_value = process
            with self.subTest(failure=type(failure).__name__), \
                    patch.object(MECHANICS.subprocess, "Popen", return_value=process), \
                    patch.object(MECHANICS, "_read_bounded_process", side_effect=failure), \
                    patch.object(MECHANICS.PLAN, "signal_process_group") as signal_group, \
                    self.assertRaises(type(failure)):
                MECHANICS.bounded_scan_output(["engine"])
            signal_group.assert_called_once_with(4242, MECHANICS.signal.SIGKILL)
            process.wait.assert_called_once_with(timeout=10)

    def test_rendered_artifacts_thaw_compiled_plan_once(self):
        path = ROOT / "plans/python/security/py-tempfile-mktemp.yml"
        compiled = PLAN.compile_plan_ir(path, run_checks=False)
        with patch.object(MECHANICS.PLAN, "thaw", wraps=MECHANICS.PLAN.thaw) as thaw, \
                patch.object(MECHANICS.PLAN, "preflight"):
            # White-box assertion: this test owns the internal artifact boundary.
            # pylint: disable-next=protected-access
            MECHANICS._compiled_plan_artifacts(path, compiled=compiled)
        self.assertEqual(
            sum(call.args[0] is compiled.plan for call in thaw.call_args_list), 1)

    def test_plan_transaction_compiles_each_plan_once(self):
        path = ROOT / "plans/python/security/py-tempfile-mktemp.yml"
        original = MECHANICS.PLAN.compile_plan_ir
        with patch.object(MECHANICS, "plan_paths", return_value=[path]), \
                patch.object(MECHANICS.PLAN, "compile_plan_ir", wraps=original) as compile_ir, \
                patch.object(MECHANICS.PLAN, "preflight"), \
                patch.object(MECHANICS, "stale_generated_artifacts", return_value=[]), \
                patch.object(MECHANICS, "_changed_plan_artifacts", return_value=([], [])), \
                patch.object(MECHANICS, "validate_plan_fixes", return_value=0), \
                contextlib.redirect_stdout(io.StringIO()):
            # White-box assertion: this test owns the plan transaction boundary.
            # pylint: disable-next=protected-access
            self.assertEqual(MECHANICS._plans_command(False), 0)
        self.assertEqual(compile_ir.call_count, 1)

    def test_write_mode_locks_before_plan_transaction(self):
        events = []

        @contextlib.contextmanager
        def lock():
            events.append("lock-enter")
            yield
            events.append("lock-exit")

        def transaction(write):
            self.assertTrue(write)
            self.assertEqual(events, ["lock-enter"])
            events.append("transaction")
            return 0

        # White-box patch: the test verifies lock ordering at this boundary.
        # pylint: disable-next=protected-access
        with patch.object(MECHANICS.SCAFFOLD, "cli_scaffold_lock", return_value=lock()), \
                patch.object(MECHANICS, "_plans_command", side_effect=transaction):
            self.assertEqual(MECHANICS.plans_command(True), 0)
        self.assertEqual(events, ["lock-enter", "transaction", "lock-exit"])

    def test_oracle_mismatch_fails_exactly(self):
        plan = minimal_plan(oracles={"danger()": {"count": 2}})
        finding = {"text": "danger()", "range": {"byteOffset": {"start": 0, "end": 8}}}
        with patch.object(MECHANICS, "scan_rule", return_value=[finding]), \
                self.assertRaisesRegex(RuntimeError, "ORACLE_MISMATCH.*count"):
            MECHANICS.check_oracles(plan, {})

    def test_atomic_write_preserves_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.yml"
            path.write_text("old\n")
            path.chmod(0o640)
            MECHANICS.write_atomic(path, "new\n")
            self.assertEqual(path.read_text(), "new\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)

    def test_regeneration_refuses_unowned_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_path = root / "plans/python/security/py-sample.yml"
            rule_path = root / "rules/python/security/py-sample.yml"
            fixture_path = root / "tests/python/security/py-sample.yml"
            for path in (plan_path, rule_path, fixture_path):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("hand authored\n")
            generated = "# Generated from: plans/python/security/py-sample.yml\nid: py-sample\n"
            with self.assertRaisesRegex(RuntimeError, "refusing to overwrite"), \
                    patch.object(MECHANICS, "ROOT", root), \
                    patch.object(MECHANICS, "plan_paths", return_value=[plan_path]), \
                    patch.object(MECHANICS, "validate_plan_id_ownership"), \
                    patch.object(MECHANICS.PLAN, "compile_plan_ir",
                                 return_value=SimpleNamespace(plan=minimal_plan())), \
                    patch.object(MECHANICS, "_compiled_plan_artifacts", return_value=
                                 MECHANICS.RenderedPlan(
                                     minimal_plan(), rule_path,
                                     fixture_path, generated, generated)):
                MECHANICS.plans_command(True)

    def test_regeneration_validates_candidate_fixes_before_writing(self):
        target = ROOT / "rules/python/security/py-sample.yml"
        updates = [(target, "id: py-sample\n", "owner")]
        compiled = SimpleNamespace(plan=minimal_plan())
        artifacts = MECHANICS.RenderedPlan(
            minimal_plan(), target, target, "id: py-sample\n", "id: py-sample\n")
        with patch.object(MECHANICS, "plan_paths", return_value=[Path("plan.yml")]), \
                patch.object(MECHANICS.PLAN, "compile_plan_ir",
                             return_value=compiled), \
                patch.object(MECHANICS, "_compiled_plan_artifacts",
                             return_value=artifacts), \
                patch.object(MECHANICS, "validate_plan_id_ownership"), \
                patch.object(MECHANICS, "stale_generated_artifacts", return_value=[]), \
                patch.object(MECHANICS, "_changed_plan_artifacts",
                             return_value=(["rule"], updates)), \
                patch.object(MECHANICS, "validate_plan_fixes",
                             side_effect=RuntimeError("FIX_PARSE_FAILED")) as validate, \
                patch.object(MECHANICS, "_write_plan_artifacts") as write, \
                self.assertRaisesRegex(RuntimeError, "FIX_PARSE_FAILED"):
            MECHANICS.plans_command(True)
        self.assertEqual(validate.call_args.args[1], {target.resolve(): "id: py-sample\n"})
        self.assertEqual(validate.call_args.args[2], {Path("plan.yml"): artifacts})
        write.assert_not_called()

    def test_embedded_generation_marker_does_not_claim_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rule.yml"
            path.write_text(
                "id: hand-authored\n# Generated from: plans/python/security/claimed.yml\n",
                encoding="utf-8",
            )
            self.assertIsNone(MECHANICS.generated_owner(path))

    def test_deleted_plan_is_reported_as_stale_generated_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rule = root / "rules/python/security/py-removed.yml"
            fixture = root / "tests/python/security/py-removed.yml"
            for path in (rule, fixture):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    "# Generated from: plans/python/security/py-removed.yml\nid: py-removed\n",
                    encoding="utf-8",
                )
            with patch.object(MECHANICS, "ROOT", root), \
                    patch.object(MECHANICS, "plan_paths", return_value=[]), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(MECHANICS.plans_command(False), 1)

    def test_duplicate_plan_ids_are_rejected_before_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = []
            for language in ("python", "javascript"):
                path = root / f"plans/{language}/security/shared.yml"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(yaml.safe_dump(minimal_plan(id="shared", language=language)))
                paths.append(path)
            with patch.object(MECHANICS, "ROOT", root), \
                    self.assertRaisesRegex(RuntimeError, "PLAN_ID_COLLISION"):
                MECHANICS.validate_plan_id_ownership(paths)

    def test_fix_output_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            rule = Path(directory) / "fix.yml"
            rule.write_text(yaml.safe_dump({
                "id": "cpp-fix", "language": "cpp", "fix": "safe()",
                "rule": {"pattern": "danger()"},
            }))

            def run(command, **_kwargs):
                if "--update-all" in command:
                    target = Path(command[-1])
                    before = target.read_text(encoding="utf-8")
                    target.write_text("safe()" if before == "danger()" else before,
                                      encoding="utf-8")
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with self.assertRaisesRegex(RuntimeError, "FIX_OUTPUT_MISMATCH"), \
                    patch.object(MECHANICS.PLAN, "run_engine", side_effect=run), \
                    patch.object(MECHANICS, "scan_rule", return_value=[]):
                MECHANICS.validate_fix(rule, "danger()", "different()")

    def test_fixer_rejects_missing_node_only_rewrite(self):
        with tempfile.TemporaryDirectory() as directory:
            rule = Path(directory) / "fix.yml"
            rule.write_text(yaml.safe_dump({
                "id": "cpp-missing-fix", "language": "cpp", "fix": "if () {}",
                "rule": {"pattern": "danger()"},
            }))
            with self.assertRaisesRegex(RuntimeError,
                                        "FIX_PARSE_FAILED: cpp-missing-fix"):
                MECHANICS.validate_fix(rule, "danger()")

    def test_fixer_accepts_valid_multi_statement_rewrite(self):
        with tempfile.TemporaryDirectory() as directory:
            rule = Path(directory) / "fix.yml"
            rule.write_text(yaml.safe_dump({
                "id": "cpp-multi-fix", "language": "cpp", "fix": "safe(); other()",
                "rule": {"pattern": "danger()"},
            }))
            MECHANICS.validate_fix(
                rule, "danger();", "safe(); other();")

    def test_fixer_command_checks_every_invalid_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rule = root / "rules/cpp/security/cpp-fix.yml"
            fixture = root / "tests/cpp/security/cpp-fix.yml"
            rule.parent.mkdir(parents=True)
            fixture.parent.mkdir(parents=True)
            rule.write_text(yaml.safe_dump({
                "id": "cpp-fix", "language": "cpp", "fix": "safe()",
                "rule": {"pattern": "danger()"},
            }))
            fixture.write_text(yaml.safe_dump({
                "id": "cpp-fix", "valid": ["safe()"],
                "invalid": ["danger()", "danger();"],
            }))
            with patch.object(MECHANICS, "ROOT", root), \
                    patch.object(MECHANICS, "validate_fix") as validate:
                self.assertEqual(MECHANICS.fixes_command("cpp-fix"), 0)
            self.assertEqual([call.args[1] for call in validate.call_args_list],
                             ["danger()", "danger();"])


class RuleMechanicsCorpusTests(unittest.TestCase):
    def test_differential_is_duplicate_sensitive_and_stable(self):
        finding = ("rule", "x.py", 0, 1, "x", "message", "warning")
        with tempfile.TemporaryDirectory() as directory:
            old, new = Path(directory) / "old", Path(directory) / "new"
            old.write_bytes(b"old")
            new.write_bytes(b"new")
            output = io.StringIO()
            with patch.object(MECHANICS, "normalized_findings",
                              side_effect=[[finding, finding], [finding]]), \
                    contextlib.redirect_stdout(output):
                status = MECHANICS.differential_command(old, new, Path("config"), Path("corpus"))
            report = json.loads(output.getvalue())
            self.assertEqual(status, 1)
            self.assertEqual(report["removed"][0]["count"], 1)

    def test_versioned_corpus_rejects_behavior_drift(self):
        finding = ("rule", "sample.py", 0, 1, "x", "message", "warning")
        with tempfile.TemporaryDirectory() as directory:
            expected = Path(directory) / "expected.json"
            expected.write_text(json.dumps({"version": 1, "findings": []}),
                                encoding="utf-8")
            with patch.object(MECHANICS, "normalized_findings", return_value=[finding]), \
                    contextlib.redirect_stderr(io.StringIO()):
                status = MECHANICS.baseline_command(
                    Path("config"), Path("corpus"), expected, False)
            self.assertEqual(status, 1)

    def test_versioned_corpus_rejects_malformed_shape(self):
        with tempfile.TemporaryDirectory() as directory:
            expected = Path(directory) / "expected.json"
            expected.write_text("[]", encoding="utf-8")
            with patch.object(MECHANICS, "normalized_findings", return_value=[]), \
                    self.assertRaisesRegex(RuntimeError, "version 1"):
                MECHANICS.baseline_command(
                    Path("config"), Path("corpus"), expected, False)

    def test_corpus_file_bound_fails_before_engine_run(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "a.py").write_text("x")
            with patch.object(MECHANICS, "MAX_FILES", 0), \
                    patch.object(MECHANICS, "bounded_scan_output",
                                 return_value=b"[]") as engine_run:
                with self.assertRaisesRegex(RuntimeError, "corpus exceeds 0 files"):
                    MECHANICS.normalized_findings(Path("engine"), Path("config"), Path(directory))
                engine_run.assert_not_called()

    def test_normalized_findings_rejects_non_list_json(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(MECHANICS, "bounded_scan_output", return_value=b"{}"), \
                self.assertRaisesRegex(TypeError, "expected a finding list"):
            MECHANICS.normalized_findings(
                Path("engine"), Path("config"), Path(directory))

    def test_normalized_findings_rejects_malformed_entry(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(MECHANICS, "bounded_scan_output", return_value=b"[{}]"), \
                self.assertRaisesRegex(RuntimeError, "malformed.*finding"):
            MECHANICS.normalized_findings(
                Path("engine"), Path("config"), Path(directory))

    def test_normalized_finding_rejects_invalid_byte_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "sample.py"
            target.write_text("x", encoding="utf-8")
            for start, end in ((-1, 0), (2, 1)):
                finding = {
                    "ruleId": "sample",
                    "file": str(target),
                    "range": {"byteOffset": {"start": start, "end": end}},
                }
                with self.subTest(start=start, end=end), \
                        self.assertRaisesRegex(RuntimeError, "malformed.*finding"):
                    MECHANICS._normalize_finding(finding, root)

    def test_scan_output_bound_terminates_oversized_output(self):
        with patch.object(MECHANICS, "MAX_SCAN_OUTPUT_BYTES", 10), \
                self.assertRaisesRegex(RuntimeError, "scan output exceeds"):
            MECHANICS.bounded_scan_output(
                [sys.executable, "-c", "print('x' * 100)"])

    def test_scan_output_bound_terminates_stalled_process(self):
        with self.assertRaisesRegex(RuntimeError, "scan exceeded"):
            MECHANICS.bounded_scan_output(
                [sys.executable, "-c", "import time; time.sleep(2)"], timeout=0.05)
