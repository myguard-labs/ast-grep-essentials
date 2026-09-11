"""State-machine tests for the bounded one-rule drafting driver."""

import contextlib
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("rule_draft", ROOT / "tools/rule-draft.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load rule-draft.py")
DRAFT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRAFT)


class RuleDraftTests(unittest.TestCase):
    def setUp(self):
        # enterContext supplies the with-equivalent cleanup Pylint requests.
        # pylint: disable=consider-using-with
        self.temporary = Path(self.enterContext(tempfile.TemporaryDirectory()))
        # pylint: enable=consider-using-with
        self.root = self.temporary / "repo"
        self.work = self.temporary / "work"
        self.rule = self.root / "rules/go/security/go-test-rule.yml"
        self.fixture = self.root / "tests/go/security/go-test-rule.yml"
        self.rule.parent.mkdir(parents=True)
        self.fixture.parent.mkdir(parents=True)
        self.rule.write_text(
            "id: go-test-rule\nlanguage: go\nrule:\n  pattern: bad($X)\n",
            encoding="utf-8")
        self.initial_rule = self.rule.read_text(encoding="utf-8")
        self.fixture.write_text(
            "id: go-test-rule\nvalid: [good(x)]\ninvalid: [bad(x)]\n",
            encoding="utf-8")

    def advance(self, results):
        calls = []

        def run(command, **_kwargs):
            calls.append(command)
            return results.pop(0)

        with patch.object(DRAFT, "ROOT", self.root), \
                patch.object(DRAFT, "PROBE", self.root / "tools/rule-probe.py"), \
                patch.object(DRAFT.subprocess, "run", side_effect=run), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            result = DRAFT.advance("go-test-rule", self.work)
        return result, output.getvalue(), calls

    @staticmethod
    def failed(detail="fixture-counts: invalid[0]=0"):
        return SimpleNamespace(returncode=1,
                               stdout=f"rules/go/security/go-test-rule.yml: FAIL\n"
                                      f"  [FAIL] {detail}\n",
                               stderr="")

    @staticmethod
    def passed():
        return SimpleNamespace(returncode=0,
                               stdout="rules/go/security/go-test-rule.yml: PASS\n",
                               stderr="")

    def test_distinct_failures_park_on_fourth_attempt(self):
        for attempt in range(1, 5):
            self.rule.write_text(self.rule.read_text(encoding="utf-8") + f"# {attempt}\n",
                                 encoding="utf-8")
            result, output, calls = self.advance([self.failed()])
            self.assertEqual(result, 1)
            self.assertEqual(len(calls), 1)
            expected = "PARKED" if attempt == 4 else "RETRY"
            self.assertIn(f"go-test-rule: {expected} {attempt}/4", output)
        report = (self.work / "draft/go-test-rule.md").read_text(encoding="utf-8")
        self.assertEqual(report.count("## Attempt"), 4)

    def test_repeated_candidate_does_not_probe_or_consume_attempt(self):
        self.advance([self.failed()])
        result, output, calls = self.advance([])
        self.assertEqual(result, 2)
        self.assertEqual(calls, [])
        self.assertIn("REPEATED 1/4", output)
        state = json.loads((self.work / "draft/go-test-rule.json").read_text(
            encoding="utf-8"))
        self.assertEqual(len(state["attempts"]), 1)

        self.rule.write_text(self.initial_rule + "# second\n", encoding="utf-8")
        self.advance([self.failed()])
        self.rule.write_text(self.initial_rule, encoding="utf-8")
        result, output, calls = self.advance([])
        self.assertEqual(result, 2)
        self.assertEqual(calls, [])
        self.assertIn("REPEATED 2/4", output)

    def test_pass_is_terminal_and_idempotent(self):
        result, output, calls = self.advance([self.passed()])
        self.assertEqual(result, 0)
        self.assertEqual(len(calls), 1)
        self.assertIn("PASS 1/4", output)
        result, output, calls = self.advance([])
        self.assertEqual(result, 0)
        self.assertEqual(calls, [])
        self.assertEqual(output, "go-test-rule: PASS 1/4\n")

    def test_probe_uses_fingerprinted_bytes_during_aba_edit(self):
        observed = {}
        snapshot = self.root / "tests/__snapshots__/go-test-rule-snapshot.yml"
        coverage = self.root / "tests/arm_coverage.json"
        snapshot.parent.mkdir(parents=True)
        snapshot.write_bytes(b"snapshot bytes\n")
        coverage.write_bytes(b'{"cases": []}\n')

        def probe(command, **_kwargs):
            input_root = Path(command[command.index("--input-root") + 1])
            for source in (self.rule, self.fixture, snapshot, coverage):
                observed[source] = (input_root / source.relative_to(self.root)).read_bytes()
            self.rule.write_text(self.initial_rule + "# raced\n", encoding="utf-8")
            self.rule.write_text(self.initial_rule, encoding="utf-8")
            return self.passed()

        with patch.object(DRAFT, "ROOT", self.root), \
                patch.object(DRAFT, "PROBE", self.root / "tools/rule-probe.py"), \
                patch.object(DRAFT.subprocess, "run", side_effect=probe), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(DRAFT.advance("go-test-rule", self.work), 0)
        for source in (self.rule, self.fixture, snapshot, coverage):
            self.assertEqual(observed[source], source.read_bytes())
        state = json.loads((self.work / "draft/go-test-rule.json").read_text())
        expected = DRAFT.candidate(self.rule, self.fixture, self.root)[0]
        self.assertEqual(state["attempts"][0]["candidate"], expected)

    def test_failed_verdict_without_gate_details_prints_one_line(self):
        failed = SimpleNamespace(
            returncode=1,
            stdout="rules/go/security/go-test-rule.yml: FAIL\n",
            stderr="",
        )
        result, output, _calls = self.advance([failed])
        self.assertEqual(result, 1)
        self.assertEqual(output, "go-test-rule: RETRY 1/4\n")

    def test_terminal_state_rejects_changed_probe_input(self):
        supporting = (
            self.root / "tests/__snapshots__/go-test-rule-snapshot.yml",
            self.root / "tests/arm_coverage.json",
        )
        supporting[0].parent.mkdir(parents=True)
        supporting[0].write_bytes(b"snapshot bytes\n")
        supporting[1].write_bytes(b'{"cases": []}\n')
        self.advance([self.passed()])
        for path in (self.rule, self.fixture, *supporting):
            original = path.read_bytes()
            path.write_bytes(original + b"# changed\n")
            with self.subTest(path=path), patch.object(DRAFT, "ROOT", self.root), \
                    self.assertRaisesRegex(DRAFT.DraftError, "different probe inputs"):
                DRAFT.advance("go-test-rule", self.work)
            path.write_bytes(original)

    def test_pass_with_sexp_is_valid_terminal_state(self):
        passed = self.passed()
        passed.stdout += "  sexp 'bad($X)':\n    (call_expression)\n"
        self.advance([passed])
        result, output, calls = self.advance([])
        self.assertEqual(result, 0)
        self.assertEqual(calls, [])
        self.assertEqual(output, "go-test-rule: PASS 1/4\n")

    def test_malformed_state_fails_closed(self):
        state = self.work / "draft/go-test-rule.json"
        state.parent.mkdir(parents=True)
        state.write_text('{"schema": 1}', encoding="utf-8")
        with patch.object(DRAFT, "ROOT", self.root), self.assertRaises(DRAFT.DraftError):
            DRAFT.advance("go-test-rule", self.work)

    def test_nonstring_state_status_reports_cli_error(self):
        state_path = self.work / "draft/go-test-rule.json"
        state_path.parent.mkdir(parents=True)
        for status in ([], {}):
            with self.subTest(status=status):
                state_path.write_text(json.dumps({
                    "schema": 1,
                    "rule": "go-test-rule",
                    "status": status,
                    "attempts": [],
                }), encoding="utf-8")
                argv = ["rule-draft.py", "go-test-rule", "--work", str(self.work)]
                with patch.object(DRAFT, "ROOT", self.root), patch("sys.argv", argv), \
                        contextlib.redirect_stderr(io.StringIO()) as error:
                    self.assertEqual(DRAFT.main(), 2)
                self.assertIn("rule-draft: ERROR: unknown state", error.getvalue())

    def test_state_verdict_must_match_transition(self):
        self.advance([self.failed()])
        state_path = self.work / "draft/go-test-rule.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["attempts"][0]["probe"] = "go-test-rule: PASS"
        state_path.write_text(json.dumps(state), encoding="utf-8")
        with patch.object(DRAFT, "ROOT", self.root), self.assertRaises(DRAFT.DraftError):
            DRAFT.advance("go-test-rule", self.work)

    def test_invalid_probe_verdict_does_not_create_state(self):
        for stdout in ("not a verdict\n", "go-test-rule: PASS but not really\n", ""):
            with self.subTest(stdout=stdout):
                broken = SimpleNamespace(returncode=0, stdout=stdout, stderr="")
                with self.assertRaises(DRAFT.DraftError):
                    self.advance([broken])
                self.assertFalse((self.work / "draft/go-test-rule.json").exists())

    def test_probe_infrastructure_failure_does_not_consume_attempt(self):
        unavailable = SimpleNamespace(
            returncode=2,
            stdout=("rules/go/security/go-test-rule.yml: FAIL\n"
                    "  [FAIL] ast-grep-available: run npm ci to install ast-grep\n"),
            stderr="",
        )
        with self.assertRaisesRegex(DRAFT.DraftError, "invalid verdict"):
            self.advance([unavailable])
        self.assertFalse((self.work / "draft/go-test-rule.json").exists())
        result, output, calls = self.advance([self.passed()])
        self.assertEqual(result, 0)
        self.assertEqual(len(calls), 1)
        self.assertIn("PASS 1/4", output)

    def test_probe_timeout_covers_all_bounded_phases(self):
        matcher = "any:\n- pattern: a\n- any:\n  - pattern: b\n  - pattern: c\n  - pattern: d\n"
        fixture = b"valid: [a, b]\ninvalid: [c]\n"
        self.assertEqual(DRAFT.probe_timeout(matcher, fixture, False), 396)
        self.assertEqual(DRAFT.probe_timeout(matcher, fixture, True), 486)

    def test_probe_timeout_has_a_distinct_diagnostic(self):
        with patch.object(DRAFT.subprocess, "run",
                          side_effect=subprocess.TimeoutExpired("probe", 396)), \
                self.assertRaisesRegex(DRAFT.DraftError, "probe timed out after 396s"):
            DRAFT.run_probe("go-test-rule", False, self.root, 396)

    def test_advance_propagates_timeout_without_consuming_attempt(self):
        expected = DRAFT.probe_timeout(
            yaml.safe_dump(yaml.safe_load(self.rule.read_text())["rule"]),
            self.fixture.read_bytes(), False)

        def expire(_command, **kwargs):
            self.assertEqual(kwargs["timeout"], expected)
            raise subprocess.TimeoutExpired("probe", kwargs["timeout"])

        with patch.object(DRAFT, "ROOT", self.root), \
                patch.object(DRAFT, "PROBE", self.root / "tools/rule-probe.py"), \
                patch.object(DRAFT.subprocess, "run", side_effect=expire), \
                self.assertRaisesRegex(DRAFT.DraftError, f"timed out after {expected}s"):
            DRAFT.advance("go-test-rule", self.work)
        self.assertFalse((self.work / "draft/go-test-rule.json").exists())
        result, _output, _calls = self.advance([self.passed()])
        self.assertEqual(result, 0)
        state = json.loads((self.work / "draft/go-test-rule.json").read_text())
        self.assertEqual(len(state["attempts"]), 1)

    def test_parked_report_is_recreated_from_terminal_state(self):
        for attempt in range(4):
            self.rule.write_text(self.rule.read_text(encoding="utf-8") + f"# {attempt}\n",
                                 encoding="utf-8")
            self.advance([self.failed()])
        report = self.work / "draft/go-test-rule.md"
        report.unlink()
        result, output, calls = self.advance([])
        self.assertEqual(result, 1)
        self.assertEqual(calls, [])
        self.assertTrue(report.is_file())
        self.assertIn("PARKED 4/4", output)


if __name__ == "__main__":
    unittest.main()
