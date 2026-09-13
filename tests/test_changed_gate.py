import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from tests.mechanics_test_support import ROOT, load_tool

CHANGED = load_tool("test-changed")


class ChangedGateTests(unittest.TestCase):
    def test_powershell_script_runs_built_parser_arm_coverage(self):
        scripts = json.loads((ROOT / "package.json").read_text())["scripts"]
        command = scripts["test:powershell"]
        self.assertIn(
            "tests.test_arm_coverage.ArmCoverageTests."
            "test_current_matcher_arm_inventory_powershell",
            command,
        )
        self.assertIn(
            "tests.test_arm_coverage.ArmCoverageTests."
            "test_classified_arms_have_distinguishing_counts_powershell",
            command,
        )

    def test_workflow_runs_full_suites_on_pull_requests_only(self):
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8"))
        self.assertEqual(workflow.get("on", workflow.get(True)), ["pull_request"])
        steps = {step.get("name"): step for step in workflow["jobs"]["test"]["steps"]}
        self.assertEqual(steps["Full native suite"].get("run"), "npm test")
        self.assertNotIn("if", steps["Full native suite"])
        self.assertEqual(
            steps["Generated artifacts and fixers"].get("run"),
            "npm run test:mechanics",
        )
        self.assertNotIn("if", steps["Generated artifacts and fixers"])

    def test_rule_ids_include_plans_fixtures_rules_and_snapshots(self):
        paths = [
            "plans/python/security/py-one.yml",
            "rules/go/correctness/go-two.yml",
            "tests/php/security/php-three.yml",
            "tests/__snapshots__/py-four-snapshot.yml",
        ]
        self.assertEqual(CHANGED.rule_ids(paths), ["go-two", "php-three", "py-four", "py-one"])

    def test_infrastructure_changes_escalate_but_rule_changes_do_not(self):
        self.assertTrue(CHANGED.requires_full_suite(["tools/rule-plan.py"]))
        self.assertTrue(CHANGED.requires_full_suite(["tests/test_inventory.py"]))
        self.assertTrue(CHANGED.requires_full_suite(["tests/arm_coverage.json"]))
        self.assertTrue(CHANGED.requires_full_suite(
            ["tests/arm_coverage_powershell.json"]))
        self.assertFalse(CHANGED.requires_full_suite(["rules/python/security/py-one.yml"]))

    def test_infrastructure_fast_gate_runs_mechanics_once_and_marks_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "github-output"
            with patch.object(CHANGED, "run") as run, \
                    patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}), \
                    patch("sys.argv", ["test-changed.py", "tools/rule-plan.py"]):
                self.assertEqual(CHANGED.main(), 0)
            self.assertEqual(output.read_text(encoding="utf-8"), "mechanics_ran=true\n")
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ["npm", "test"], ["npm", "run", "test:mechanics"],
        ])

    def test_focused_gate_runs_inventory_and_each_changed_probe(self):
        paths = ["rules/python/security/py-one.yml"]
        with patch.object(CHANGED, "rule_ids", return_value=["py-one"]), \
                patch.object(CHANGED, "run") as run, \
                patch.object(Path, "glob", return_value=iter([Path("rule.yml")])), \
                patch("sys.argv", ["test-changed.py", *paths]):
            self.assertEqual(CHANGED.main(), 0)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn([CHANGED.sys.executable, "-m", "unittest", "tests.test_inventory",
                       "tests.test_diagnostics", "tests.test_coderabbit_provenance"],
                      commands)
        self.assertIn([CHANGED.sys.executable, "tools/rule-probe.py", "py-one"], commands)
        diagnostic = next(call for call in run.call_args_list
                          if "tests.test_diagnostics" in call.args[0])
        self.assertEqual(diagnostic.args[1], {"ASTGREP_RULE_IDS": "py-one"})

    def test_change_discovery_includes_deletions(self):
        result = SimpleNamespace(returncode=0, stdout="tests/test_removed.py\n", stderr="")
        with patch.object(CHANGED.subprocess, "run", return_value=result) as run:
            self.assertEqual(CHANGED.changed_paths("origin/main"), ["tests/test_removed.py"])
        self.assertIn("--diff-filter=ACMRD", run.call_args.args[0])
        self.assertIn("--no-renames", run.call_args.args[0])
