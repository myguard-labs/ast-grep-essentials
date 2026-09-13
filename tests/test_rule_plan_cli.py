import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.mechanics_test_support import ROOT, load_tool, minimal_plan

PLAN = load_tool("rule-plan")
MECHANICS = load_tool("rule-mechanics")


class RulePlanFixTests(unittest.TestCase):
    def test_fixer_requires_fixed_oracle_on_invalid_source(self):
        plan = minimal_plan(
            fix="safe()",
            oracles={"safe()": {"fixed": "safe()"}},
        )
        with self.assertRaisesRegex(ValueError, "fixed output for every invalid source"):
            PLAN.validate_plan(plan)

    def test_fixer_requires_exact_output_for_each_invalid_source(self):
        plan = minimal_plan(
            fix="safe()",
            cases={"invalid": ["danger()", "danger(1)"], "valid": ["safe()"]},
            oracles={"danger()": {"fixed": "safe()"}},
        )
        with self.assertRaisesRegex(ValueError, "every invalid source"):
            PLAN.validate_plan(plan)

    def test_valid_fixed_oracle_may_expect_no_change(self):
        plan = minimal_plan(
            fix="safe()",
            cases={"invalid": ["danger()"], "valid": ["safe()"]},
            oracles={
                "danger()": {"fixed": "safe()"},
                "safe()": {"fixed": "safe()"},
            },
        )
        with patch.object(MECHANICS.PLAN, "load_plan", return_value=plan), \
                patch.object(MECHANICS, "validate_fix") as validate:
            self.assertEqual(MECHANICS.validate_plan_fixes([Path("plan.yml")]), 2)
        self.assertFalse(validate.call_args_list[0].kwargs["allow_no_change"])
        self.assertTrue(validate.call_args_list[1].kwargs["allow_no_change"])


class RulePlanCliTests(unittest.TestCase):
    def test_cli_writes_end_to_end_phase_telemetry(self):
        with tempfile.TemporaryDirectory() as directory:
            telemetry = Path(directory) / "telemetry.json"
            result = subprocess.run(
                [sys.executable, ROOT / "tools/rule-plan.py",
                 ROOT / "plans/python/security/py-tempfile-mktemp.yml",
                 "--telemetry", telemetry],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(telemetry.read_text(encoding="utf-8"))
        self.assertEqual(report["version"], 1)
        self.assertEqual(report["plan"], "py-tempfile-mktemp")
        self.assertEqual(report["counts"], {
            "engine_processes": 2,
            "plans": 1,
            "valid_cases": 13,
            "invalid_cases": 3,
            "exclusions": 4,
            "bytes": sum(len(source.encode()) for values in PLAN.load_plan(
                ROOT / "plans/python/security/py-tempfile-mktemp.yml")["cases"].values()
                         for source in values),
            "mutants": 9,
            "survived": 4,
            "invalid": 0,
            "errors": 0,
        })
        self.assertIn("preflight", report["wall_clock_ms_informational"])

    def test_rule_plan_help_is_clean(self):
        result = subprocess.run(
            [sys.executable, ROOT / "tools/rule-plan.py", "--help"],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage:", result.stdout)
        self.assertIn("PLAN.yml", result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_readme_documents_the_actual_plan_commands_and_guides(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("rule-scaffold.py --plan", readme)
        self.assertNotIn("docs/complex-rules.md", readme)
        for text in ("python3 tools/rule-plan.py", "npm run generate:check",
                     "npm run generate", "docs/authoring.md", "plans/README.md"):
            self.assertIn(text, readme)
