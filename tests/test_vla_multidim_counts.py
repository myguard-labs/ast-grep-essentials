"""Assert count of findings for multi-dimensional VLA declarations."""

import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AST_GREP = ROOT / "node_modules" / ".bin" / "ast-grep"


class VLAMultidimCountTests(unittest.TestCase):
    def test_multidimensional_vla_reports_per_dimension(self):
        """Multi-dimensional VLAs nest array declarators; each variable
        dimension should report separately. Verify the rule reports exactly
        2 findings for int m[rows][cols] and exactly 1 for int m[rows][10]."""
        rule_path = ROOT / "rules" / "c" / "security" / "c-alloca-vla.yml"

        # Test: int m[rows][cols] should yield exactly 2 findings
        source_two_dims = "void f(int rows, int cols) { int m[rows][cols]; }"
        result = subprocess.run(
            [AST_GREP, "scan", "--rule", rule_path, "--json=compact", "--stdin"],
            input=source_two_dims, text=True, capture_output=True,
            check=False, timeout=15,
        )
        self.assertIn(result.returncode, (0, 1), result.stderr)
        self.assertTrue(result.stdout.strip(), result.stderr)
        findings_two = json.loads(result.stdout)
        self.assertEqual(len(findings_two), 2,
                         f"Expected 2 findings for 'int m[rows][cols]', got {len(findings_two)}")

        # Test: int m[rows][10] should yield exactly 1 finding
        # (only the variable dimension 'rows', not the fixed-size dimension '10')
        source_one_dim = "void f(int rows) { int m[rows][10]; }"
        result = subprocess.run(
            [AST_GREP, "scan", "--rule", rule_path, "--json=compact", "--stdin"],
            input=source_one_dim, text=True, capture_output=True,
            check=False, timeout=15,
        )
        self.assertIn(result.returncode, (0, 1), result.stderr)
        self.assertTrue(result.stdout.strip(), result.stderr)
        findings_one = json.loads(result.stdout)
        self.assertEqual(len(findings_one), 1,
                         f"Expected 1 finding for 'int m[rows][10]', got {len(findings_one)}")


if __name__ == "__main__":
    unittest.main()
