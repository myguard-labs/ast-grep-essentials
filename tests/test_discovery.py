"""Exercise file-language discovery separately from string fixtures."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AST_GREP = ROOT / "node_modules" / ".bin" / "ast-grep"


class DiscoveryTests(unittest.TestCase):
    def test_phtml_uses_php_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "redirect.phtml"
            source.write_text('<?php header("Location: " . $_GET["next"]);\n')
            result = subprocess.run(
                [
                    AST_GREP,
                    "scan",
                    "--config",
                    ROOT / "sgconfig.yml",
                    "--filter",
                    "^php-open-redirect-superglobal$",
                    "--json=compact",
                    source,
                ],
                text=True,
                capture_output=True,
                check=False,
                timeout=15,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            findings = json.loads(result.stdout)
            self.assertEqual([item["ruleId"] for item in findings],
                             ["php-open-redirect-superglobal"])

    def test_suppression_directive_must_lead_comment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rules = root / "rules"
            rules.mkdir()
            (root / "sgconfig.yml").write_text("ruleDirs:\n  - rules\n")
            (rules / "probe.yml").write_text(
                "id: probe\n"
                "language: JavaScript\n"
                "severity: warning\n"
                "message: probe\n"
                "rule:\n"
                "  pattern: console.log($A)\n"
            )
            prose = root / "prose.js"
            prose.write_text(
                "// This prose mentions ast-grep-ignore: probe.\n"
                'console.log("must match");\n'
            )
            directive = root / "directive.js"
            directive.write_text(
                "// ast-grep-ignore: probe\n"
                'console.log("must be suppressed");\n'
            )

            result = subprocess.run(
                [
                    AST_GREP,
                    "scan",
                    "--config",
                    root / "sgconfig.yml",
                    "--json=compact",
                    prose,
                    directive,
                ],
                text=True,
                capture_output=True,
                check=False,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            findings = json.loads(result.stdout)
            self.assertEqual(
                [(item["ruleId"], Path(item["file"]).name) for item in findings],
                [("probe", "prose.js")],
            )


if __name__ == "__main__":
    unittest.main()
