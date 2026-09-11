"""Verify completeness and required attribution of imported CodeRabbit rules."""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/coderabbit-rules.json"
MYGUARD_HEADER = (
    "# MyGuard rule: https://github.com/myguard-labs/ast-grep-essentials | "
    "https://deb.myguard.nl\n"
)
def yaml_id(path):
    match = re.search(r"(?m)^id:\s*[\"']?([^\s\"']+)", path.read_text())
    return match.group(1) if match else None


class CodeRabbitProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST.read_text())
        cls.entries = cls.manifest["rules"]

    def test_manifest_covers_all_imported_rules(self):
        self.assertEqual(len(self.entries), 184)
        targets = [entry["target_path"] for entry in self.entries]
        self.assertEqual(len(targets), len(set(targets)))
        marked = {
            str(path.relative_to(ROOT))
            for path in (ROOT / "rules").rglob("*.yml")
            if "# CodeRabbit source repository:" in path.read_text()
        }
        self.assertEqual(marked, set(targets))

    def test_each_rule_names_source_author_and_license(self):
        repository = self.manifest["source_repository"]
        commit = self.manifest["source_commit"]
        author = self.manifest["original_author_git"]
        for entry in self.entries:
            with self.subTest(rule=entry["id"]):
                path = ROOT / entry["target_path"]
                lines = path.read_text().splitlines(keepends=True)
                self.assertEqual(lines[0], MYGUARD_HEADER)
                self.assertEqual(
                    lines[1], f"# CodeRabbit source repository: {repository}\n"
                )
                self.assertEqual(
                    lines[2],
                    f"# CodeRabbit source file: {repository}/blob/{commit}/"
                    f"{entry['source_path']}\n",
                )
                self.assertEqual(lines[3], f"# Original author (Git): {author}\n")
                self.assertEqual(
                    lines[4],
                    "# License: Apache License 2.0 "
                    "(https://www.apache.org/licenses/LICENSE-2.0)\n",
                )
                self.assertTrue(lines[5].startswith("# Modified by MyGuard: "))
                self.assertEqual(yaml_id(path), entry["id"])

    def test_manifest_records_pinned_source_digests(self):
        for entry in self.entries:
            with self.subTest(rule=entry["id"]):
                self.assertRegex(entry["source_sha256"], r"^[0-9a-f]{64}$")

    def test_upstream_apache_license_is_included(self):
        license_text = (
            ROOT / "LICENSES/CodeRabbit-ast-grep-essentials-Apache-2.0.txt"
        ).read_text()
        self.assertIn("Apache License", license_text)
        self.assertIn("Version 2.0, January 2004", license_text)


if __name__ == "__main__":
    unittest.main()
