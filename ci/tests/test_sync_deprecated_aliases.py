"""Cover the deprecated-alias generator that keeps aliases matching."""

import sys
import tempfile
import unittest
from pathlib import Path

import yaml

CI_ROOT = Path(__file__).resolve().parents[1]
if str(CI_ROOT) not in sys.path:
    sys.path.insert(0, str(CI_ROOT))

# pylint: disable=wrong-import-position
import sync_deprecated_aliases as alias_sync

REPLACEMENT = """\
id: real-rule
language: c
severity: warning
message: original
note: original note
rule:
  pattern: foo($A)
constraints:
  A:
    kind: identifier
"""

ALIAS = """\
id: old-rule
language: c
severity: 'off'
message: deprecated; use real-rule
note: compatibility alias
rule:
  pattern: STALE
metadata:
  deprecated_alias_of: real-rule
"""


class AliasSyncTests(unittest.TestCase):
    def setUp(self):
        # Released by addCleanup below, which outlives this method unlike `with`.
        # pylint: disable-next=consider-using-with
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.rules = self.root / "rules/c/correctness"
        self.rules.mkdir(parents=True)
        (self.rules / "real-rule.yml").write_text(REPLACEMENT)
        (self.rules / "old-rule.yml").write_text(ALIAS)
        self.addCleanup(self._tmp.cleanup)

    def alias(self) -> dict:
        return yaml.safe_load((self.rules / "old-rule.yml").read_text())

    def test_check_reports_drift_without_writing(self):
        before = (self.rules / "old-rule.yml").read_text()
        self.assertEqual(alias_sync.sync(self.root, check=True), 1)
        self.assertEqual((self.rules / "old-rule.yml").read_text(), before)

    def test_sync_copies_the_matcher_from_the_replacement(self):
        self.assertEqual(alias_sync.sync(self.root, check=False), 0)
        alias = self.alias()
        self.assertEqual(alias["rule"], {"pattern": "foo($A)"})
        self.assertEqual(alias["constraints"], {"A": {"kind": "identifier"}})

    def test_sync_preserves_alias_owned_metadata(self):
        alias_sync.sync(self.root, check=False)
        alias = self.alias()
        self.assertEqual(alias["id"], "old-rule")
        self.assertEqual(alias["severity"], "off")
        self.assertEqual(alias["message"], "deprecated; use real-rule")
        self.assertEqual(alias["note"], "compatibility alias")
        self.assertEqual(alias["metadata"]["deprecated_alias_of"], "real-rule")

    def test_sync_is_idempotent_and_leaves_the_replacement_alone(self):
        replacement = (self.rules / "real-rule.yml").read_text()
        alias_sync.sync(self.root, check=False)
        once = (self.rules / "old-rule.yml").read_text()
        self.assertEqual(alias_sync.sync(self.root, check=False), 0)
        self.assertEqual((self.rules / "old-rule.yml").read_text(), once)
        self.assertEqual(alias_sync.sync(self.root, check=True), 0)
        self.assertEqual((self.rules / "real-rule.yml").read_text(), replacement)

    def test_enriching_only_the_replacement_is_caught_then_repaired(self):
        """The regression this generator exists to prevent."""
        alias_sync.sync(self.root, check=False)
        self.assertEqual(alias_sync.sync(self.root, check=True), 0)
        (self.rules / "real-rule.yml").write_text(
            REPLACEMENT.replace(
                "  pattern: foo($A)",
                "  any:\n    - pattern: foo($A)\n    - pattern: bar($A)",
            )
        )
        self.assertEqual(alias_sync.sync(self.root, check=True), 1)
        alias_sync.sync(self.root, check=False)
        self.assertEqual(self.alias()["rule"]["any"][1], {"pattern": "bar($A)"})

    def test_multi_line_patterns_stay_block_scalars(self):
        (self.rules / "real-rule.yml").write_text(
            "id: real-rule\nlanguage: c\nseverity: warning\nmessage: m\n"
            "rule:\n  pattern:\n    context: |\n      void f(void) { g(); }\n"
            "    selector: call_expression\n"
        )
        alias_sync.sync(self.root, check=False)
        text = (self.rules / "old-rule.yml").read_text()
        self.assertIn("context: |", text)
        self.assertEqual(
            self.alias()["rule"]["pattern"]["context"], "void f(void) { g(); }\n"
        )

    def test_a_rule_without_the_marker_is_never_rewritten(self):
        (self.rules / "old-rule.yml").write_text(ALIAS.replace(
            "metadata:\n  deprecated_alias_of: real-rule\n", ""))
        before = (self.rules / "old-rule.yml").read_text()
        self.assertEqual(alias_sync.sync(self.root, check=True), 0)
        self.assertEqual((self.rules / "old-rule.yml").read_text(), before)

    def test_a_missing_target_is_a_hard_error(self):
        (self.rules / "old-rule.yml").write_text(
            ALIAS.replace("deprecated_alias_of: real-rule",
                          "deprecated_alias_of: nonexistent"))
        with self.assertRaises(SystemExit):
            alias_sync.sync(self.root, check=True)

    def test_an_ambiguous_target_is_a_hard_error(self):
        other = self.root / "rules/c/security"
        other.mkdir(parents=True)
        (other / "real-rule.yml").write_text(REPLACEMENT)
        with self.assertRaises(SystemExit):
            alias_sync.sync(self.root, check=True)


if __name__ == "__main__":
    unittest.main()
