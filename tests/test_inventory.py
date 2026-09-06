"""Fail when a rule is untested, a fixture is orphaned, or an ID collides."""

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


class InventoryTests(unittest.TestCase):
    def test_every_rule_has_distinguishing_fixtures(self):
        rules = sorted((ROOT / "rules").rglob("*.yml"))
        fixtures = set((ROOT / "tests").rglob("*.yml"))
        fixtures = {p for p in fixtures if "__snapshots__" not in p.parts}
        self.assertTrue(rules, "empty ruleset")
        ids = set()
        expected = set()
        for path in rules:
            with self.subTest(rule=path.name):
                rule = yaml.safe_load(path.read_text())
                relative = path.relative_to(ROOT / "rules")
                self.assertEqual(len(relative.parts), 3)
                self.assertEqual(relative.parts[0], rule["language"])
                self.assertEqual(path.stem, rule["id"])
                self.assertNotIn(rule["id"], ids)
                ids.add(rule["id"])
                fixture = ROOT / "tests" / relative
                expected.add(fixture)
                self.assertTrue(fixture.is_file(), f"missing {fixture}")
                data = yaml.safe_load(fixture.read_text())
                self.assertEqual(data["id"], rule["id"])
                for key in ("valid", "invalid"):
                    self.assertIsInstance(data[key], list)
                    self.assertTrue(data[key])
                    self.assertTrue(all(isinstance(s, str) and s.strip() for s in data[key]))
                self.assertFalse(set(data["valid"]) & set(data["invalid"]))
                snapshot_path = ROOT / "tests" / "__snapshots__" / f"{rule['id']}-snapshot.yml"
                snapshot = yaml.safe_load(snapshot_path.read_text())
                self.assertIsInstance(snapshot, dict)
                self.assertIsInstance(snapshot["snapshots"], dict)
                self.assertEqual(set(snapshot["snapshots"]), set(data["invalid"]))
        self.assertEqual(expected, fixtures)
