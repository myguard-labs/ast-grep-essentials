"""Fail when a rule is untested, unlinked, orphaned, or has a colliding ID."""

import json
import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULE_ORIGIN_COMMENT = (
    "# MyGuard rule: https://github.com/myguard-labs/ast-grep-essentials | "
    "https://deb.myguard.nl"
)


class InventoryTests(unittest.TestCase):
    def test_every_rule_links_to_myguard(self):
        """Every distributed rule identifies its repository and project site."""
        rules = sorted((ROOT / "rules").rglob("*.yml"))
        self.assertTrue(rules, "empty ruleset")
        for path in rules:
            with self.subTest(rule=path.relative_to(ROOT)):
                self.assertTrue(
                    path.read_text(encoding="utf-8").startswith(f"{RULE_ORIGIN_COMMENT}\n"),
                    f"{path.relative_to(ROOT)} must start with {RULE_ORIGIN_COMMENT!r}",
                )

    def test_native_config_excludes_only_powershell_rule_dir(self):
        """Every native language is configured without loading PowerShell."""
        config = yaml.safe_load((ROOT / "sgconfig.yml").read_text())
        configured = set(config["ruleDirs"])
        expected = {
            f"rules/{path.name}"
            for path in (ROOT / "rules").iterdir()
            if path.is_dir() and path.name != "powershell"
        }
        self.assertEqual(configured, expected)
        self.assertNotIn("rules/powershell", configured)

    def test_native_fixture_filter_excludes_only_powershell(self):
        package = json.loads((ROOT / "package.json").read_text())
        command = package["scripts"]["test"]
        match = re.search(r"--filter '([^']+)'", command)
        self.assertIsNotNone(match, "npm test must filter opt-in PowerShell fixtures")
        pattern = re.compile(match.group(1))
        native_ids = {
            path.stem for path in (ROOT / "rules").rglob("*.yml")
            if path.relative_to(ROOT / "rules").parts[0] != "powershell"
        }
        powershell_ids = {
            path.stem for path in (ROOT / "rules" / "powershell").rglob("*.yml")
        }
        self.assertTrue(native_ids)
        self.assertTrue(powershell_ids)
        self.assertEqual({rule_id for rule_id in native_ids if pattern.search(rule_id)},
                         native_ids)
        self.assertEqual({rule_id for rule_id in powershell_ids if pattern.search(rule_id)},
                         set())

    def test_every_rule_has_distinguishing_fixtures(self):
        rules = sorted(
            path for path in (ROOT / "rules").rglob("*.yml")
            if path.relative_to(ROOT / "rules").parts[0] != "powershell"
        )
        fixtures = set((ROOT / "tests").rglob("*.yml"))
        fixtures = {
            path for path in fixtures
            if "__snapshots__" not in path.parts
            and path.relative_to(ROOT / "tests").parts[0] != "powershell"
        }
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
