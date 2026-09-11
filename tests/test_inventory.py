"""Check repository inventory, test coverage, IDs, and metadata consistency."""

import json
import re
import unittest
from pathlib import Path
from textwrap import dedent

import yaml

ROOT = Path(__file__).resolve().parents[1]


class InventoryTests(unittest.TestCase):
    def test_license_contract(self):
        license_name = "MyGuard Internal Use License 1.0"
        license_path = ROOT / "LICENSE"
        self.assertTrue(license_path.is_file(), "LICENSE must exist")
        license_text = license_path.read_text()
        expected_license = dedent(
            f"""\
            {license_name}

            Copyright (C) 2026 Thijs Eilander. All rights reserved.

            Permission is granted to download, copy, run, and modify this software solely
            for internal use, including internal commercial use.

            The software and modified versions may not be sold, sublicensed, published,
            redistributed, or otherwise made available to third parties.

            As a limited exception to the preceding paragraph, you may create and modify a
            GitHub fork or branch solely to prepare and submit modified versions through a
            GitHub pull request to:

            https://github.com/myguard-labs/ast-grep-essentials

            GitHub users may also exercise the on-service rights granted by GitHub's Terms
            of Service. Those platform rights do not grant permission to redistribute the
            software outside GitHub.

            Contributing Back

            Users who create new rules, fixes, or improvements are expected to submit those
            changes to the canonical repository above through a GitHub pull request.
            This expectation is nonbinding and is not a condition of the permissions
            granted above. Submission does not guarantee acceptance.
            """
        )
        self.assertEqual(license_text, expected_license)

        readme = (ROOT / "README.md").read_text()
        license_section = readme.split("## License\n\n", 1)[1].split("\n## ", 1)[0]
        normalized_section = " ".join(license_section.split())
        expected_summary = (
            f"The [{license_name}](LICENSE) permits internal use, including "
            "internal commercial use. Outside GitHub, distribution to third "
            "parties is prohibited. GitHub users retain applicable on-service "
            "rights, and the license defines a limited fork and branch workflow "
            "for pull-request contributions."
        )
        self.assertEqual(normalized_section, expected_summary)

        package = json.loads((ROOT / "package.json").read_text())
        package_lock = json.loads((ROOT / "package-lock.json").read_text())
        expected_license = "SEE LICENSE IN LICENSE"
        self.assertEqual(package["license"], expected_license)
        self.assertEqual(package_lock["packages"][""]["license"], expected_license)

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
