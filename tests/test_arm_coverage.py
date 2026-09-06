"""Keep the classified matcher alternatives observable, including duplicate hits.

The fixture runner snapshots only its first finding. These named witnesses
assert exact JSON counts and demonstrate a count change after deleting their
specific arm. Rule parse errors and scanner failures are errors, never kills.
"""

import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
AST_GREP = ROOT / "node_modules" / ".bin" / "ast-grep"


def any_arms(node, path=()):
    """Enumerate each removable arm beneath the main matcher, in YAML order."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "any" and isinstance(value, list) and len(value) > 1:
                for index in range(len(value)):
                    yield path + (key,), index
            yield from any_arms(value, path + (key,))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from any_arms(value, path + (index,))


def delete_arm(rule, path, index):
    mutant = copy.deepcopy(rule)
    node = mutant["rule"]
    for component in path:
        node = node[component]
    del node[index]
    return mutant


def scan_count(rule, source):
    result = subprocess.run(
        [AST_GREP, "scan", "--inline-rules", yaml.safe_dump(rule),
         "--stdin", "--json=compact"],
        input=source, text=True, capture_output=True, timeout=15, check=False,
    )
    findings = json.loads(result.stdout)
    expected_status = int(any(finding["severity"] == "error" for finding in findings))
    if result.returncode != expected_status:
        raise RuntimeError(f"scanner failed: {result.returncode}: {result.stderr}")
    if any(finding["ruleId"] != rule["id"] for finding in findings):
        raise RuntimeError("scanner returned findings for another rule")
    return len(findings)


class ArmCoverageTests(unittest.TestCase):
    def test_current_matcher_arm_inventory(self):
        cases = json.loads((ROOT / "tests/arm_coverage.json").read_text())["cases"]
        witnesses = {(case["rule"], case["path"], case["index"]): case
                     for case in cases if case["classification"] != "equivalent"}
        # Removing the only CONDITION binder cannot produce an executable rule.
        # Keep this specific invalid mutation visible; it is not a test kill.
        invalid = {("nginx-send-header-two-valued", "any", 2):
                   "Undefined meta var `CONDITION` used in `constraints`."}
        seen_invalid = set()
        tested = fixture_kills = count_kills = 0
        for rule_path in sorted((ROOT / "rules").rglob("*.yml")):
            rule = yaml.safe_load(rule_path.read_text())
            arms = list(any_arms(rule["rule"]))
            if not arms:
                continue
            # Hidden/ignored directories are silently skipped by the fixture
            # runner. A visible directory plus an asserted discovery count
            # prevents an empty test run from masquerading as a survivor.
            with tempfile.TemporaryDirectory(prefix="arm-coverage-", dir=ROOT) as name:
                directory = Path(name)
                (directory / "rules").mkdir()
                snapshots = directory / "tests/__snapshots__"
                snapshots.mkdir(parents=True)
                fixture_path = ROOT / "tests" / rule_path.relative_to(ROOT / "rules")
                (directory / "tests" / rule_path.name).write_bytes(fixture_path.read_bytes())
                snapshot_name = f"{rule['id']}-snapshot.yml"
                (snapshots / snapshot_name).write_bytes(
                    (ROOT / "tests/__snapshots__" / snapshot_name).read_bytes()
                )
                config = directory / "sgconfig.yml"
                config.write_text("ruleDirs: [rules]\ntestConfigs: [{testDir: tests}]\n")
                target = directory / "rules" / rule_path.name
                target.write_text(yaml.safe_dump(rule))
                command = [AST_GREP, "test", "-c", config]
                baseline = subprocess.run(command, capture_output=True, text=True,
                                          timeout=15, check=False)
                self.assertEqual(baseline.returncode, 0, baseline.stdout + baseline.stderr)
                self.assertIn("test result: ok. 1 passed; 0 failed;", baseline.stdout)
                for path, index in arms:
                    identity = (rule["id"], "/".join(map(str, path)), index)
                    with self.subTest(rule=identity[0], path=identity[1], index=index):
                        tested += 1
                        mutant = delete_arm(rule, path, index)
                        target.write_text(yaml.safe_dump(mutant))
                        result = subprocess.run(command, capture_output=True, text=True,
                                                timeout=15, check=False)
                        output = result.stdout + result.stderr
                        if identity in invalid:
                            self.assertNotEqual(result.returncode, 0)
                            self.assertIn("Cannot parse rule", output)
                            self.assertIn(invalid[identity], output)
                            seen_invalid.add(identity)
                            print(f"Invalid deletion {identity}: {invalid[identity]}")
                            continue
                        self.assertIn("Running 1 tests", output, "mutant did not execute")
                        if result.returncode != 0:
                            self.assertEqual(result.returncode, 4, output)
                            self.assertIn("Error: test failed.", output)
                            self.assertIn(f"FAIL {rule['id']} ", output)
                            fixture_kills += 1
                            continue
                        self.assertIn("test result: ok. 1 passed; 0 failed;", output)
                        self.assertIn(identity, witnesses, "matcher arm deletion survived")
                        case = witnesses[identity]
                        self.assertEqual(scan_count(rule, case["source"]), case["expected"])
                        observed = scan_count(mutant, case["source"])
                        self.assertNotEqual(observed, case["expected"],
                                            "matcher arm deletion survived count oracle")
                        print(f"Count kill {identity}: {case['expected']} -> {observed}")
                        count_kills += 1
        self.assertGreater(tested, 0)
        self.assertEqual(seen_invalid, set(invalid))
        print(f"Matcher arms: {tested}; fixture kills: {fixture_kills}; "
              f"count kills: {count_kills}; invalid rules (not kills): {len(seen_invalid)}")

    def test_classified_arms_have_distinguishing_counts(self):
        cases = json.loads((ROOT / "tests/arm_coverage.json").read_text())["cases"]
        identities = [(case["rule"], case["original_path"], case["original_index"])
                      for case in cases]
        self.assertEqual(len(identities), 50)
        self.assertEqual(len(set(identities)), len(identities))
        rules = {path.stem: path for path in (ROOT / "rules").rglob("*.yml")}
        for case in cases:
            with self.subTest(rule=case["rule"], path=case["original_path"],
                              index=case["original_index"]):
                if case["classification"] == "equivalent":
                    self.assertTrue(case["reason"])
                    continue
                self.assertIn(case["classification"], ("missing-fixture", "weak-count-oracle"))
                rule_path = rules[case["rule"]]
                rule = yaml.safe_load(rule_path.read_text())
                fixture = yaml.safe_load(
                    (ROOT / "tests" / rule_path.relative_to(ROOT / "rules")).read_text()
                )
                category = "invalid" if case["expected"] else "valid"
                self.assertIn(case["source"], fixture[category])
                self.assertEqual(scan_count(rule, case["source"]), case["expected"],
                                 "fixture diagnostic count changed")
                mutant = copy.deepcopy(rule)
                arms = mutant["rule"]
                for component in case["path"].split("/"):
                    arms = arms[int(component) if isinstance(arms, list) else component]
                self.assertGreater(len(arms), 1, "arm deletion must leave a valid alternative")
                del arms[case["index"]]
                observed = scan_count(mutant, case["source"])
                self.assertEqual(observed, case["deleted_expected"],
                                 "deleted arm's witness changed")
                self.assertNotEqual(observed, case["expected"], "matcher arm deletion survived")

    def test_scanner_errors_are_not_mutant_kills(self):
        rule = {"id": "broken-control", "language": "c", "rule": {"kind": "not_a_c_kind"}}
        with self.assertRaises((json.JSONDecodeError, RuntimeError)):
            scan_count(rule, "void f(void) {}")
