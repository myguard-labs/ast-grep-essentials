import sys
import tempfile
import unittest
from pathlib import Path

CI_ROOT = Path(__file__).resolve().parents[1]
if str(CI_ROOT) not in sys.path:
    sys.path.insert(0, str(CI_ROOT))

# pylint: disable=wrong-import-position
import check_fixture_depth as depth


class CheckFixtureDepthTests(unittest.TestCase):
    def make(self, root: Path, rule_id: str, valid: int, invalid: int, fixture: bool = True) -> str:
        rule = root / f"rules/python/security/{rule_id}.yml"
        rule.parent.mkdir(parents=True, exist_ok=True)
        rule.write_text(f"id: {rule_id}\nlanguage: python\nrule: {{kind: call}}\n")
        if fixture:
            test = root / f"tests/python/security/{rule_id}.yml"
            test.parent.mkdir(parents=True, exist_ok=True)
            lines = ["id: " + rule_id, "valid:"]
            lines += [f"  - x{n}" for n in range(valid)]
            lines += ["invalid:"] + [f"  - f{n}()" for n in range(invalid)]
            test.write_text("\n".join(lines) + "\n")
        return f"rules/python/security/{rule_id}.yml"

    def run_check(self, rule_id, valid, invalid, fixture=True, grandfathered=()):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = self.make(root, rule_id, valid, invalid, fixture)
            return depth.check(root, [path], frozenset(grandfathered))

    def test_three_by_three_passes(self) -> None:
        self.assertEqual(self.run_check("py-a", 3, 3), [])

    def test_two_by_two_fails(self) -> None:
        failures = self.run_check("py-a", 2, 2)
        self.assertEqual(len(failures), 1)
        self.assertIn("needs >=3 valid cases, has 2", failures[0])
        self.assertIn("needs >=3 invalid cases, has 2", failures[0])

    def test_boundary_one_side_short(self) -> None:
        failures = self.run_check("py-a", 3, 2)
        self.assertIn("invalid", failures[0])
        self.assertNotIn(" valid cases", failures[0])

    def test_grandfathered_passes(self) -> None:
        self.assertEqual(self.run_check("py-a", 1, 1, grandfathered=["py-a"]), [])

    def test_missing_test_file_named(self) -> None:
        failures = self.run_check("py-a", 0, 0, fixture=False)
        self.assertIn("no test file tests/python/security/py-a.yml", failures[0])

    def test_grandfather_file_loads(self) -> None:
        ids = depth.load_grandfather()
        self.assertGreater(len(ids), 1000)
        self.assertNotIn("swift-cc-md5-sha1", ids)
