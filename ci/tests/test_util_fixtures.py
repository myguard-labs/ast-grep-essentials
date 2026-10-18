"""Run the global util fixtures under ci/util-tests with real ast-grep."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UTIL = ROOT / "utils/python/non-empty-string-literal.yml"
CONFIG_DIR = ROOT / "ci/util-tests"
BINARY = os.environ.get("AST_GREP_UTIL_TESTS")


def run_tests(config: Path) -> subprocess.CompletedProcess[str]:
    assert BINARY is not None
    return subprocess.run(
        [BINARY, "test", "-c", str(config)],
        cwd=config.parent,
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
        stdin=subprocess.DEVNULL,
    )


@unittest.skipUnless(BINARY, "needs AST_GREP_UTIL_TESTS")
class UtilFixtureTests(unittest.TestCase):
    def mutant_config(self, old: str, new: str) -> Path:
        """Copy the util test config next to a util with ``old`` replaced."""
        scratch = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(scratch.cleanup)
        base = Path(scratch.name)
        shutil.copytree(CONFIG_DIR, base / "ci/util-tests")
        (base / "utils/python").mkdir(parents=True)
        text = UTIL.read_text(encoding="utf-8")
        self.assertIn(old, text)
        (base / "utils/python" / UTIL.name).write_text(
            text.replace(old, new), encoding="utf-8"
        )
        return base / "ci/util-tests/sgconfig.yml"

    def test_shipped_util_passes_its_fixtures(self) -> None:
        result = run_tests(CONFIG_DIR / "sgconfig.yml")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("1 passed; 0 failed", result.stdout)

    def test_util_accepting_empty_strings_fails_the_fixtures(self) -> None:
        config = self.mutant_config("kind: string_content", "kind: string_start")
        result = run_tests(config)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL probe-non-empty-string-literal", result.stdout)

    def test_util_matching_nothing_fails_the_fixtures(self) -> None:
        config = self.mutant_config("kind: string\n", "kind: integer\n")
        result = run_tests(config)
        self.assertNotEqual(result.returncode, 0)

    def test_malformed_util_aborts_the_run(self) -> None:
        config = self.mutant_config("kind: string\n", "kind: [\n")
        result = run_tests(config)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
