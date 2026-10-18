"""Run the global util fixtures under ci/util-tests with real ast-grep.

Every util under ``utils/`` is discovered and gets the same four checks: the
shipped util passes its probe fixtures, an over-accepting mutant fails them, a
match-nothing mutant fails them, and a malformed util aborts the run. The
mutants are util specific, so each util needs an entry in ``MUTANTS``; a util
without one (or without its probe rule and fixture) fails the inventory test.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UTILS_DIR = ROOT / "utils"
CONFIG_DIR = ROOT / "ci/util-tests"
BINARY = os.environ.get("AST_GREP_UTIL_TESTS")


@dataclass(frozen=True)
class Mutants:
    """Text replacements that turn a shipped util into a known-bad one."""

    over_accepting: tuple[str, str]
    match_nothing: tuple[str, str]
    malformed: tuple[str, str]


MUTANTS: dict[str, Mutants] = {
    "python/non-empty-string-literal.yml": Mutants(
        over_accepting=("kind: string_content", "kind: string_start"),
        match_nothing=("kind: string\n", "kind: integer\n"),
        malformed=("kind: string\n", "kind: [\n"),
    ),
    "python/python-imported-module.yml": Mutants(
        over_accepting=(
            "  any:\n",
            (
                "  any:\n"
                "    - kind: dotted_name\n"
                "      inside:\n"
                "        kind: future_import_statement\n"
            ),
        ),
        match_nothing=("rule:\n", "rule:\n  kind: comment\n"),
        malformed=("rule:\n", "rule:\n  kind: [\n"),
    ),
}


def shipped_utils() -> dict[str, Path]:
    """Map each util path relative to ``utils/`` to its file."""
    return {
        path.relative_to(UTILS_DIR).as_posix(): path
        for path in sorted(UTILS_DIR.rglob("*.y*ml"))
    }


def util_id(path: Path) -> str:
    """Return the ``id:`` of a util file."""
    text = path.read_text(encoding="utf-8")
    found = re.search(r"^id: (\S+)$", text, re.MULTILINE)
    if found is None:
        raise ValueError(f"{path}: no top-level id")
    return found.group(1)


def failed_probe(path: Path) -> str:
    """Return a regex for the FAIL line of the util's own probe."""
    return rf"(?m)^FAIL probe-{re.escape(util_id(path))}\s"


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


class UtilInventoryTests(unittest.TestCase):
    def test_every_util_has_mutants_a_probe_and_fixtures(self) -> None:
        utils = shipped_utils()
        self.assertTrue(utils)
        self.assertEqual(sorted(utils), sorted(MUTANTS))
        for name, path in utils.items():
            with self.subTest(util=name):
                ident = util_id(path)
                self.assertEqual(path.stem, ident)
                probe = CONFIG_DIR / f"rules/probe-{ident}.yml"
                fixture = CONFIG_DIR / f"tests/probe-{ident}-test.yml"
                self.assertTrue(probe.is_file(), probe)
                self.assertTrue(fixture.is_file(), fixture)
                self.assertIn(f"matches: {ident}", probe.read_text(encoding="utf-8"))

    def test_util_id_rejects_a_file_without_an_id(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "no-id.yml"
            path.write_text("language: python\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                util_id(path)


@unittest.skipUnless(BINARY, "needs AST_GREP_UTIL_TESTS")
class UtilFixtureTests(unittest.TestCase):
    def mutant_config(self, name: str, old: str, new: str) -> Path:
        """Copy the util tests and every util, replacing ``old`` in ``name``."""
        scratch = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(scratch.cleanup)
        base = Path(scratch.name)
        shutil.copytree(CONFIG_DIR, base / "ci/util-tests")
        shutil.copytree(UTILS_DIR, base / "utils")
        target = base / "utils" / name
        text = target.read_text(encoding="utf-8")
        self.assertIn(old, text)
        target.write_text(text.replace(old, new), encoding="utf-8")
        return base / "ci/util-tests/sgconfig.yml"

    def test_shipped_utils_pass_their_fixtures(self) -> None:
        result = run_tests(CONFIG_DIR / "sgconfig.yml")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        probes = len(list((CONFIG_DIR / "tests").glob("probe-*-test.yml")))
        self.assertGreaterEqual(probes, len(shipped_utils()))
        self.assertIn(f"{probes} passed; 0 failed", result.stdout)

    def test_over_accepting_util_fails_the_fixtures(self) -> None:
        for name, path in shipped_utils().items():
            with self.subTest(util=name):
                config = self.mutant_config(name, *MUTANTS[name].over_accepting)
                result = run_tests(config)
                self.assertNotEqual(result.returncode, 0)
                self.assertRegex(result.stdout, failed_probe(path))

    def test_util_matching_nothing_fails_the_fixtures(self) -> None:
        for name, path in shipped_utils().items():
            with self.subTest(util=name):
                config = self.mutant_config(name, *MUTANTS[name].match_nothing)
                result = run_tests(config)
                self.assertNotEqual(result.returncode, 0)
                self.assertRegex(result.stdout, failed_probe(path))

    def test_malformed_util_aborts_the_run(self) -> None:
        for name in shipped_utils():
            with self.subTest(util=name):
                config = self.mutant_config(name, *MUTANTS[name].malformed)
                result = run_tests(config)
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
