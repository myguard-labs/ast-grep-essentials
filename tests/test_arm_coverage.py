"""Keep the classified matcher alternatives observable, including duplicate hits.

The fixture runner snapshots only its first finding. These named witnesses
assert exact JSON counts and demonstrate a count change after deleting their
specific arm. Rule parse errors and scanner failures are errors, never kills.

Two independent rule trees are gated here: the native pack (`rules/` +
`tests/`, plain `sgconfig.yml`) and the PowerShell pack (`rules-powershell/` +
`tests-powershell/`, `sgconfig.powershell.yml`). They are NOT symmetric --
PowerShell needs a compiled Tree-sitter grammar ast-grep loads as a custom
language, and that grammar is built, not vendored. When it is absent, the
PowerShell half fails closed as an explicit, visible skip (never a silent pass
and never a hard failure that blocks native-only work), matching the repo's
"fail closed rather than silently reporting zero findings" principle
documented in sgconfig.powershell.yml. `customLanguages` must never be added to
the central sgconfig.yml: an unloadable parser there aborts the entire native
scan for every consumer, so the PowerShell config and its libraryPath stay
confined to a temporary config built here and in sgconfig.powershell.yml.
"""

import collections
import copy
import json
import platform
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from tests._astgrep import resolve_ast_grep

ROOT = Path(__file__).resolve().parents[1]
AST_GREP = resolve_ast_grep()

# Mirrors tests/test_powershell_parser.py's artifact-naming logic: the build
# script emits the platform-native suffix, so the artifact this host should
# have is not always `.so`.
_HOST_SUFFIX = {"Darwin": ".dylib", "Windows": ".dll"}.get(platform.system(), ".so")
POWERSHELL_LIBRARY = ROOT / "build" / "powershell" / f"powershell{_HOST_SUFFIX}"
POWERSHELL_BUILD_SCRIPT = ROOT / "tools" / "powershell" / "build-grammar.sh"


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


def scan_count(rule, source, config=None):
    command = [AST_GREP, "scan", "--inline-rules", yaml.safe_dump(rule)]
    if config is not None:
        command += ["-c", config]
    command += ["--stdin", "--json=compact"]
    result = subprocess.run(
        command, input=source, text=True, capture_output=True, timeout=15, check=False,
    )
    findings = json.loads(result.stdout)
    expected_status = int(any(finding["severity"] == "error" for finding in findings))
    if result.returncode != expected_status:
        raise RuntimeError(f"scanner failed: {result.returncode}: {result.stderr}")
    if any(finding["ruleId"] != rule["id"] for finding in findings):
        raise RuntimeError("scanner returned findings for another rule")
    return len(findings)


def _tree_config_text(tree, rules_rel, tests_rel):
    """The throwaway sgconfig for one rule's single-file temp workspace."""
    return (
        f"ruleDirs: [{rules_rel}]\n"
        f"{tree.extra_config}"
        f"testConfigs: [{{testDir: {tests_rel}}}]\n"
    )


Tree = collections.namedtuple(
    "Tree", ["name", "rules_dir", "tests_dir", "cases_path", "extra_config"],
    defaults=[""],
)


NATIVE_TREE = Tree(
    name="native",
    rules_dir=ROOT / "rules",
    tests_dir=ROOT / "tests",
    cases_path=ROOT / "tests/arm_coverage.json",
)

# libraryPath in sgconfig.powershell.yml is resolved RELATIVE TO THE CONFIG
# FILE. The mutant workspace below is a temp directory outside this repo, so
# the config it writes needs an ABSOLUTE path to the built grammar or ast-grep
# silently finds nothing where it should fail closed instead.
# Every target the shipped config knows about is mapped to the one built
# library. Hardcoding a single triple here would let the skip guard pass on
# macOS, Windows or ARM Linux -- where the grammar IS built, so the guard sees
# the file -- while ast-grep found no entry for its own target and reported
# nothing. The triples come from the shipped config so the two cannot drift.
_POWERSHELL_TARGETS = tuple(
    yaml.safe_load((ROOT / "sgconfig.powershell.yml").read_text())
    ["customLanguages"]["powershell"]["libraryPath"]
)

_POWERSHELL_CONFIG_EXTRA = (
    "customLanguages:\n"
    "  powershell:\n"
    "    libraryPath:\n"
    + "".join(f"      {target}: {POWERSHELL_LIBRARY.resolve()}\n"
              for target in _POWERSHELL_TARGETS)
    + "    extensions: [ps1, psm1, psd1]\n"
    "    expandoChar: 'µ'\n"
)

POWERSHELL_TREE = Tree(
    name="powershell",
    rules_dir=ROOT / "rules-powershell",
    tests_dir=ROOT / "tests-powershell",
    cases_path=ROOT / "tests/arm_coverage_powershell.json",
    extra_config=_POWERSHELL_CONFIG_EXTRA,
)

requires_powershell_parser = unittest.skipUnless(
    POWERSHELL_LIBRARY.is_file(),
    f"PowerShell grammar not built; run {POWERSHELL_BUILD_SCRIPT.relative_to(ROOT)}",
)


class ArmCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if AST_GREP is None:
            raise unittest.SkipTest(
                "ast-grep binary not found. Install with: "
                "npm install (for local node_modules/.bin/ast-grep) or "
                "install ast-grep to system PATH"
            )

    def _run_arm_inventory(self, tree, powershell_config=None):
        # pylint: disable=too-many-locals,too-many-statements
        # Already true of this method pre-extension (28 locals, 59 statements
        # against the same 15/50 thresholds); parameterizing it over both
        # rule trees, rather than duplicating the body per tree, pushed it a
        # little further past thresholds it was already over.
        cases = json.loads(tree.cases_path.read_text())["cases"]
        witnesses = {(case["rule"], case["path"], case["index"]): case
                     for case in cases if case["classification"] != "equivalent"}
        # Every matcher arm must parse on its own and be killed by a fixture.
        invalid = {}
        seen_invalid = set()
        tested = fixture_kills = count_kills = 0
        for rule_path in sorted(tree.rules_dir.rglob("*.yml")):
            rule = yaml.safe_load(rule_path.read_text())
            arms = list(any_arms(rule["rule"]))
            if not arms:
                continue
            # Hidden/ignored directories are silently skipped by the fixture
            # runner. A visible directory plus an asserted discovery count
            # prevents an empty test run from masquerading as a survivor.
            prefix = f"arm-coverage-{tree.name}-"
            with tempfile.TemporaryDirectory(prefix=prefix, dir=ROOT) as name:
                directory = Path(name)
                rules_rel = tree.rules_dir.name
                tests_rel = tree.tests_dir.name
                (directory / rules_rel).mkdir()
                snapshots = directory / tests_rel / "__snapshots__"
                snapshots.mkdir(parents=True)
                fixture_path = tree.tests_dir / rule_path.relative_to(tree.rules_dir)
                (directory / tests_rel / rule_path.name).write_bytes(fixture_path.read_bytes())
                snapshot_name = f"{rule['id']}-snapshot.yml"
                snapshot_src = tree.tests_dir / "__snapshots__" / snapshot_name
                (snapshots / snapshot_name).write_bytes(snapshot_src.read_bytes())
                config = directory / "sgconfig.yml"
                config.write_text(_tree_config_text(tree, rules_rel, tests_rel))
                target = directory / rules_rel / rule_path.name
                target.write_text(yaml.safe_dump(rule))
                command = [AST_GREP, "test", "-c", config]
                baseline = subprocess.run(command, capture_output=True, text=True,
                                          timeout=15, check=False)
                self.assertEqual(baseline.returncode, 0, baseline.stdout + baseline.stderr)
                self.assertIn("test result: ok. 1 passed; 0 failed;", baseline.stdout)
                for path, index in arms:
                    identity = (rule["id"], "/".join(map(str, path)), index)
                    with self.subTest(tree=tree.name, rule=identity[0],
                                       path=identity[1], index=index):
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
                        expected = case["expected"]
                        observed_baseline = scan_count(rule, case["source"], powershell_config)
                        self.assertEqual(observed_baseline, expected)
                        observed = scan_count(mutant, case["source"], powershell_config)
                        self.assertNotEqual(observed, expected,
                                            "matcher arm deletion survived count oracle")
                        print(f"Count kill {identity}: {expected} -> {observed}")
                        count_kills += 1
        self.assertGreater(tested, 0)
        self.assertEqual(seen_invalid, set(invalid))
        print(f"[{tree.name}] Matcher arms: {tested}; fixture kills: {fixture_kills}; "
              f"count kills: {count_kills}; invalid rules (not kills): {len(seen_invalid)}")

    def test_powershell_test_config_registers_the_host_target(self):
        """The mutant workspace config must carry an entry for the triple
        ast-grep will actually resolve on this host. Without it the skip guard
        still passes -- the grammar file exists -- while ast-grep finds no
        library for its own target and quietly scans nothing, turning the
        matcher-arm gate into a silent pass. Derived from the shipped config so
        a platform added there is covered here without a second edit."""
        generated = yaml.safe_load(_POWERSHELL_CONFIG_EXTRA)
        registered = generated["customLanguages"]["powershell"]["libraryPath"]
        # platform.machine() reports the OS name for the CPU; Rust target
        # triples use its own. arm64 (macOS/BSD) and aarch64 (Linux) are the
        # same architecture under two spellings.
        machine = platform.machine().lower()
        host = {"arm64": "aarch64", "amd64": "x86_64"}.get(machine, machine)
        self.assertTrue(
            any(target.startswith(f"{host}-") for target in registered),
            f"no libraryPath entry for host architecture {host!r} "
            f"(platform.machine()={platform.machine()!r}); "
            f"registered: {sorted(registered)}",
        )
        self.assertTrue(all(Path(p).is_absolute() for p in registered.values()))

    def test_current_matcher_arm_inventory(self):
        self._run_arm_inventory(NATIVE_TREE)

    @requires_powershell_parser
    def test_current_matcher_arm_inventory_powershell(self):
        # scan_count's --stdin invocation also needs the custom-language
        # config, since it runs outside the temp workspace built above.
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yml", dir=ROOT, delete=False
        ) as handle:
            handle.write(
                "ruleDirs: []\n" + _POWERSHELL_CONFIG_EXTRA
            )
            powershell_config = Path(handle.name)
        try:
            self._run_arm_inventory(POWERSHELL_TREE, powershell_config=powershell_config)
        finally:
            powershell_config.unlink(missing_ok=True)

    def _run_classified_arms(self, tree, expected_count, powershell_config=None):
        cases = json.loads(tree.cases_path.read_text())["cases"]
        identities = [(case["rule"], case["original_path"], case["original_index"])
                      for case in cases]
        self.assertEqual(len(identities), expected_count)
        self.assertEqual(len(set(identities)), len(identities))
        rules = {path.stem: path for path in tree.rules_dir.rglob("*.yml")}
        for case in cases:
            with self.subTest(tree=tree.name, rule=case["rule"], path=case["original_path"],
                              index=case["original_index"]):
                if case["classification"] == "equivalent":
                    self.assertTrue(case["reason"])
                    continue
                self.assertIn(case["classification"], ("missing-fixture", "weak-count-oracle"))
                rule_path = rules[case["rule"]]
                rule = yaml.safe_load(rule_path.read_text())
                fixture = yaml.safe_load(
                    (tree.tests_dir / rule_path.relative_to(tree.rules_dir)).read_text()
                )
                self.assertIn(case["source"], fixture["invalid" if case["expected"] else "valid"])
                self.assertEqual(scan_count(rule, case["source"], powershell_config),
                                 case["expected"], "fixture diagnostic count changed")
                mutant = copy.deepcopy(rule)
                arms = mutant["rule"]
                for component in case["path"].split("/"):
                    arms = arms[int(component) if isinstance(arms, list) else component]
                self.assertGreater(len(arms), 1, "arm deletion must leave a valid alternative")
                del arms[case["index"]]
                observed = scan_count(mutant, case["source"], powershell_config)
                self.assertEqual(observed, case["deleted_expected"],
                                 "deleted arm's witness changed")
                self.assertNotEqual(observed, case["expected"], "matcher arm deletion survived")

    def test_classified_arms_have_distinguishing_counts(self):
        self._run_classified_arms(NATIVE_TREE, 50)

    @requires_powershell_parser
    def test_classified_arms_have_distinguishing_counts_powershell(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yml", dir=ROOT, delete=False
        ) as handle:
            handle.write("ruleDirs: []\n" + _POWERSHELL_CONFIG_EXTRA)
            powershell_config = Path(handle.name)
        try:
            self._run_classified_arms(POWERSHELL_TREE, 2, powershell_config=powershell_config)
        finally:
            powershell_config.unlink(missing_ok=True)

    def test_scanner_errors_are_not_mutant_kills(self):
        rule = {"id": "broken-control", "language": "c", "rule": {"kind": "not_a_c_kind"}}
        with self.assertRaises((json.JSONDecodeError, RuntimeError)):
            scan_count(rule, "void f(void) {}")
