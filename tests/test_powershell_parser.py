"""Controls for the opt-in PowerShell custom-language integration.

The parser is a dynamic library ast-grep loads at scan time. That makes it a
security boundary: an absent, mismatched or broken library must never degrade
into "scan completed, zero findings", because a clean report is exactly what a
missing parser and a clean codebase look like from the outside.

These tests therefore assert two separable properties:

* the integration works when the parser is present (positive discovery), and
* it fails *closed* -- non-zero exit, diagnostic on stderr, no findings output
  -- for a missing parser, a wrong-architecture parser, and a parser that
  errors on the input.

They also pin the isolation property that motivates the separate config: the
native-language scan driven by `sgconfig.yml` must be unaffected whether or not
the PowerShell grammar has ever been built.
"""

import json
import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
AST_GREP = ROOT / "node_modules" / ".bin" / "ast-grep"
PSH_CONFIG = ROOT / "sgconfig.powershell.yml"
NATIVE_CONFIG = ROOT / "sgconfig.yml"
BUILD_DIR = ROOT / "build" / "powershell"
BUILD_SCRIPT = ROOT / "tools" / "powershell" / "build-grammar.sh"

# The build script emits the platform-native suffix, so the artifact this host
# should have is not always `.so`.
HOST_SUFFIX = {"Darwin": ".dylib", "Windows": ".dll"}.get(platform.system(), ".so")
LIBRARY = BUILD_DIR / f"powershell{HOST_SUFFIX}"

# Any artifact the build script could have produced, on any platform. Used to
# tell "nothing was built" (skip is honest) apart from "something was built but
# this host cannot use it" (a failure that must not hide behind a skip).
ANY_ARTIFACT_SUFFIXES = (".so", ".dylib", ".dll")


def _netns_available():
    """Can we run a child with no network? Used to keep build controls offline."""
    try:
        return subprocess.run(
            ["unshare", "-rn", "true"],
            capture_output=True, timeout=30, check=False,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


NETNS_AVAILABLE = _netns_available()

PROBE_SCRIPT = "Invoke-Expression $userInput\n"

# A rule that matches the probe script, written out per-test so the controls do
# not depend on the rule pack that later work adds.
PROBE_RULE = """
id: psh-control-probe
language: powershell
severity: warning
message: probe
rule:
  pattern: Invoke-Expression $A
"""


def library_available():
    return LIBRARY.is_file()


def built_artifacts():
    """Every grammar artifact present, regardless of which platform built it."""
    if not BUILD_DIR.is_dir():
        return []
    return sorted(
        p for p in BUILD_DIR.iterdir()
        if p.is_file() and p.suffix in ANY_ARTIFACT_SUFFIXES
    )


requires_parser = unittest.skipUnless(
    library_available(),
    f"PowerShell grammar not built; run {BUILD_SCRIPT.relative_to(ROOT)}",
)


class PowerShellHarness(unittest.TestCase):
    """Build a throwaway workspace whose config points at a chosen library."""

    def workspace(self, library_path, extensions=("ps1", "psm1", "psd1"),
                  script=PROBE_SCRIPT, filename="probe.ps1"):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "rules-powershell").mkdir()
        (tmp / "rules-powershell" / "probe.yml").write_text(PROBE_RULE)
        (tmp / "src").mkdir()
        (tmp / "src" / filename).write_text(script)
        exts = "\n".join(f"      - {e}" for e in extensions)
        (tmp / "sgconfig.yml").write_text(
            "ruleDirs:\n"
            "  - rules-powershell\n"
            "customLanguages:\n"
            "  powershell:\n"
            f"    libraryPath: {library_path}\n"
            "    extensions:\n"
            f"{exts}\n"
            "    expandoChar: 'µ'\n"
        )
        return tmp

    def scan(self, tmp, json_output=True):
        cmd = [str(AST_GREP), "scan", "-c", str(tmp / "sgconfig.yml")]
        if json_output:
            cmd.append("--json=compact")
        cmd.append(str(tmp / "src"))
        return subprocess.run(cmd, capture_output=True, text=True, check=False)


class TestPositiveDiscovery(PowerShellHarness):
    """The parser, when present, actually finds PowerShell code."""

    @requires_parser
    def test_ps1_is_discovered_and_matched(self):
        tmp = self.workspace(LIBRARY)
        result = self.scan(tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        findings = json.loads(result.stdout)
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(findings[0]["ruleId"], "psh-control-probe")
        self.assertTrue(findings[0]["file"].endswith("probe.ps1"))

    @requires_parser
    def test_psm1_is_discovered(self):
        tmp = self.workspace(LIBRARY, filename="module.psm1")
        result = self.scan(tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)), 1)

    @requires_parser
    def test_psd1_is_discovered(self):
        """`.psd1` registration is gated on this parsing cleanly.

        PowerShell data files are a subset of the script grammar, so the same
        parser handles them; the assertion here is that registering the
        extension actually yields a parsed, matchable tree rather than a file
        ast-grep walks past.
        """
        tmp = self.workspace(LIBRARY, filename="manifest.psd1")
        result = self.scan(tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)), 1)

    @requires_parser
    def test_psd1_manifest_parses_without_error_nodes(self):
        """The evidence that justified registering `.psd1` at all."""
        manifest = (
            "@{\n"
            "    ModuleVersion = '1.0.0'\n"
            "    GUID = '11111111-2222-3333-4444-555555555555'\n"
            "    FunctionsToExport = @('Get-Thing')\n"
            "    PrivateData = @{ PSData = @{ Tags = @('a') } }\n"
            "}\n"
        )
        tmp = self.workspace(LIBRARY, script=manifest, filename="manifest.psd1")
        (tmp / "rules-powershell" / "probe.yml").write_text(
            "id: psh-parse-error\n"
            "language: powershell\n"
            "severity: error\n"
            "message: parse error\n"
            "rule:\n"
            "  kind: ERROR\n"
        )
        result = self.scan(tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [], "manifest produced ERROR nodes")


class TestFailsClosed(PowerShellHarness):
    """A parser that is absent, wrong or broken must not report "clean"."""

    def assert_failed_closed(self, result):
        self.assertNotEqual(
            result.returncode, 0,
            "scan exited 0; an unusable parser must not look like a clean scan",
        )
        self.assertIn("custom language", result.stderr.lower())
        # No findings document may be emitted -- a consumer parsing stdout as
        # JSON must not receive an empty, successful-looking result set.
        self.assertNotEqual(result.stdout.strip(), "[]")

    def test_missing_parser_fails_closed(self):
        tmp = self.workspace("build/powershell/absent.so")
        self.assert_failed_closed(self.scan(tmp))

    def test_wrong_architecture_parser_fails_closed(self):
        """A library for another architecture is present but unloadable."""
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        bogus = tmp / "wrong-arch.so"
        # A valid ELF header claiming an architecture the host loader will
        # refuse (EM_AARCH64 = 183 on an x86-64 host, and vice versa), followed
        # by nothing loadable. The point is that the file exists and is
        # readable, so only real loading -- not a stat() -- can reject it.
        header = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
        header += (3).to_bytes(2, "little")  # ET_DYN
        # platform.machine(), not os.uname(): the latter does not exist on
        # native Windows Python and would raise AttributeError before this
        # control ever reached the loader it is meant to exercise.
        machine = 183 if platform.machine() in ("x86_64", "AMD64") else 62
        header += machine.to_bytes(2, "little")
        header += b"\x00" * 64
        bogus.write_bytes(bytes(header))
        work = self.workspace(bogus)
        self.assert_failed_closed(self.scan(work))

    def test_corrupt_parser_fails_closed(self):
        """A file that is not a shared object at all."""
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        bogus = tmp / "not-a-library.so"
        bogus.write_text("this is not a shared object\n")
        work = self.workspace(bogus)
        self.assert_failed_closed(self.scan(work))

    @requires_parser
    def test_parser_error_is_reported_not_swallowed(self):
        """Unparsable PowerShell surfaces as an ERROR node, not as silence.

        This is the fourth failure mode: the library loads fine, but the input
        defeats the grammar. A rule pack that cannot see ERROR nodes would
        report such a file as clean.
        """
        malformed = "function Broken {\n    param([string]$x\n    if ($x -eq\n}\n"
        tmp = self.workspace(LIBRARY, script=malformed)
        (tmp / "rules-powershell" / "probe.yml").write_text(
            "id: psh-parse-error\n"
            "language: powershell\n"
            "severity: error\n"
            "message: parse error\n"
            "rule:\n"
            "  kind: ERROR\n"
        )
        result = self.scan(tmp)
        findings = json.loads(result.stdout)
        self.assertGreater(
            len(findings), 0,
            "malformed PowerShell produced no ERROR node; parse failures would be invisible",
        )


class TestChecksumGateFailsClosed(unittest.TestCase):
    """A malformed lockfile must abort the build, never verify nothing.

    The provenance gate is the security boundary this whole integration rests
    on: ast-grep loads the built library as native code, so a substituted
    grammar silently changes which findings are reported. The dangerous failure
    is not a checksum *mismatch* -- that path was always correct -- but a
    lockfile whose checksum list cannot be read or does not cover every
    compiled source. Historically that made the extractor fail inside a process
    substitution whose exit status `set -e` could not observe, so zero
    checksums were compared and the script compiled anyway, exiting 0.

    These controls run the real script against doctored lockfiles and require a
    non-zero exit. They are offline: each case must be rejected before the
    script ever fetches anything.
    """

    def run_with_lock(self, lock_data, offline=True):
        """Run the build script against a doctored copy of the lockfile.

        Offline by default. The script validates the lockfile before it
        fetches, so a rejection must not depend on the network being up -- and
        running these with networking available would let a control "pass" on a
        DNS failure without exercising the checksum logic at all.
        """
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        tools = tmp / "tools" / "powershell"
        tools.mkdir(parents=True)
        shutil.copy(BUILD_SCRIPT, tools / BUILD_SCRIPT.name)
        (tools / "grammar.lock.json").write_text(json.dumps(lock_data))
        cmd = [str(tools / BUILD_SCRIPT.name), str(tmp / "out.so")]
        if offline and NETNS_AVAILABLE:
            cmd = ["unshare", "-rn"] + cmd
        return subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=300,
        )

    def valid_lock(self):
        return json.loads((BUILD_SCRIPT.parent / "grammar.lock.json").read_text())

    def assert_refused(self, result, because, diagnostic=None):
        self.assertNotEqual(
            result.returncode, 0,
            f"build exited 0 with {because}; an unverified parser was built.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}",
        )
        self.assertNotIn(
            "==> compiling", result.stdout,
            f"build reached the compile step with {because}",
        )
        # Assert the specific rejection, not merely a non-zero exit: without
        # this a control would also "pass" on a network failure, an interpreter
        # error, or any other incidental crash.
        self.assertNotIn(
            "==> fetching", result.stdout,
            f"build fetched before rejecting {because}; validation must "
            "precede the download so the gate does not depend on the network",
        )
        if diagnostic is not None:
            self.assertIn(
                diagnostic, result.stderr,
                f"expected the {because} rejection to say {diagnostic!r}",
            )

    def test_missing_sourceSha256_aborts(self):
        """The reported bypass: no checksum list at all."""
        lock = self.valid_lock()
        del lock["grammar"]["sourceSha256"]
        self.assert_refused(self.run_with_lock(lock), "sourceSha256 removed",
                            "unreadable lockfile")

    def test_partial_sourceSha256_aborts(self):
        """A lockfile covering parser.c but not scanner.c.

        Verifying only the entries that happen to be present would let an
        attacker skip verification of a file by omitting its entry, while the
        build still reported checksums as "ok".
        """
        lock = self.valid_lock()
        lock["grammar"]["sourceSha256"].pop("src/scanner.c")
        self.assert_refused(self.run_with_lock(lock), "scanner.c entry omitted",
                            "sourceSha256 has no entry for: src/scanner.c")

    def test_empty_sourceSha256_aborts(self):
        lock = self.valid_lock()
        lock["grammar"]["sourceSha256"] = {}
        self.assert_refused(self.run_with_lock(lock), "an empty checksum map",
                            "sourceSha256 must be a non-empty object")

    def test_wrong_typed_sourceSha256_aborts(self):
        lock = self.valid_lock()
        lock["grammar"]["sourceSha256"] = ["src/parser.c"]
        self.assert_refused(self.run_with_lock(lock), "a list instead of a map",
                            "sourceSha256 must be a non-empty object")

    def test_malformed_digest_aborts(self):
        """A digest that is not a sha256 cannot silently compare unequal."""
        lock = self.valid_lock()
        lock["grammar"]["sourceSha256"]["src/parser.c"] = "not-a-digest"
        self.assert_refused(self.run_with_lock(lock), "a malformed digest",
                            "is not a sha256 digest")

    def test_unparsable_lockfile_aborts(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        tools = tmp / "tools" / "powershell"
        tools.mkdir(parents=True)
        shutil.copy(BUILD_SCRIPT, tools / BUILD_SCRIPT.name)
        (tools / "grammar.lock.json").write_text("{ this is not json")
        cmd = [str(tools / BUILD_SCRIPT.name), str(tmp / "out.so")]
        if NETNS_AVAILABLE:
            cmd = ["unshare", "-rn"] + cmd
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=300,
        )
        self.assert_refused(result, "an unparsable lockfile", "unreadable lockfile")

    def test_digest_for_a_non_compiled_file_aborts(self):
        """A digest with no matching source verifies a file nobody compiles."""
        lock = self.valid_lock()
        lock["grammar"]["sourceSha256"]["src/ghost.c"] = "0" * 64
        self.assert_refused(
            self.run_with_lock(lock), "a digest for a non-compiled file",
            "entries for non-compiled files",
        )


class TestCompiledSetMatchesVerifiedSet(unittest.TestCase):
    """Every C source the archive ships must be verified and compiled.

    The controls above keep the lockfile internally consistent. That is not
    sufficient: a lockfile can agree with itself and still be wrong about the
    grammar. Dropping scanner.c from both `sources` and `sourceSha256` passes
    every internal-consistency check, and the parser then gets built without
    its external lexer -- hand-written C, and the most attractive part of a
    Tree-sitter grammar to tamper with.

    This control needs the network, because the invariant is about the
    extracted archive rather than the lockfile alone.
    """

    def test_lockfile_omitting_a_shipped_source_aborts(self):
        lock = json.loads(
            (BUILD_SCRIPT.parent / "grammar.lock.json").read_text()
        )
        lock["grammar"]["sources"] = ["src/parser.c"]
        lock["grammar"]["sourceSha256"].pop("src/scanner.c")

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        tools = tmp / "tools" / "powershell"
        tools.mkdir(parents=True)
        shutil.copy(BUILD_SCRIPT, tools / BUILD_SCRIPT.name)
        (tools / "grammar.lock.json").write_text(json.dumps(lock))

        out = tmp / "out.so"
        result = subprocess.run(
            [str(tools / BUILD_SCRIPT.name), str(out)],
            capture_output=True, text=True, check=False, timeout=600,
        )
        if "==> fetching" in result.stdout and result.returncode != 0 \
                and "refusing to build" not in result.stderr:
            self.skipTest(f"could not fetch the grammar: {result.stderr[:200]}")

        self.assertNotEqual(
            result.returncode, 0,
            "build exited 0 with scanner.c dropped from the lockfile; "
            "the external lexer was compiled without ever being verified.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}",
        )
        self.assertNotIn("==> compiling", result.stdout)
        self.assertIn(
            "pinned sources do not match the C sources in the archive",
            result.stderr,
        )
        self.assertFalse(out.exists(), "an unverified library was produced")


class TestSkipCannotMasqueradeAsPass(unittest.TestCase):
    """A built artifact this host cannot use must fail, never skip.

    Every parser-dependent test above is guarded by `requires_parser`, which
    skips when the host artifact is absent. That guard is correct only when the
    grammar genuinely was not built: a skip and a pass are indistinguishable in
    a suite summary, so if a build *did* succeed and the tests skipped anyway,
    the whole positive-discovery half of this file would silently stop
    asserting anything -- on exactly the platform it was meant to cover.

    This test closes that gap. It is deliberately NOT guarded by
    `requires_parser`.
    """

    def test_built_artifact_matches_this_host(self):
        artifacts = built_artifacts()
        if not artifacts:
            self.skipTest(
                "no grammar artifact built at all; "
                f"run {BUILD_SCRIPT.relative_to(ROOT)}"
            )
        self.assertTrue(
            LIBRARY.is_file(),
            "a grammar artifact was built ("
            + ", ".join(p.name for p in artifacts)
            + f") but this host needs {LIBRARY.name}. The parser tests would "
            "skip and the suite would look green while nothing was verified. "
            "Rebuild with tools/powershell/build-grammar.sh on this platform.",
        )

    def test_config_maps_this_host_target(self):
        """The config must name a path for a host that can build the grammar.

        Independent of whether anything is built: a host absent from the
        `libraryPath` map fails closed at scan time, but it would do so with a
        generic loader error long after someone believed the platform was
        supported. Assert the mapping is declared for the suffix this host
        actually produces.
        """
        config = yaml.safe_load(PSH_CONFIG.read_text())
        library_path = config["customLanguages"]["powershell"]["libraryPath"]
        self.assertIsInstance(
            library_path, dict,
            "libraryPath must be a target-triple map; a single hardcoded path "
            "cannot match the platform-specific suffix the build script emits",
        )
        suffixes = {Path(v).suffix for v in library_path.values()}
        self.assertIn(
            HOST_SUFFIX, suffixes,
            f"no libraryPath entry uses {HOST_SUFFIX}, which this host builds",
        )


class TestNativeScanUnaffected(unittest.TestCase):
    """The opt-in config must not change the default scan in either direction."""

    def test_native_config_declares_no_custom_language(self):
        text = NATIVE_CONFIG.read_text()
        self.assertNotIn(
            "customLanguages", text,
            "registering a custom language in sgconfig.yml aborts the whole scan "
            "when its library is absent, breaking all native-language rules",
        )

    def test_native_scan_succeeds_regardless_of_grammar(self):
        """Native rules run identically whether or not the grammar is built."""
        result = subprocess.run(
            [str(AST_GREP), "scan", "-c", str(NATIVE_CONFIG),
             "--json=compact", str(ROOT / "tests" / "python")],
            capture_output=True, text=True, cwd=ROOT, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        json.loads(result.stdout)

    def test_powershell_rules_are_not_in_the_native_rule_dir(self):
        """Native discovery counts stay untouched by the PowerShell pack."""
        native_langs = {p.name for p in (ROOT / "rules").iterdir() if p.is_dir()}
        self.assertNotIn("powershell", native_langs)


if __name__ == "__main__":
    unittest.main()
