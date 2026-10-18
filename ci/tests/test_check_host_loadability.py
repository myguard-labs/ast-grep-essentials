"""Cover the host-loadability gate that loads the corpus on ast-grep 0.45.2."""

import contextlib
import io
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

CI_ROOT = Path(__file__).resolve().parents[1]
if str(CI_ROOT) not in sys.path:
    sys.path.insert(0, str(CI_ROOT))

# pylint: disable=wrong-import-position
import check_host_loadability as gate

RULE = "id: {id}\nlanguage: {language}\nrule:\n  pattern: foo($A)\n"

FAKE = """\
#!{python}
import sys
args = sys.argv[1:]
if args == ["--version"]:
    print("ast-grep {version}")
    raise SystemExit(0)
config = args[args.index("-c") + 1]
root = __import__("pathlib").Path(config).parent / "rules"
names = sorted(str(p.relative_to(root)) for p in root.rglob("*.yml"))
open({log!r}, "w").write("\\n".join(names))
bad = [n for n in names if "malformed" in n]
if bad:
    print("Cannot parse rule " + bad[0], file=sys.stderr)
    raise SystemExit(8)
tree = __import__("pathlib").Path(config).parent / "tree"
files = sorted(str(p.relative_to(tree)) for p in tree.rglob("*") if p.is_file())
open({log!r} + ".tree", "w").write("\\n".join(files))
if files and any("severity: error" in p.read_text() for p in root.rglob("*.yml")):
    print("error-severity rule matched " + files[0], file=sys.stderr)
    raise SystemExit(1)
"""


class HostLoadabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(scratch.cleanup)
        self.tmp = Path(scratch.name)
        self.root = self.tmp / "repo"
        (self.root / "rules").mkdir(parents=True)
        self.log = self.tmp / "staged.txt"

    def rule(self, relative: str, language: str = "python") -> None:
        path = self.root / "rules" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(RULE.format(id=path.stem, language=language))

    def fake(self, version: str = gate.MIN_VERSION) -> list[str]:
        script = self.tmp / "fake-ast-grep"
        script.write_text(
            FAKE.format(python=sys.executable, version=version, log=str(self.log))
        )
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        return [str(script)]

    def staged(self) -> list[str]:
        return self.log.read_text().splitlines()

    def test_loads_every_rule_and_reports_count(self) -> None:
        self.rule("python/security/a.yml")
        self.rule("php/security/b.yml", "php")
        self.assertEqual(gate.check(self.root, self.fake()), 2)
        self.assertEqual(self.staged(), ["php/security/b.yml", "python/security/a.yml"])

    def test_rule_that_fails_to_load_fails_the_gate(self) -> None:
        self.rule("python/security/ok.yml")
        self.rule("python/security/malformed.yml")
        with self.assertRaisesRegex(gate.GateError, r"exit 8.*malformed"):
            gate.check(self.root, self.fake())

    def test_staged_tree_has_no_source_files(self) -> None:
        self.rule("python/security/a.yml")
        gate.check(self.root, self.fake())
        self.assertEqual(Path(f"{self.log}.tree").read_text(encoding="utf-8"), "")

    def test_error_severity_rule_does_not_fail_on_empty_tree(self) -> None:
        path = self.root / "rules/python/security/error.yml"
        path.parent.mkdir(parents=True)
        path.write_text(
            "id: error\nlanguage: python\nseverity: error\nrule:\n  pattern: foo($A)\n",
            encoding="utf-8",
        )
        self.assertEqual(gate.check(self.root, self.fake()), 1)
        self.assertEqual(Path(f"{self.log}.tree").read_text(encoding="utf-8"), "")

    def test_no_rules_is_refused(self) -> None:
        with self.assertRaisesRegex(gate.GateError, "no non-PowerShell rules"):
            gate.check(self.root, self.fake())

    def test_missing_rules_directory_is_refused(self) -> None:
        with self.assertRaisesRegex(gate.GateError, "no rules directory"):
            gate.check(self.tmp / "absent", self.fake())

    def test_powershell_rules_are_excluded_by_directory_and_language(self) -> None:
        self.rule("python/security/a.yml")
        self.rule("powershell/security/malformed-dir.yml", "powershell")
        self.rule("misc/malformed-lang.yml", "PowerShell")
        self.assertEqual(gate.check(self.root, self.fake()), 1)
        self.assertEqual(self.staged(), ["python/security/a.yml"])

    def test_only_powershell_rules_counts_as_no_rules(self) -> None:
        self.rule("powershell/security/p.yml", "powershell")
        with self.assertRaisesRegex(gate.GateError, "no non-PowerShell rules"):
            gate.check(self.root, self.fake())

    def test_wrong_ast_grep_version_is_refused(self) -> None:
        self.rule("python/security/a.yml")
        with self.assertRaisesRegex(gate.GateError, "expected ast-grep 0.45.2"):
            gate.check(self.root, self.fake("0.50.0"))

    def test_version_probe_exit_code_is_named(self) -> None:
        self.rule("python/security/a.yml")
        script = self.tmp / "failing-ast-grep"
        script.write_text(
            f"#!{sys.executable}\nimport sys\n"
            "print('ast-grep 0.45.2')\nsys.stderr.write('broken install')\n"
            "raise SystemExit(3)\n",
            encoding="utf-8",
        )
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        with self.assertRaisesRegex(
            gate.GateError, r"--version exited 3.*broken install"
        ):
            gate.check(self.root, [str(script)])

    def test_missing_binary_is_a_gate_error(self) -> None:
        self.rule("python/security/a.yml")
        with self.assertRaisesRegex(gate.GateError, "cannot run"):
            gate.check(self.root, [str(self.tmp / "no-such-binary")])

    def test_main_exit_codes_and_messages(self) -> None:
        self.rule("python/security/a.yml")
        out, err = io.StringIO(), io.StringIO()
        argv = ["--root", str(self.root), "--ast-grep", *self.fake()]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(gate.main(argv), 0)
        self.assertIn("ok: 1 non-PowerShell rules", out.getvalue())
        self.rule("python/security/malformed.yml")
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(gate.main(argv), 1)
        self.assertIn("error: ast-grep 0.45.2 failed to load", err.getvalue())

    @unittest.skipUnless(os.environ.get("AST_GREP_045"), "needs AST_GREP_045")
    def test_real_binary_rejects_kindless_pattern(self) -> None:
        self.rule("php/security/kindless.yml", "php")
        path = self.root / "rules/php/security/kindless.yml"
        path.write_text(path.read_text().replace("foo($A)", '__DIR__ . "$LIT"'))
        with self.assertRaisesRegex(gate.GateError, "AST kinds"):
            gate.check(self.root, [os.environ["AST_GREP_045"]])

    @unittest.skipUnless(os.environ.get("AST_GREP_045"), "needs AST_GREP_045")
    def test_real_binary_error_severity_rule_passes_on_empty_tree(self) -> None:
        path = self.root / "rules/python/security/int.yml"
        path.parent.mkdir(parents=True)
        path.write_text(
            "id: int\nlanguage: python\nseverity: error\n"
            "rule:\n  kind: integer\nmessage: m\n"
        )
        self.assertEqual(gate.check(self.root, [os.environ["AST_GREP_045"]]), 1)


if __name__ == "__main__":
    unittest.main()
