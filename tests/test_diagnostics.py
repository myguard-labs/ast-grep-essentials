"""Assert main diagnostic text emitted by ast-grep, not just snapshots."""

import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from tests._astgrep import resolve_ast_grep

ROOT = Path(__file__).resolve().parents[1]
AST_GREP = resolve_ast_grep()
CODERABBIT_IDS = {
    entry["id"]
    for entry in json.loads((ROOT / "docs/coderabbit-rules.json").read_text())["rules"]
}


class DiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if AST_GREP is None:
            raise unittest.SkipTest(
                "ast-grep binary not found. Install with: "
                "npm install (for local node_modules/.bin/ast-grep) or "
                "install ast-grep to system PATH"
            )
    def test_all_rules_emit_declared_diagnostics(self):
        rules = sorted(
            path for path in (ROOT / "rules").rglob("*.yml")
            if path.relative_to(ROOT / "rules").parts[0] != "powershell"
        )
        self.assertEqual(len(rules), 450, "update the explicit diagnostic inventory")
        checked = 0
        for path in rules:
            with self.subTest(rule=path.stem):
                declared = yaml.safe_load(path.read_text())
                fixture = yaml.safe_load(
                    (ROOT / "tests" / path.relative_to(ROOT / "rules")).read_text()
                )
                # A direct --rule scan evaluates off rules and reports their
                # declared severity, unlike project-config discovery.
                result = subprocess.run(
                    [AST_GREP, "scan", "--rule", path, "--json=compact", "--stdin"],
                    input=fixture["invalid"][0], text=True, capture_output=True,
                    check=False, timeout=15,
                )
                self.assertIn(result.returncode, (0, 1), result.stderr)
                findings = json.loads(result.stdout)
                self.assertTrue(findings, "first invalid fixture must emit a finding")
                finding = findings[0]
                self.assertEqual(finding["ruleId"], declared["id"])
                for field in ("message", "note", "severity"):
                    expected = declared[field]
                    if field == "severity" and expected is False:
                        expected = "off"
                    if path.stem in CODERABBIT_IDS and field in ("message", "note"):
                        # Upstream diagnostics interpolate captured metavariables.
                        self.assertIsInstance(finding[field], str, field)
                        self.assertTrue(finding[field].strip(), field)
                        for token in re.findall(r"\$[A-Z][A-Z0-9_]*", expected):
                            self.assertIn(
                                token[1:],
                                finding["metaVariables"]["single"],
                                f"unbound {field} token {token}",
                            )
                    else:
                        self.assertEqual(finding[field], expected, field)
                checked += 1
        self.assertEqual(checked, 450)

    def test_deprecated_rule_id_matcher_tracks_replacement(self):
        replacement = yaml.safe_load(
            (ROOT / "rules/c/correctness/c-string-sizeof-includes-nul.yml").read_text()
        )
        alias = yaml.safe_load(
            (ROOT / "rules/c/correctness/nginx-string-sizeof-includes-nul.yml").read_text()
        )
        metadata = {"id", "severity", "message", "note"}
        replacement_matcher = {
            key: value for key, value in replacement.items() if key not in metadata
        }
        alias_matcher = {
            key: value for key, value in alias.items() if key not in metadata
        }
        self.assertEqual(alias_matcher, replacement_matcher)

    def test_deprecated_rule_id_preserves_explicit_promotion(self):
        source = 'void f(void) { value.len = sizeof("text"); }\n'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "positive.c"
            path.write_text(source)

            normal = subprocess.run(
                [AST_GREP, "scan", "-c", ROOT / "sgconfig.yml",
                 "--json=compact", path],
                text=True, capture_output=True, check=False, timeout=15,
            )
            self.assertEqual(normal.returncode, 0, normal.stderr)
            self.assertEqual(
                [finding["ruleId"] for finding in json.loads(normal.stdout)],
                ["c-string-sizeof-includes-nul"],
            )

            promoted = subprocess.run(
                [AST_GREP, "scan", "-c", ROOT / "sgconfig.yml",
                 "--error=nginx-string-sizeof-includes-nul",
                 "--json=compact", path],
                text=True, capture_output=True, check=False, timeout=15,
            )
            self.assertEqual(promoted.returncode, 1, promoted.stderr)
            self.assertEqual(
                sorted(finding["ruleId"] for finding in json.loads(promoted.stdout)),
                ["c-string-sizeof-includes-nul", "nginx-string-sizeof-includes-nul"],
            )

    def test_no_error_rule_concedes_a_routine_dismissal(self):
        """Error severity can fail a consumer's scan, so it is reserved for
        near-zero-false-positive defects. A rule whose own note concedes that it
        is routinely dismissed, or that it cannot establish its claim, is
        advisory by definition and must carry severity warning."""
        concessions = (
            "routine dismissal",
            "known false positive",
            "is a false positive",
            "legitimate dismissal",
            "false positive is accepted",
        )
        offenders = []
        paths = sorted(
            path for path in (ROOT / "rules").rglob("*.yml")
            if path.relative_to(ROOT / "rules").parts[0] != "powershell"
        )
        for path in paths:
            declared = yaml.safe_load(path.read_text())
            if declared.get("severity") != "error":
                continue
            note = declared.get("note") or ""
            hit = next((c for c in concessions if c in note), None)
            if hit is not None:
                offenders.append(f"{declared['id']}: note concedes {hit!r}")
        self.assertEqual(offenders, [], "demote these rules to severity warning")

    CASES = (
        (
            "php/security/php-extract-superglobal.yml",
            "<?php extract($_POST);",
            ("GET, POST, REQUEST, COOKIE or SERVER superglobal",),
            ("(////)",),
        ),
        (
            "go/security/go-sql-sprintf.yml",
            'package p; func f() { db.Query(fmt.Sprintf("SELECT %s", column)) }',
            ("numbered dollar placeholders or question marks",),
            ("placeholders (, ?)",),
        ),
        (
            "c/security/c-prctl-set-dumpable.yml",
            "void f(void) { prctl(PR_SET_DUMPABLE, 1L); }",
            ("optional U/L suffix", "RLIMIT_CORE is ignored for piped collectors", "core.5.html"),
            ("fs.suid_dumpable=0",),
        ),
        (
            "php/security/php-unserialize.yml",
            "<?php unserialize($data);",
            ("standard data format such as JSON", "independently trusted or authenticated"),
            (),
        ),
        (
            "php/correctness/wp-wpdb-prepare-quoted-placeholder.yml",
            '<?php $wpdb->prepare("SELECT * FROM t WHERE id = \'%d\'", $id);',
            ("plain %s", "Numbered or formatted string placeholders", "%1$s", "%05s"),
            ("leave the bare placeholder",),
        ),
        (
            "php/security/wp-wpdb-orderby-interpolation.yml",
            '<?php $wpdb->get_results("SELECT * FROM t ORDER BY {$orderby}");',
            ("WordPress 6.2", "%i", "identifier_placeholders", "%d", "ASC or DESC"),
            ("Placeholders cannot be used for identifiers", "prepare offers no protection"),
        ),
        (
            "python/security/py-eval-exec.yml",
            'eval("1 + 1")',
            ("requires review", "external input", "trusted, resource-bounded input",
             "format-specific parser with input limits", "exhaust memory"),
            ("on a non-literal",),
        ),
        (
            "python/security/py-yaml-load-unsafe.yml",
            "yaml.load(data)",
            ("Modern PyYAML versions require an explicit Loader", "API and security review"),
            ("the default loader",),
        ),
        (
            "python/correctness/py-bare-except.yml",
            "try:\n    work()\nexcept:\n    pass",
            ("BaseException subclasses", "KeyboardInterrupt", "SystemExit"),
            ("MemoryError", "out-of-memory"),
        ),
        (
            "c/correctness/c-time-truncated-to-int.yml",
            "void f(void) { unsigned int stamp = time(NULL); }",
            ("Signed 32-bit seconds", "unsigned types have a different range", "time.2.html"),
            (),
        ),
        (
            "go/security/go-weak-hash-import.yml",
            'package p\nimport "crypto/md5"',
            ("review of the construction", "does not establish compromise", "rfc6151"),
            ("broken for any security use",),
        ),
        (
            "go/security/go-math-rand.yml",
            'package p\nimport "math/rand"',
            ("import alone does not identify", "ChaCha8-based global generation"),
            ("a deterministic, predictable PRNG",),
        ),
        (
            "go/correctness/go-context-cancel-leak.yml",
            "package m; func f() { ctx, _ := context.WithCancelCause(p); use(ctx) }",
            ("defer cancel()", "defer cancel(nil)", "WithCancelCause"),
            (),
        ),
        (
            "c/correctness/c-signal-not-sigaction.yml",
            "void f(void) { signal(SIGTERM, handler); }",
            ("sigaction.2.html",),
            (),
        ),
        (
            "c/correctness/c-localtime-not-reentrant.yml",
            "void f(void) { localtime(&now); }",
            ("ctime.3.html",),
            (),
        ),
        (
            "c/security/c-snprintf-return-advance.yml",
            'void f(void) { p += snprintf(p, n, "%s", value); }',
            ("printf.3.html",),
            (),
        ),
    )

    def test_php_sql_secondary_labels_are_unique(self):
        for source in (
            '<?php query("SELECT $column");',
            '<?php QUERY("SELECT $column");',
            '<?php mysqli_query($db, "SELECT $column");',
            '<?php mysqli_execute_query($db, "SELECT $column");',
            '<?php \\mysqli_execute_query($db, "SELECT $column");',
        ):
            with self.subTest(source=source):
                result = subprocess.run(
                    [AST_GREP, "scan", "--rule",
                     ROOT / "rules/php/security/php-sql-string-interp.yml",
                     "--json=compact", "--stdin"],
                    input=source, text=True, capture_output=True, check=True,
                )
                findings = json.loads(result.stdout)
                self.assertEqual(len(findings), 1)
                labels = findings[0]["labels"]
                ranges = [
                    (label["range"]["byteOffset"]["start"],
                     label["range"]["byteOffset"]["end"])
                    for label in labels if label["style"] == "secondary"
                ]
                self.assertTrue(ranges)
                self.assertEqual(len(ranges), len(set(ranges)),
                                 "duplicate secondary label ranges")
                self.assertEqual(sum(label["text"] == '\"SELECT $column\"'
                                     for label in labels), 1)

    def test_php_upload_diagnostic_is_literal_and_complete(self):
        result = subprocess.run(
            [AST_GREP, "scan", "--rule",
             ROOT / "rules/php/security/php-upload-unvalidated-name.yml",
             "--json=compact", "--stdin"],
            input="<?php move_uploaded_file($_FILES['f']['tmp_name'], "
                  "'/uploads/' . $_FILES['f']['name']);",
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        findings = json.loads(result.stdout)
        self.assertEqual(len(findings), 1, result.stderr)
        finding = findings[0]
        self.assertEqual(finding["severity"], "error")
        diagnostic = f'{finding["message"]}\n{finding["note"]}'
        self.assertIn("client-supplied upload name field", diagnostic)
        self.assertIn("Generate the stored name yourself", diagnostic)
        self.assertNotIn("$_FILES", diagnostic)

    def test_emitted_diagnostic_contracts(self):
        for relative, source, required, forbidden in self.CASES:
            with self.subTest(rule=relative):
                result = subprocess.run(
                    [
                        AST_GREP,
                        "scan",
                        "--rule",
                        ROOT / "rules" / relative,
                        "--json=compact",
                        "--stdin",
                    ],
                    input=source,
                    text=True,
                    capture_output=True,
                    check=True,
                )
                findings = json.loads(result.stdout)
                self.assertEqual(len(findings), 1, result.stderr)
                finding = findings[0]
                self.assertEqual(finding["ruleId"], Path(relative).stem)
                self.assertEqual(finding["severity"], "warning")
                diagnostic = f'{finding["message"]}\n{finding["note"]}'
                self.assertNotIn("_shared/", diagnostic)
                for fragment in required:
                    self.assertIn(fragment, diagnostic)
                for fragment in forbidden:
                    self.assertNotIn(fragment, diagnostic)


if __name__ == "__main__":
    unittest.main()
