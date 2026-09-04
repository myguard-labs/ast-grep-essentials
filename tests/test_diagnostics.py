"""Assert main diagnostic text emitted by ast-grep, not just snapshots."""

import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AST_GREP = ROOT / "node_modules" / ".bin" / "ast-grep"


class DiagnosticTests(unittest.TestCase):
    CASES = (
        (
            "c/security/c-prctl-set-dumpable.yml",
            "void f(void) { prctl(PR_SET_DUMPABLE, 1L); }",
            ("1/1L", "RLIMIT_CORE is ignored for piped collectors", "core.5.html"),
            ("fs.suid_dumpable=0",),
        ),
        (
            "php/security/php-unserialize.yml",
            "<?php unserialize($data);",
            ("standard data format such as JSON", "independently trusted or authenticated"),
            (),
        ),
        (
            "python/security/py-eval-exec.yml",
            'eval("1 + 1")',
            ("requires review", "external input"),
            ("on a non-literal",),
        ),
        (
            "python/security/py-yaml-load-unsafe.yml",
            "yaml.load(data)",
            ("Modern PyYAML versions require an explicit Loader", "API and security review"),
            ("the default loader",),
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
