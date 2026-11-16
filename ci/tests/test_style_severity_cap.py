"""Refuse warning/error severity for rules under rules/*/style/."""

import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
ALLOWED = {"info", "hint", "off"}


def style_violations(rules_root):
    """Return 'path: severity' for style rules outside the allowed severities."""
    bad = []
    for path in sorted(Path(rules_root).glob("*/style/**/*.y*ml")):
        if path.suffix not in (".yml", ".yaml"):
            continue
        with path.open(encoding="utf-8") as handle:
            for doc in yaml.safe_load_all(handle):
                if not isinstance(doc, dict):
                    continue
                raw = doc.get("severity", "hint")
                # YAML 1.1 loads an unquoted `off` as False.
                sev = "off" if raw is False else str(raw).strip().lower()
                if sev not in ALLOWED:
                    bad.append(f"{path.relative_to(rules_root)}: {sev}")
    return bad


class StyleSeverityCapTest(unittest.TestCase):
    def _fixture(self, tmp, severity):
        style = Path(tmp) / "python" / "style"
        style.mkdir(parents=True)
        (style / "x.yml").write_text(
            f"id: x\nlanguage: python\nseverity: {severity}\nrule:\n  pattern: a\n",
            encoding="utf-8",
        )
        return Path(tmp)

    def test_current_pack_passes(self):
        self.assertEqual(style_violations(REPO_ROOT / "rules"), [])

    def test_error_and_warning_fail(self):
        for sev in ("error", "warning"):
            with tempfile.TemporaryDirectory() as tmp:
                self.assertEqual(len(style_violations(self._fixture(tmp, sev))), 1, sev)

    def test_info_hint_off_pass(self):
        for sev in ("info", "hint", "off"):
            with tempfile.TemporaryDirectory() as tmp:
                self.assertEqual(style_violations(self._fixture(tmp, sev)), [], sev)

    def test_non_style_dir_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            sec = Path(tmp) / "python" / "security"
            sec.mkdir(parents=True)
            (sec / "y.yml").write_text("id: y\nseverity: error\n", encoding="utf-8")
            self.assertEqual(style_violations(Path(tmp)), [])


if __name__ == "__main__":
    unittest.main()
