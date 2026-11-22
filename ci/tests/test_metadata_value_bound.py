"""Refuse rules metadata values the harness loader rejects (non-string or over 512 chars)."""

import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
MAX_LEN = 512
LIST_KEYS = {"todo_cases"}


def metadata_violations(rules_root):
    """Return 'path: key (reason)' for metadata values the harness would refuse."""
    bad = []
    for path in sorted(Path(rules_root).rglob("*.y*ml")):
        if path.suffix not in (".yml", ".yaml"):
            continue
        with path.open(encoding="utf-8") as handle:
            for doc in yaml.safe_load_all(handle):
                meta = doc.get("metadata") if isinstance(doc, dict) else None
                if not isinstance(meta, dict):
                    continue
                rel = path.relative_to(rules_root)
                for key, item in meta.items():
                    if key in LIST_KEYS:
                        continue
                    if not isinstance(item, str):
                        bad.append(f"{rel}: {key} (not a string)")
                    elif len(item) > MAX_LEN:
                        bad.append(f"{rel}: {key} ({len(item)} chars)")
    return bad


class MetadataValueBoundTest(unittest.TestCase):
    def _fixture(self, tmp, body):
        rules = Path(tmp) / "python" / "security"
        rules.mkdir(parents=True)
        (rules / "x.yml").write_text(
            f"id: x\nlanguage: python\nmetadata:\n  {body}\n", encoding="utf-8"
        )
        return Path(tmp)

    def test_current_pack_passes(self):
        self.assertEqual(metadata_violations(REPO_ROOT / "rules"), [])

    def test_limit_is_inclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fixture(tmp, f"k: {'a' * 512}")
            self.assertEqual(metadata_violations(root), [])

    def test_over_limit_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fixture(tmp, f"k: {'a' * 513}")
            self.assertEqual(len(metadata_violations(root)), 1)

    def test_non_string_refused(self):
        for body in ("k: 5", "k: true", "k: [a, b]", "k: {a: b}"):
            with tempfile.TemporaryDirectory() as tmp:
                root = self._fixture(tmp, body)
                self.assertEqual(len(metadata_violations(root)), 1, body)

    def test_todo_cases_list_exempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fixture(tmp, f"todo_cases:\n    - {'a' * 900}")
            self.assertEqual(metadata_violations(root), [])

    def test_rule_without_metadata_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "go" / "security"
            rules.mkdir(parents=True)
            (rules / "y.yml").write_text("id: y\nlanguage: go\n", encoding="utf-8")
            self.assertEqual(metadata_violations(Path(tmp)), [])
