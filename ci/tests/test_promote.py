"""Tests for the reviewed-pack promotion gates in ci/promote.py."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from collections.abc import Iterator
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path, PurePosixPath
from unittest.mock import patch

CI_ROOT = Path(__file__).resolve().parents[1]
if str(CI_ROOT) not in sys.path:
    sys.path.insert(0, str(CI_ROOT))

# pylint: disable=protected-access,wrong-import-position
import promote

FAKE_ENGINE = textwrap.dedent(
    """\
    #!{python}
    import json, pathlib, sys, time
    cfg = json.loads(pathlib.Path({config!r}).read_text())
    cmd = sys.argv[1]
    if cmd == "--version":
        print("ast-grep " + cfg["version"]) if cfg["version"] else print("weird")
        sys.exit(0)
    if cmd == "test":
        print(cfg["test_out"])
        sys.exit(cfg["test_rc"])
    state = pathlib.Path({config!r} + ".n")
    n = int(state.read_text()) if state.exists() else 0
    state.write_text(str(n + 1))
    time.sleep(cfg["sleep"])
    lines = cfg["scan"] + (cfg["extra"] if cfg["vary"] and n % 2 else [])
    for rule in lines:
        print(rule if rule.startswith("{{") or not rule else json.dumps({{"ruleId": rule}}))
    sys.exit(cfg["scan_rc"])
    """
)

GOOD_TEST_OUT = "PASS py-one\n\ntest result: ok. 1 passed; 0 failed;"


def sh(cwd: Path, *argv: str) -> str:
    return subprocess.run(
        argv, cwd=cwd, check=True, text=True, capture_output=True
    ).stdout


class Fixture:
    """A throwaway rule-pack repository with a fake engine and an origin."""

    def __init__(self, base: Path) -> None:
        self.base = base
        self.repo = base / "repo"
        self.origin = base / "origin.git"
        self.config = base / "engine.json"
        self.engine = base / "ast-grep"
        self.cfg = {
            "version": "0.45.3",
            "test_out": GOOD_TEST_OUT,
            "test_rc": 0,
            "scan": ["py-one", ""],
            "extra": ["py-one"],
            "vary": False,
            "sleep": 0,
            "scan_rc": 1,
        }
        self.save()
        self.engine.write_text(
            FAKE_ENGINE.format(python=sys.executable, config=str(self.config))
        )
        self.engine.chmod(0o755)
        self.write(
            "package.json", json.dumps({"devDependencies": {"@ast-grep/cli": "0.45.3"}})
        )
        self.rule("py-one")
        self.write("ci/corpus/sample.py", "print('hello')\n")
        self.write(
            "ci/tests/test_ok.py",
            "import unittest\nclass T(unittest.TestCase):\n    def test(self): pass\n",
        )
        self.write(".gitignore", "__pycache__/\n")

    def save(self) -> None:
        self.config.write_text(json.dumps(self.cfg))

    def set(self, **values: object) -> None:
        self.cfg.update(values)
        self.save()

    def write(self, rel: str, text: str) -> Path:
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def rule(self, rule_id: str, controls: str | None = None) -> None:
        self.write(
            f"rules/python/security/{rule_id}.yml",
            f"id: {rule_id}\nlanguage: python\nrule: {{kind: call}}\n",
        )
        if controls is None:
            controls = f"id: {rule_id}\nvalid: ['x']\ninvalid: ['f()']\n"
        if controls:
            self.write(f"tests/python/security/{rule_id}.yml", controls)

    def baseline(self, **perf: object) -> dict:
        data = promote.build_baseline(self.repo, self.engine, 1, None)
        data["perf"].update(perf)
        promote.write_baseline(self.repo, data)
        return data

    def init_git(self) -> None:
        sh(self.base, "git", "init", "-q", "--bare", "-b", "main", str(self.origin))
        key = self.base / "signing"
        sh(
            self.base,
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "t@example.invalid",
            "-f",
            str(key),
        )
        allowed = self.base / "allowed"
        allowed.write_text(
            "t@example.invalid " + (self.base / "signing.pub").read_text()
        )
        for argv in (
            ["git", "init", "-q", "-b", "main"],
            ["git", "config", "user.name", "Test"],
            ["git", "config", "user.email", "t@example.invalid"],
            ["git", "config", "commit.gpgsign", "false"],
            ["git", "config", "tag.gpgsign", "false"],
            ["git", "config", "gpg.format", "ssh"],
            ["git", "config", "user.signingkey", str(key)],
            ["git", "config", "gpg.ssh.allowedSignersFile", str(allowed)],
            ["git", "remote", "add", "origin", str(self.origin)],
        ):
            sh(self.repo, *argv)
        self.commit("base")

    def commit(self, message: str, push: bool = True) -> str:
        sh(self.repo, "git", "add", "-A")
        sh(self.repo, "git", "commit", "-q", "-m", message)
        if push:
            sh(self.repo, "git", "push", "-q", "origin", "HEAD:refs/heads/main")
        return sh(self.repo, "git", "rev-parse", "HEAD").strip()


@contextmanager
def fixture() -> Iterator[Fixture]:
    with tempfile.TemporaryDirectory() as tmp:
        yield Fixture(Path(tmp))


def signed_tag(repo: Path, name: str, rev: str = "HEAD") -> None:
    sh(repo, "git", "tag", "-s", "-m", f"review {name}", name, rev)


def quiet(func, *args, **kwargs):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        value = func(*args, **kwargs)
    return value, out.getvalue() + err.getvalue()


class HelperTests(unittest.TestCase):
    def test_bounded_truncates_with_count(self) -> None:
        self.assertEqual(promote.bounded(["a", "b"], 2), ["a", "b"])
        self.assertEqual(
            promote.bounded(["a", "b", "c"], 2), ["a", "b", "... and 1 more"]
        )

    def test_reviewed_tags_orders_and_ignores_malformed(self) -> None:
        names = [
            "reviewed-20261008-10",
            "reviewed-20261008-2",
            "reviewed-20250101-1",
            "reviewed-20261008-0",
            "reviewed-2026108-1",
            "reviewed-20261008-x",
            "other",
        ]
        self.assertEqual(
            promote.reviewed_tags(names),
            ["reviewed-20250101-1", "reviewed-20261008-2", "reviewed-20261008-10"],
        )

    def test_next_tag_name(self) -> None:
        self.assertEqual(promote.next_tag_name([], "20261008"), "reviewed-20261008-1")
        self.assertEqual(
            promote.next_tag_name(
                [
                    "reviewed-20261008-1",
                    "reviewed-20261008-3",
                    "reviewed-20261009-7",
                    "junk",
                ],
                "20261008",
            ),
            "reviewed-20261008-4",
        )
        with self.assertRaisesRegex(promote.PromotionError, "YYYYMMDD"):
            promote.next_tag_name([], "2026-10-08")

    def test_run_reports_missing_binary_and_failure(self) -> None:
        with self.assertRaisesRegex(promote.PromotionError, "cannot run"):
            promote.run(["/nonexistent/binary"], cwd=Path("/"))
        with self.assertRaisesRegex(promote.PromotionError, "false failed: exit 1"):
            promote.run(["false"], cwd=Path("/"))
        self.assertEqual(
            promote.run(["false"], cwd=Path("/"), check=False).returncode, 1
        )

    def test_parse_args_rejects_runs_out_of_range(self) -> None:
        self.assertEqual(promote.parse_args(["--runs", "1"]).runs, 1)
        self.assertEqual(
            promote.parse_args(["--runs", str(promote.MAX_RUNS)]).command, "check"
        )
        for bad in ("0", str(promote.MAX_RUNS + 1)):
            with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                promote.parse_args(["--runs", bad])


class ControlTests(unittest.TestCase):
    def test_complete_controls_pass(self) -> None:
        with fixture() as fx:
            self.assertIsNone(
                promote.control_problem(
                    fx.repo, PurePosixPath("rules/python/security/py-one.yml")
                )
            )

    def test_each_missing_control_is_withheld(self) -> None:
        cases = {
            "": "no fixture",
            "- just a list\n": "not a mapping",
            "id: other\nvalid: ['x']\ninvalid: ['f()']\n": "does not match",
            "id: py-x\ninvalid: ['f()']\n": "lacks valid cases",
            "id: py-x\nvalid: ['x']\ninvalid: []\n": "lacks invalid cases",
            "id: py-x\nvalid: ['  ']\ninvalid: 'f()'\n": "lacks valid and invalid",
            "id: py-x\nvalid: [x\n": "unreadable YAML",
        }
        for text, reason in cases.items():
            with self.subTest(reason=reason), fixture() as fx:
                fx.rule("py-x", controls=text)
                problem = promote.control_problem(
                    fx.repo, PurePosixPath("rules/python/security/py-x.yml")
                )
                self.assertIn(reason, problem or "")

    def test_rule_without_id_and_duplicates_fail(self) -> None:
        with fixture() as fx:
            fx.write("rules/python/security/bad.yml", "language: python\n")
            fx.write(
                "tests/python/security/bad.yml", "id: bad\nvalid: [x]\ninvalid: [y]\n"
            )
            self.assertIn(
                "no string id",
                promote.control_problem(  # type: ignore[arg-type]
                    fx.repo, PurePosixPath("rules/python/security/bad.yml")
                ),
            )
            with self.assertRaisesRegex(promote.PromotionError, "no string id"):
                promote.rule_ids(fx.repo)
        with fixture() as fx:
            fx.write("rules/python/correctness/py-one.yml", "id: py-one\n")
            with self.assertRaisesRegex(
                promote.PromotionError, "duplicate rule ids: py-one"
            ):
                promote.rule_ids(fx.repo)


class EngineAndCorpusTests(unittest.TestCase):
    def test_pinned_engine_version(self) -> None:
        with fixture() as fx:
            self.assertEqual(promote.pinned_engine_version(fx.repo), "0.45.3")
            fx.write(
                "package.json",
                json.dumps({"devDependencies": {"@ast-grep/cli": "^0.45.3"}}),
            )
            with self.assertRaisesRegex(promote.PromotionError, "not exact"):
                promote.pinned_engine_version(fx.repo)
            fx.write("package.json", "{}")
            with self.assertRaisesRegex(promote.PromotionError, "no @ast-grep/cli pin"):
                promote.pinned_engine_version(fx.repo)

    def test_find_engine_prefers_explicit_then_local_then_path(self) -> None:
        with fixture() as fx:
            self.assertEqual(promote.find_engine(fx.repo, str(fx.engine)), fx.engine)
            cwd = os.getcwd()
            os.chdir(fx.base)
            try:
                self.assertEqual(promote.find_engine(fx.repo, "ast-grep"), fx.engine)
            finally:
                os.chdir(cwd)
            with self.assertRaisesRegex(promote.PromotionError, "not executable"):
                promote.find_engine(fx.repo, str(fx.base / "missing"))
            with (
                patch.object(promote.shutil, "which", return_value=None),
                self.assertRaisesRegex(promote.PromotionError, "npm ci"),
            ):
                promote.find_engine(fx.repo, None)
            with patch.object(promote.shutil, "which", return_value=str(fx.engine)):
                self.assertEqual(promote.find_engine(fx.repo, None), fx.engine)
            local = fx.repo / "node_modules/.bin/ast-grep"
            local.parent.mkdir(parents=True)
            shutil.copy(fx.engine, local)
            self.assertEqual(promote.find_engine(fx.repo, None), local)

    def test_engine_version_requires_a_version(self) -> None:
        with fixture() as fx:
            self.assertEqual(promote.engine_version(fx.engine, fx.repo), "0.45.3")
            fx.set(version="")
            with self.assertRaisesRegex(promote.PromotionError, "no version"):
                promote.engine_version(fx.engine, fx.repo)

    def test_corpus_digest_pins_content(self) -> None:
        with fixture() as fx:
            digest, files = promote.corpus_digest(fx.repo)
            self.assertEqual(files, 1)
            self.assertEqual(promote.corpus_digest(fx.repo)[0], digest)
            fx.write("ci/corpus/sample.py", "print('changed')\n")
            self.assertNotEqual(promote.corpus_digest(fx.repo)[0], digest)
            (fx.repo / "ci/corpus/link.py").symlink_to(fx.repo / "package.json")
            with self.assertRaisesRegex(promote.PromotionError, "symlink"):
                promote.corpus_digest(fx.repo)
            shutil.rmtree(fx.repo / "ci/corpus")
            (fx.repo / "ci/corpus").mkdir()
            with self.assertRaisesRegex(promote.PromotionError, "empty"):
                promote.corpus_digest(fx.repo)
            shutil.rmtree(fx.repo / "ci/corpus")
            with self.assertRaisesRegex(promote.PromotionError, "missing"):
                promote.corpus_digest(fx.repo)

    def test_scan_counts_and_rejects_bad_output(self) -> None:
        with fixture() as fx:
            counts, _ = promote.scan_once(fx.engine, fx.repo)
            self.assertEqual(dict(counts), {"py-one": 1})
            fx.set(scan_rc=0, scan=[])
            self.assertEqual(dict(promote.scan_once(fx.engine, fx.repo)[0]), {})
            fx.set(scan_rc=2)
            with self.assertRaisesRegex(promote.PromotionError, "corpus scan failed"):
                promote.scan_once(fx.engine, fx.repo)
            fx.set(scan_rc=0, scan=["{not json"])
            with self.assertRaisesRegex(promote.PromotionError, "malformed JSON"):
                promote.scan_once(fx.engine, fx.repo)

    def test_timed_scan_rejects_nondeterministic_counts(self) -> None:
        with fixture() as fx:
            scan = promote.timed_scan(fx.engine, fx.repo, 3)
            self.assertEqual((scan.counts, len(scan.timings)), ({"py-one": 1}, 3))
            fx.set(vary=True)
            with self.assertRaisesRegex(promote.PromotionError, "nondeterministic"):
                promote.timed_scan(fx.engine, fx.repo, 2)


class BaselineTests(unittest.TestCase):
    def test_round_trip_and_preserved_tolerances(self) -> None:
        with fixture() as fx:
            data = fx.baseline(tolerance_ratio=0.1)
            loaded = promote.load_baseline(fx.repo)
            self.assertEqual(loaded, data)
            self.assertEqual(loaded["fp"]["rules"], ["py-one"])
            self.assertEqual(loaded["fp"]["counts"], {"py-one": 1})
            loaded["fp"]["acknowledged"] = {"py-two": 3}
            rebuilt = promote.build_baseline(fx.repo, fx.engine, 1, loaded)
            self.assertEqual(rebuilt["perf"]["tolerance_ratio"], 0.1)
            self.assertEqual(rebuilt["fp"]["acknowledged"], {})

    def test_malformed_baselines_are_rejected(self) -> None:
        def mutate(path: str, value: object):
            def apply(data: dict) -> None:
                *parents, last = path.split(".")
                for key in parents:
                    data = data[key]
                if value is KeyError:
                    del data[last]
                else:
                    data[last] = value

            return apply

        cases = [
            (mutate("schema", 2), "schema must be 1"),
            (mutate("perf", KeyError), "lacks perf"),
            (mutate("engine", 1), "engine must be a string"),
            (mutate("corpus", "x"), "corpus.digest"),
            (mutate("fp", []), "perf and fp must be objects"),
            (mutate("perf.median_seconds", -1), "perf.median_seconds"),
            (mutate("perf.tolerance_ratio", True), "perf.tolerance_ratio"),
            (mutate("perf.tolerance_ratio", float("nan")), "perf.tolerance_ratio"),
            (mutate("perf.tolerance_seconds", float("inf")), "perf.tolerance_seconds"),
            (mutate("perf.runs", 1.5), "perf.runs"),
            (mutate("fp.new_rule_threshold", "0"), "new_rule_threshold"),
            (mutate("fp.counts", []), "fp.counts must be an object"),
            (mutate("fp.acknowledged", {"r": -2}), "fp.acknowledged.r"),
            (mutate("fp.rules", [1]), "fp.rules"),
        ]
        with fixture() as fx:
            good = fx.baseline()
            path = fx.repo / promote.BASELINE
            for apply, reason in cases:
                with self.subTest(reason=reason):
                    data = json.loads(json.dumps(good))
                    apply(data)
                    path.write_text(json.dumps(data))
                    with self.assertRaisesRegex(promote.PromotionError, reason):
                        promote.load_baseline(fx.repo)
            path.write_text("[]")
            with self.assertRaisesRegex(promote.PromotionError, "schema"):
                promote.load_baseline(fx.repo)
            path.write_text("{oops")
            with self.assertRaisesRegex(promote.PromotionError, "unreadable"):
                promote.load_baseline(fx.repo)
            path.unlink()
            with self.assertRaisesRegex(promote.PromotionError, "baseline missing"):
                promote.load_baseline(fx.repo)


def base_doc(**fp: object) -> dict:
    doc: dict[str, dict[str, object]] = {
        "perf": {
            "median_seconds": 1.0,
            "tolerance_ratio": 0.5,
            "tolerance_seconds": 0.25,
        },
        "fp": {
            "rules": ["old"],
            "counts": {"old": 2},
            "acknowledged": {},
            "new_rule_threshold": 0,
        },
    }
    doc["fp"].update(fp)
    return doc


class CompareTests(unittest.TestCase):
    def test_findings_within_baseline_pass(self) -> None:
        report = promote.Report()
        promote.compare_findings(base_doc(), {"old": 2}, report)
        self.assertTrue(report.ok)
        self.assertEqual(report.summary["corpus_findings"], 2)

    def test_new_rule_findings_block_unless_acknowledged(self) -> None:
        report = promote.Report()
        promote.compare_findings(base_doc(), {"new": 1, "old": 3}, report)
        self.assertFalse(report.ok)
        text = "\n".join(report.failures)
        self.assertIn("new: 1 finding(s) (new rule, threshold 0)", text)
        self.assertIn("old: 3 finding(s) (was 2, threshold 0)", text)

        report = promote.Report()
        promote.compare_findings(
            base_doc(acknowledged={"new": 1, "old": 3}), {"new": 1, "old": 3}, report
        )
        self.assertTrue(report.ok, report.failures)
        self.assertIn("acknowledged up to 1", "\n".join(report.notes))

        report = promote.Report()
        promote.compare_findings(base_doc(acknowledged={"new": 1}), {"new": 2}, report)
        self.assertFalse(report.ok)

    def test_threshold_boundary(self) -> None:
        report = promote.Report()
        promote.compare_findings(
            base_doc(new_rule_threshold=2), {"new": 2, "old": 4}, report
        )
        self.assertTrue(report.ok)
        promote.compare_findings(base_doc(new_rule_threshold=2), {"new": 3}, report)
        self.assertFalse(report.ok)

    def test_perf_tolerance_boundary(self) -> None:
        limit = 1.0 * 1.5 + 0.25
        report = promote.Report()
        promote.compare_perf(base_doc(), promote.Scan({}, limit, [limit]), report)
        self.assertTrue(report.ok)
        promote.compare_perf(
            base_doc(), promote.Scan({}, limit + 0.001, [limit]), report
        )
        self.assertIn("corpus scan regressed", report.failures[0])


class CheckTests(unittest.TestCase):
    def ready(self, fx: Fixture) -> None:
        fx.baseline()
        fx.init_git()

    def test_clean_pack_passes_and_reports(self) -> None:
        with fixture() as fx:
            self.ready(fx)
            report = promote.run_checks(fx.repo, fx.repo, fx.engine, None, 1)
            self.assertTrue(report.ok, report.failures)
            self.assertEqual(report.summary["promoted_rules"], 1)
            self.assertEqual(report.summary["previous_tag"], "none")
            code, out = quiet(
                promote.main,
                [
                    "check",
                    "--repo",
                    str(fx.repo),
                    "--engine",
                    str(fx.engine),
                    "--runs",
                    "1",
                ],
            )
            self.assertEqual(code, 0, out)
            self.assertIn("promotion check: PASS", out)
            code, out = quiet(
                promote.main,
                [
                    "--repo",
                    str(fx.repo),
                    "--engine",
                    str(fx.engine),
                    "--runs",
                    "1",
                    "--rev",
                    "HEAD",
                ],
            )
            self.assertEqual(code, 0, out)

    def test_failing_rule_tests_block(self) -> None:
        for values, reason in (
            ({"test_rc": 1, "test_out": "FAIL py-one"}, "ast-grep test failed"),
            ({"test_out": "no summary line"}, "ast-grep test failed"),
            (
                {"test_out": "test result: ok. 0 passed; 0 failed;"},
                "ast-grep test failed",
            ),
        ):
            with self.subTest(reason=values), fixture() as fx:
                self.ready(fx)
                fx.set(**values)
                report = promote.run_checks(fx.repo, fx.repo, fx.engine, None, 1)
                self.assertIn(reason, report.failures[0])

    def test_failing_unit_tests_block(self) -> None:
        with fixture() as fx:
            self.ready(fx)
            fx.write(
                "ci/tests/test_bad.py",
                "import unittest\n"
                "class T(unittest.TestCase):\n    def test(self): self.fail('x')\n",
            )
            report = promote.run_checks(fx.repo, fx.repo, fx.engine, None, 1)
            self.assertTrue(any("ci/tests failed" in line for line in report.failures))

    def test_rule_without_controls_is_withheld_since_previous_tag(self) -> None:
        with fixture() as fx:
            self.ready(fx)
            signed_tag(fx.repo, "reviewed-20261001-1")
            sh(fx.repo, "git", "tag", "reviewed-20261001-2")  # lightweight: ignored
            fx.rule("py-two", controls="id: py-two\nvalid: ['x']\n")
            fx.rule("py-three", controls="")
            fx.write("rules/python/security/notes.txt", "ignored")
            fx.baseline()
            report = promote.run_checks(fx.repo, fx.repo, fx.engine, None, 1)
            self.assertEqual(report.summary["previous_tag"], "reviewed-20261001-1")
            self.assertIn("  reviewed-20261001-2", report.notes)
            withheld = [line for line in report.failures if "withheld" in line]
            self.assertEqual(len(withheld), 3, report.failures)
            self.assertIn("py-three.yml: no fixture", withheld[1])
            self.assertIn("py-two.yml: fixture lacks invalid", withheld[2])
            code, out = quiet(
                promote.main,
                ["--repo", str(fx.repo), "--engine", str(fx.engine), "--runs", "1"],
            )
            self.assertEqual(code, 1)
            self.assertIn("FAIL 2 rule(s) withheld", out)
            self.assertIn("promotion check: FAIL", out)

    def test_unverified_tags_never_bound_the_review(self) -> None:
        with fixture() as fx:
            self.ready(fx)
            sh(fx.repo, "git", "tag", "reviewed-20261001-1")
            sh(fx.repo, "git", "tag", "-a", "-m", "unsigned", "reviewed-20261001-2")
            self.assertEqual(
                promote.previous_tag(fx.repo, "HEAD"),
                (None, ["reviewed-20261001-2", "reviewed-20261001-1"]),
            )
            report = promote.run_checks(fx.repo, fx.repo, fx.engine, None, 1)
            self.assertEqual(report.summary["previous_tag"], "none")
            self.assertEqual(report.summary["promoted_rules"], 1)

    def test_changed_rule_and_fixture_selection(self) -> None:
        with fixture() as fx:
            self.ready(fx)
            fx.rule("py-two")
            fx.commit("add py-two")
            signed_tag(fx.repo, "reviewed-20261001-1")
            tag = "reviewed-20261001-1"
            self.assertEqual(promote.changed_rules(fx.repo, fx.repo, "HEAD", tag), [])
            fx.write("tests/__snapshots__/py-one-snapshot.yml", "id: py-one\n")
            fx.write("tests/python/security/README.md", "notes\n")
            fx.write("tests/python/security/py-one.yml", "id: py-one\nvalid: ['x']\n")
            sh(fx.repo, "git", "rm", "-q", "tests/python/security/py-two.yml")
            fx.rule("py-new", controls="")
            fx.rule("py-caf\u00e9", controls="")
            fx.write("tests/python/security/orphan.yml", "id: orphan\n")
            rules = "rules/python/security/"
            self.assertEqual(
                [str(p) for p in promote.changed_rules(fx.repo, fx.repo, None, tag)],
                [
                    rules + "py-caf\u00e9.yml",
                    rules + "py-new.yml",
                    rules + "py-one.yml",
                    rules + "py-two.yml",
                ],
            )
            report = promote.Report()
            promote.gate_controls(fx.repo, fx.repo, None, report)
            self.assertIn(
                "  withheld rules/python/security/py-two.yml: no fixture "
                "at tests/python/security/py-two.yml",
                report.failures,
            )
            fx.commit("edit fixtures")
            sh(fx.repo, "git", "rm", "-q", "rules/python/security/py-one.yml")
            self.assertEqual(
                [str(p) for p in promote.changed_rules(fx.repo, fx.repo, "HEAD", tag)],
                # py-one is gone from the tree the check reads
                [
                    rules + "py-caf\u00e9.yml",
                    rules + "py-new.yml",
                    rules + "py-two.yml",
                ],
            )

    def test_corpus_gates_block(self) -> None:
        cases = [
            (lambda fx: fx.set(version="0.45.4"), "engine 0.45.4 differs"),
            (
                lambda fx: fx.write("ci/corpus/sample.py", "x = 1\n"),
                "pinned corpus changed",
            ),
            (
                lambda fx: fx.set(scan=["py-one", "py-one"]),
                "exceed the corpus finding baseline",
            ),
            (lambda fx: fx.set(sleep=0.6), "corpus scan regressed"),
        ]
        for breaker, reason in cases:
            with self.subTest(reason=reason), fixture() as fx:
                self.ready(fx)
                breaker(fx)
                report = promote.run_checks(fx.repo, fx.repo, fx.engine, None, 1)
                self.assertTrue(
                    any(reason in line for line in report.failures), report.failures
                )

    def test_acknowledged_findings_pass_and_are_reported(self) -> None:
        with fixture() as fx:
            self.ready(fx)
            data = promote.load_baseline(fx.repo)
            data["fp"]["acknowledged"] = {"py-one": 2}
            promote.write_baseline(fx.repo, data)
            fx.set(scan=["py-one", "py-one"])
            code, out = quiet(
                promote.main,
                ["--repo", str(fx.repo), "--engine", str(fx.engine), "--runs", "1"],
            )
            self.assertEqual(code, 0, out)
            self.assertIn(
                "py-one: 2 finding(s) (was 1, threshold 0), acknowledged up to 2", out
            )

    def test_baseline_refuses_an_unpinned_engine(self) -> None:
        with fixture() as fx:
            fx.set(version="0.45.4")
            code, out = quiet(
                promote.main,
                ["baseline", "--repo", str(fx.repo), "--engine", str(fx.engine)],
            )
            self.assertEqual(code, 2)
            self.assertIn("engine 0.45.4 differs from package.json pin 0.45.3", out)
            self.assertFalse((fx.repo / promote.BASELINE).exists())

    def test_baseline_command_writes_and_preserves(self) -> None:
        with fixture() as fx:
            argv = [
                "baseline",
                "--repo",
                str(fx.repo),
                "--engine",
                str(fx.engine),
                "--runs",
                "1",
            ]
            code, out = quiet(promote.main, argv)
            self.assertEqual(code, 0, out)
            self.assertIn("1 rules, 1 corpus findings", out)
            data = json.loads((fx.repo / promote.BASELINE).read_text())
            data["perf"]["tolerance_seconds"] = 9
            (fx.repo / promote.BASELINE).write_text(json.dumps(data))
            self.assertEqual(quiet(promote.main, argv)[0], 0)
            self.assertEqual(
                promote.load_baseline(fx.repo)["perf"]["tolerance_seconds"], 9
            )

    def test_main_reports_errors_with_exit_2(self) -> None:
        with fixture() as fx:
            code, out = quiet(
                promote.main,
                ["--repo", str(fx.repo), "--engine", str(fx.base / "none")],
            )
            self.assertEqual(code, 2)
            self.assertIn("FAIL ast-grep engine not executable", out)

    def test_export_reports_archive_failure(self) -> None:
        with fixture() as fx:
            self.ready(fx)
            real = subprocess.run

            def archive_fails(argv, *args, **kwargs):
                if argv[:2] == ["git", "archive"]:
                    raise OSError("boom")
                return real(argv, *args, **kwargs)  # pylint: disable=subprocess-run-check

            with (
                patch.object(promote.subprocess, "run", side_effect=archive_fails),
                self.assertRaisesRegex(promote.PromotionError, "git archive"),
                promote.exported(fx.repo, "HEAD"),
            ):
                pass  # pragma: no cover


class TagTests(unittest.TestCase):
    def ready(self, fx: Fixture) -> None:
        fx.baseline()
        fx.init_git()

    def tag(self, fx: Fixture, date: str = "20261008") -> tuple[int, str]:
        return quiet(
            promote.main,
            [
                "tag",
                "--repo",
                str(fx.repo),
                "--engine",
                str(fx.engine),
                "--runs",
                "1",
                "--date",
                date,
            ],
        )

    def test_creates_signed_annotated_tag_without_pushing(self) -> None:
        with fixture() as fx:
            self.ready(fx)
            sh(
                fx.origin,
                "git",
                "-c",
                "tag.gpgsign=false",
                "tag",
                "reviewed-20261008-1",
                "main",
            )
            fx.write("ci/tests/__init__.py", "")
            fx.commit("second")
            code, out = self.tag(fx)
            self.assertEqual(code, 0, out)
            self.assertIn(
                "push with: git push origin refs/tags/reviewed-20261008-2", out
            )
            self.assertEqual(
                sh(fx.repo, "git", "cat-file", "-t", "reviewed-20261008-2").strip(),
                "tag",
            )
            body = sh(fx.repo, "git", "cat-file", "tag", "reviewed-20261008-2")
            self.assertIn("SSH SIGNATURE", body)
            self.assertIn("corpus_findings: 1", body)
            self.assertIn("scan_median_seconds:", body)
            self.assertEqual(sh(fx.origin, "git", "tag", "-l"), "reviewed-20261008-1\n")
            code, out = self.tag(fx)
            self.assertEqual(code, 2)
            self.assertIn("already carries reviewed-20261008-2", out)

    def test_remote_moving_during_check_blocks(self) -> None:
        with fixture() as fx:
            self.ready(fx)
            real = promote.run_checks

            def push_meanwhile(*args, **kwargs):
                report = real(*args, **kwargs)
                fx.write("ci/tests/__init__.py", "")
                sh(fx.repo, "git", "add", "-A")
                sh(fx.repo, "git", "commit", "-q", "-m", "concurrent")
                sh(fx.repo, "git", "push", "-q", "origin", "HEAD:refs/heads/main")
                sh(fx.repo, "git", "reset", "-q", "--hard", "HEAD~1")
                return report

            with patch.object(promote, "run_checks", side_effect=push_meanwhile):
                code, out = self.tag(fx)
            self.assertEqual(code, 2)
            self.assertIn("is not origin/main", out)
            self.assertEqual(sh(fx.repo, "git", "tag", "-l"), "")

    def test_remote_reviewed_tag_on_head_blocks(self) -> None:
        with fixture() as fx:
            self.ready(fx)
            sh(
                fx.origin,
                "git",
                "-c",
                "user.name=T",
                "-c",
                "user.email=t@e.invalid",
                "-c",
                "tag.gpgsign=false",
                "tag",
                "-a",
                "-m",
                "r",
                "reviewed-20261007-3",
                "main",
            )
            self.assertEqual(
                list(promote.remote_tags(fx.repo, "origin")), ["reviewed-20261007-3"]
            )
            code, out = self.tag(fx)
            self.assertEqual(code, 2)
            self.assertIn("already carries reviewed-20261007-3", out)

    def test_unverifiable_signature_removes_the_new_tag(self) -> None:
        with fixture() as fx:
            self.ready(fx)
            (fx.base / "allowed").write_text("")
            code, out = self.tag(fx)
            self.assertEqual(code, 2)
            self.assertIn(
                "signature of reviewed-20261008-1 does not verify; tag removed", out
            )
            self.assertEqual(sh(fx.repo, "git", "tag", "-l"), "")

    def test_preconditions_block_tagging(self) -> None:
        with fixture() as fx:
            self.ready(fx)
            fx.write("ci/corpus/sample.py", "dirty\n")
            code, out = self.tag(fx)
            self.assertEqual(code, 2)
            self.assertIn("not clean", out)
            fx.commit("ahead", push=False)
            code, out = self.tag(fx)
            self.assertIn("is not origin/main", out)
            sh(fx.repo, "git", "push", "-q", "origin", "HEAD:refs/heads/main")
            code, out = self.tag(fx)
            self.assertEqual(code, 2)
            self.assertIn("pinned corpus changed", out)
            self.assertIn("check failed; no tag created", out)
            self.assertEqual(sh(fx.repo, "git", "tag", "-l"), "")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
