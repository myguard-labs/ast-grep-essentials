import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path, PurePosixPath
from unittest.mock import patch

CI_ROOT = Path(__file__).resolve().parents[1]
if str(CI_ROOT) not in sys.path:
    sys.path.insert(0, str(CI_ROOT))

# pylint: disable=protected-access,wrong-import-position
import validate_changed_rules as gate


class ValidateChangedRulesTests(unittest.TestCase):
    def make_pair(self, root: Path, rule_id: str = "py-one") -> tuple[Path, Path]:
        rule = root / f"rules/python/security/{rule_id}.yml"
        fixture = root / f"tests/python/security/{rule_id}.yml"
        rule.parent.mkdir(parents=True, exist_ok=True)
        fixture.parent.mkdir(parents=True, exist_ok=True)
        rule.write_text(f"id: {rule_id}\nlanguage: python\nrule: {{kind: call}}\n")
        fixture.write_text(f"id: {rule_id}\nvalid: [x]\ninvalid: [f()]\n")
        return rule, fixture

    def make_engine(self, root: Path, output: str, exit_code: int = 0) -> Path:
        engine = root / "ast-grep"
        engine.write_text(f"#!/bin/sh\nprintf '%s\\n' '{output}'\nexit {exit_code}\n")
        engine.chmod(0o755)
        return engine

    def test_changed_rule_requires_changed_mirrored_fixture(self) -> None:
        paths = [
            "rules/python/security/py-one.yml",
            "tests/python/security/py-one.yml",
            "rules/go/correctness/go-two.yml",
        ]
        self.assertEqual(
            gate.missing_fixture_changes(paths),
            ["tests/go/correctness/go-two.yml"],
        )

    def commit_base(self, root: Path) -> str:
        environment = {
            **os.environ,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
        }
        for command in (
            ["git", "init", "-q"],
            ["git", "add", "-A"],
            [
                "git",
                "-c",
                "user.name=ci",
                "-c",
                "user.email=ci@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "-m",
                "base",
            ],
        ):
            subprocess.run(command, cwd=root, env=environment, check=True)
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def header_rule(self, root: Path, header: str, body: str) -> tuple[Path, str]:
        rule, _ = self.make_pair(root)
        rule.write_text(header + body)
        return rule, "rules/python/security/py-one.yml"

    def test_banner_only_change_needs_no_fixture_change(self) -> None:
        body = "id: py-one\nlanguage: python\nrule: {kind: call}\n"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            rule, path = self.header_rule(root, "# old\n# Last touched: x\n\n", body)
            base = self.commit_base(root)
            rule.write_text("# new\n\n" + body)

            exempt = gate.header_only_rule_changes(root, base, [path])
            engine = self.make_engine(root, "test result: ok. 1 passed; 0 failed;")
            with redirect_stdout(io.StringIO()):
                count = gate.validate_changed(root, engine, [path], base)

        self.assertEqual(exempt, frozenset({path}))
        self.assertEqual(gate.missing_fixture_changes([path], exempt), [])
        self.assertEqual(count, 1)

    def test_body_change_still_needs_a_fixture_change(self) -> None:
        body = "id: py-one\nlanguage: python\nrule: {kind: call}\n"
        changes = {
            "matcher": "# b\n" + body.replace("call", "call_expression"),
            "comment inside a block scalar": (
                "# b\n" + body + "note: |\n  # changed\n"
            ),
            "comment below the first key": "# b\nid: py-one\n# moved\n" + body[11:],
            "banner emptied the rule": "# b\n",
        }
        for label, text in changes.items():
            with self.subTest(label), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                rule, path = self.header_rule(root, "# a\n", body + "note: |\n  # x\n")
                if label != "comment inside a block scalar":
                    rule.write_text("# a\n" + body)
                base = self.commit_base(root)
                rule.write_text(text)

                exempt = gate.header_only_rule_changes(root, base, [path])
                engine = self.make_engine(root, "test result: ok. 1 passed; 0 failed;")
                with self.assertRaisesRegex(gate.ValidationError, "mirrored fixtures"):
                    gate.validate_changed(root, engine, [path], base)

                self.assertEqual(exempt, frozenset())

    def test_added_rule_is_never_exempt(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "README").write_text("x\n")
            base = self.commit_base(root)
            _, path = self.header_rule(root, "# a\n", "id: py-one\n")

            self.assertEqual(
                gate.header_only_rule_changes(root, base, [path]), frozenset()
            )

    def test_unknown_base_is_never_exempt(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            rule, path = self.header_rule(root, "# a\n", "id: py-one\n")
            base = self.commit_base(root)
            rule.write_text("# b\nid: py-one\n")

            self.assertEqual(
                gate.header_only_rule_changes(root, base, [path]), frozenset({path})
            )
            for unknown in ("0" * 40, "--output=/tmp/x"):
                with self.subTest(unknown):
                    self.assertEqual(
                        gate.header_only_rule_changes(root, unknown, [path]),
                        frozenset(),
                    )

    def test_banner_detection_follows_yaml_bytes(self) -> None:
        body = b"id: py-one\nlanguage: python\nrule: {kind: call}\n"
        cases = {
            "indented comment": (b"  # b\n\t# c\n" + body, True),
            "crlf banner": (b"# b\r\n\r\n" + body, True),
            "no-break space before #": (b"\xc2\xa0#x: 1\n" + body, False),
            "ideographic space before #": (b"\xe3\x80\x80#x\n" + body, False),
            "byte order mark": (b"\xef\xbb\xbf# b\n" + body, False),
            "yaml directive": (b"%YAML 1.2\n---\n" + body, False),
            "document marker": (b"# b\n---\n" + body, False),
            "crlf body": (b"# b\n" + body.replace(b"\n", b"\r\n"), False),
            "cr-only body": (b"# b\n" + body.replace(b"\n", b"\r"), False),
            "non-utf-8 banner": (b"# \xff\n" + body, True),
            "non-utf-8 body": (b"# b\n" + body + b"note: \xff\n", False),
        }
        for label, (candidate, expected) in cases.items():
            with self.subTest(label), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                rule, path = self.header_rule(root, "# a\n", body.decode())
                base = self.commit_base(root)
                rule.write_bytes(candidate)

                self.assertEqual(
                    gate.header_only_rule_changes(root, base, [path]),
                    frozenset({path}) if expected else frozenset(),
                )

    def test_non_utf_8_base_is_compared_without_decoding(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            rule, path = self.header_rule(root, "", "")
            rule.write_bytes(b"# \xff\nid: py-one\n")
            base = self.commit_base(root)
            rule.write_bytes(b"# fixed\nid: py-one\n")

            self.assertEqual(
                gate.header_only_rule_changes(root, base, [path]), frozenset({path})
            )

    def test_symlinked_banner_candidate_is_rejected(self) -> None:
        with (
            tempfile.TemporaryDirectory() as name,
            tempfile.TemporaryDirectory() as out,
        ):
            root = Path(name)
            rule, path = self.header_rule(root, "# a\n", "id: py-one\n")
            base = self.commit_base(root)
            outside = Path(out) / "rule.yml"
            outside.write_text("# b\nid: py-one\n")
            rule.unlink()
            rule.symlink_to(outside)

            with self.assertRaisesRegex(gate.ValidationError, "regular file"):
                gate.header_only_rule_changes(root, base, [path])

    def test_without_a_base_no_rule_is_exempt(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            _, path = self.header_rule(root, "# a\n", "id: py-one\n")
            engine = self.make_engine(root, "test result: ok. 1 passed; 0 failed;")
            with self.assertRaisesRegex(gate.ValidationError, "mirrored fixtures"):
                gate.validate_changed(root, engine, [path])

    def test_only_supported_rule_languages_enter_the_gate(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            first, _ = self.make_pair(root)
            second, _ = self.make_pair(root, "py-two")
            self.assertEqual(
                gate.changed_rule_paths(
                    root,
                    [
                        "rules/python/security/py-one.yml",
                        "tests/python/security/py-one.yml",
                        "tests/__snapshots__/py-two-snapshot.yml",
                        "README.md",
                    ],
                ),
                [
                    PurePosixPath(first.relative_to(root).as_posix()),
                    PurePosixPath(second.relative_to(root).as_posix()),
                ],
            )
        with self.assertRaisesRegex(gate.ValidationError, "unsupported rule language"):
            gate.changed_rule_paths(Path.cwd(), ["rules/unknown/security/x.yml"])

    def test_isolated_fixture_is_executed(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            rule, _ = self.make_pair(root)
            engine = self.make_engine(root, "test result: ok. 1 passed; 0 failed;")
            gate.validate_rule(root, engine, rule)

    def test_engine_error_is_not_a_pass(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            rule, _ = self.make_pair(root)
            engine = self.make_engine(root, "rule parse error", 2)
            with self.assertRaisesRegex(gate.ValidationError, "rule parse error"):
                gate.validate_rule(root, engine, rule)

    def test_zero_executed_fixtures_is_not_a_pass(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            rule, _ = self.make_pair(root)
            engine = self.make_engine(root, "test result: ok. 0 passed; 0 failed;")
            with self.assertRaisesRegex(
                gate.ValidationError, "did not execute one fixture"
            ):
                gate.validate_rule(root, engine, rule)

    def test_eleven_executed_fixtures_does_not_spoof_one(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            rule, _ = self.make_pair(root)
            engine = self.make_engine(root, "test result: ok. 11 passed; 0 failed;")
            with self.assertRaisesRegex(
                gate.ValidationError, "did not execute one fixture"
            ):
                gate.validate_rule(root, engine, rule)

    def test_traversal_path_is_rejected(self) -> None:
        with self.assertRaisesRegex(gate.ValidationError, "repository-relative"):
            gate.changed_rule_paths(Path.cwd(), ["rules/python/../../outside.yml"])

    def test_changed_fixture_must_mirror_the_exact_rule_path(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.make_pair(root)
            misplaced = root / "tests/python/other/py-one.yml"
            misplaced.parent.mkdir(parents=True)
            misplaced.write_text("id: py-one\n")
            with self.assertRaisesRegex(gate.ValidationError, "does not mirror"):
                gate.changed_rule_paths(root, ["tests/python/other/py-one.yml"])

    def test_noncanonical_rule_and_fixture_paths_are_rejected(self) -> None:
        cases = [
            "rules/python/py-one.yml",
            "rules/python/security/extra/py-one.yml",
            "rules/python/security/py-one.yaml",
            "tests/python/py-one.yml",
        ]
        for path in cases:
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(gate.ValidationError, "unsupported"),
            ):
                gate.changed_rule_paths(Path.cwd(), [path])

    def test_changed_paths_uses_bounded_git_diff(self) -> None:
        result = subprocess.CompletedProcess([], 0, "rules/python/security/x.yml\n", "")
        with patch.object(gate, "_run", return_value=result) as run:
            self.assertEqual(
                gate.changed_paths(Path("/repo"), "base"),
                ["rules/python/security/x.yml"],
            )
        self.assertIn("--diff-filter=ACMRD", run.call_args.args[0])
        self.assertEqual(run.call_args.kwargs["timeout"], 30)

    def test_process_failure_and_timeout_are_bounded_errors(self) -> None:
        failed = subprocess.CompletedProcess([], 2, "", "broken")
        with (
            patch("validate_changed_rules.subprocess.run", return_value=failed),
            self.assertRaisesRegex(gate.ValidationError, "broken"),
        ):
            gate._run(["tool"], cwd=Path.cwd(), timeout=1)
        with (
            patch(
                "validate_changed_rules.subprocess.run",
                side_effect=subprocess.TimeoutExpired(["tool"], 1),
            ),
            self.assertRaisesRegex(gate.ValidationError, "cannot run tool"),
        ):
            gate._run(["tool"], cwd=Path.cwd(), timeout=1)

    def test_duplicate_rule_ids_and_missing_fixture_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            first, fixture = self.make_pair(root)
            duplicate = root / "rules/python/correctness/py-one.yml"
            duplicate.parent.mkdir(parents=True)
            duplicate.write_text(first.read_text())
            with self.assertRaisesRegex(gate.ValidationError, "multiple rule files"):
                gate.find_rule(root, "py-one")
            duplicate.unlink()
            fixture.unlink()
            engine = self.make_engine(root, "test result: ok. 1 passed; 0 failed;")
            with self.assertRaisesRegex(
                gate.ValidationError, "missing mirrored fixture"
            ):
                gate.validate_rule(root, engine, first)

    def test_unsupported_rule_layout_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            rule = root / "rules/python/too/deep/py-one.yml"
            rule.parent.mkdir(parents=True)
            rule.write_text("id: py-one\n")
            with self.assertRaisesRegex(
                gate.ValidationError, "unsupported rule layout"
            ):
                gate.validate_rule(root, Path("/engine"), rule)

    def test_snapshot_is_copied_into_isolated_fixture_run(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            rule, _ = self.make_pair(root)
            snapshot = root / "tests/__snapshots__/py-one-snapshot.yml"
            snapshot.parent.mkdir(parents=True)
            snapshot.write_text("snapshots: {}\n")
            result = subprocess.CompletedProcess(
                [], 0, "test result: ok. 1 passed; 0 failed;\n", ""
            )
            with patch.object(gate, "_run", return_value=result) as run:
                gate.validate_rule(root, Path("/engine"), rule)
            self.assertNotIn("--skip-snapshot-tests", run.call_args.args[0])

    def test_symlinked_fixture_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            root = base / "repo"
            rule, fixture = self.make_pair(root)
            outside = base / "outside.yml"
            outside.write_text(fixture.read_text())
            fixture.unlink()
            fixture.symlink_to(outside)
            with self.assertRaisesRegex(gate.ValidationError, "regular file"):
                gate.validate_rule(root, Path("/engine"), rule)

    def test_fixture_below_escaping_parent_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            root = base / "repo"
            rule, fixture = self.make_pair(root)
            contents = fixture.read_text()
            fixture.unlink()
            fixture.parent.rmdir()
            outside = base / "outside"
            outside.mkdir()
            (outside / fixture.name).write_text(contents)
            fixture.parent.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(gate.ValidationError, "escapes the checkout"):
                gate.validate_rule(root, Path("/engine"), rule)

    def test_validate_changed_handles_present_and_removed_rules(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.make_pair(root)
            engine = self.make_engine(root, "test result: ok. 1 passed; 0 failed;")
            paths = [
                "rules/python/security/py-one.yml",
                "tests/python/security/py-one.yml",
            ]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(gate.validate_changed(root, engine, paths), 1)
            removed = [
                "rules/python/security/py-gone.yml",
                "tests/python/security/py-gone.yml",
            ]
            self.assertEqual(gate.validate_changed(root, engine, removed), 0)
            with self.assertRaisesRegex(
                gate.ValidationError, "changed mirrored fixtures"
            ):
                gate.validate_changed(root, engine, [paths[0]])

    def test_latest_engine_installs_and_verifies_registry_version(self) -> None:
        calls: list[tuple[list[str], dict[str, object]]] = []

        def fake_run(
            command: Sequence[str | Path], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            rendered = [str(part) for part in command]
            calls.append((rendered, kwargs))
            if rendered[:2] == ["npm", "view"]:
                return subprocess.CompletedProcess(rendered, 0, "9.9.9\n", "")
            if rendered[:2] == ["npm", "install"]:
                prefix = Path(rendered[rendered.index("--prefix") + 1])
                package = prefix / "node_modules/@ast-grep/cli/package.json"
                package.parent.mkdir(parents=True)
                package.write_text(json.dumps({"version": "9.9.9"}))
                engine = prefix / "node_modules/.bin/ast-grep"
                engine.parent.mkdir(parents=True)
                engine.write_text("#!/bin/sh\n")
                engine.chmod(0o755)
                return subprocess.CompletedProcess(rendered, 0, "", "")
            raise AssertionError(rendered)

        with (
            tempfile.TemporaryDirectory() as name,
            patch.dict(
                os.environ,
                {"NPM_CONFIG_REGISTRY": "https://attacker.invalid/"},
            ),
            patch.object(gate, "_run", side_effect=fake_run),
            gate.latest_engine() as (engine, version),
        ):
            self.assertTrue(engine.is_file())
            self.assertEqual(version, "9.9.9")
        self.assertIn("@ast-grep/cli@9.9.9", calls[1][0])
        self.assertEqual(calls[0][1]["cwd"], calls[1][1]["cwd"])
        self.assertNotEqual(calls[0][1]["cwd"], Path(name))
        prefix_argument = calls[1][0].index("--prefix") + 1
        self.assertEqual(calls[1][1]["cwd"], Path(calls[1][0][prefix_argument]))
        for command, kwargs in calls:
            self.assertIn(f"--registry={gate.NPM_REGISTRY}", command)
            environment = kwargs["env"]
            self.assertIsInstance(environment, dict)
            assert isinstance(environment, dict)
            self.assertNotIn("NPM_CONFIG_REGISTRY", environment)
            self.assertEqual(environment["npm_config_registry"], gate.NPM_REGISTRY)
            self.assertNotEqual(
                environment["npm_config_globalconfig"],
                environment["npm_config_userconfig"],
            )

    def test_main_supports_explicit_engine_and_latest_modes(self) -> None:
        completed = subprocess.CompletedProcess([], 0, "ast-grep 1.2.3\n", "")
        with tempfile.TemporaryDirectory() as name:
            candidate = Path(name)
            with (
                patch.object(
                    sys,
                    "argv",
                    [
                        "gate",
                        "--root",
                        name,
                        "--engine",
                        "/bin/true",
                        "--base",
                        "base-sha",
                        "README.md",
                    ],
                ),
                patch.object(gate, "validate_changed", return_value=0) as validate,
                patch.object(gate, "_run", return_value=completed),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(gate.main(), 0)
            self.assertEqual(validate.call_args.args[0], candidate.resolve())
            self.assertEqual(validate.call_args.args[3], "base-sha")

        @contextmanager
        def fake_latest() -> Iterator[tuple[Path, str]]:
            yield Path("/bin/true"), "4.5.6"

        with (
            patch.object(sys, "argv", ["gate", "--base", "base-sha", "README.md"]),
            patch.object(gate, "validate_changed", return_value=0) as validate,
            patch.object(gate, "latest_engine", fake_latest),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(gate.main(), 0)
        self.assertEqual(validate.call_args.args[3], "base-sha")

    def test_main_reports_validation_error(self) -> None:
        with (
            patch.object(
                sys,
                "argv",
                ["gate", "--root", "/missing", "/bin/true", "README.md"],
            ),
            redirect_stderr(io.StringIO()) as stderr,
        ):
            self.assertEqual(gate.main(), 1)
        self.assertIn("checkout directory", stderr.getvalue())

        with (
            patch.object(sys, "argv", ["gate", "--engine", "/bin/true", "README.md"]),
            patch.object(
                gate,
                "validate_changed",
                side_effect=gate.ValidationError("bad rule"),
            ),
            redirect_stderr(io.StringIO()) as stderr,
        ):
            self.assertEqual(gate.main(), 1)
        self.assertIn("bad rule", stderr.getvalue())

        with (
            patch.object(sys, "argv", ["gate", "--engine", "/missing", "README.md"]),
            redirect_stderr(io.StringIO()) as stderr,
        ):
            self.assertEqual(gate.main(), 1)
        self.assertIn("executable file", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
