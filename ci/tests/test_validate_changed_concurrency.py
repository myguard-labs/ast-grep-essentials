import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

CI_ROOT = Path(__file__).resolve().parents[1]
if str(CI_ROOT) not in sys.path:
    sys.path.insert(0, str(CI_ROOT))

# pylint: disable=wrong-import-position
import validate_changed_rules as gate

PASS = "test result: ok. 1 passed; 0 failed;"


def make_pair(root: Path, rule_id: str) -> list[str]:
    paths = [
        f"rules/python/security/{rule_id}.yml",
        f"tests/python/security/{rule_id}.yml",
    ]
    for relative in paths:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"id: {rule_id}\nlanguage: python\nrule: {{kind: call}}\n")
    return paths


def make_engine(root: Path) -> Path:
    # Fails any isolated config whose rule id starts with "bad"; sleeps briefly
    # on early ids so concurrent completion order differs from input order.
    engine = root / "ast-grep"
    engine.write_text(
        "#!/bin/sh\n"
        'cfg="$4"; dir=$(dirname "$cfg")\n'
        'case "$(ls "$dir/rules")" in\n'
        "  a*) sleep 0.3;;\n"
        "esac\n"
        'case "$(ls "$dir/rules")" in\n'
        '  bad*) echo boom-$(ls "$dir/rules"); exit 1;;\n'
        "esac\n"
        f"printf '%s\\n' '{PASS}'\n"
    )
    engine.chmod(0o755)
    return engine


class ConcurrentValidationTests(unittest.TestCase):
    def run_gate(
        self, ids: list[str], workers: int | None
    ) -> tuple[str, str | None, int | None]:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            paths: list[str] = []
            for rule_id in ids:
                paths += make_pair(root, rule_id)
            engine = make_engine(root)
            out = io.StringIO()
            error = None
            count = None
            with redirect_stdout(out):
                try:
                    count = gate.validate_changed(root, engine, paths, workers=workers)
                except gate.ValidationError as raised:
                    error = str(raised).replace(name, "<root>")
            return out.getvalue(), error, count

    def test_positive_all_pass_in_input_order(self) -> None:
        out, error, count = self.run_gate(["a-one", "b-two", "c-three"], None)
        self.assertIsNone(error)
        self.assertEqual(count, 3)
        self.assertEqual(
            out.splitlines(),
            [
                f"validated rules/python/security/{i}.yml"
                for i in ("a-one", "b-two", "c-three")
            ],
        )

    def test_boundary_single_and_zero_rules(self) -> None:
        out, error, count = self.run_gate(["a-one"], None)
        self.assertEqual((error, count), (None, 1))
        self.assertEqual(out, "validated rules/python/security/a-one.yml\n")
        out, error, count = self.run_gate([], None)
        self.assertEqual((out, error, count), ("", None, 0))

    def test_error_every_failure_reported_in_order(self) -> None:
        ids = ["a-one", "bad-two", "c-three", "bad-zz"]
        out, error, count = self.run_gate(ids, 4)
        self.assertIsNone(count)
        assert error is not None
        lines = error.splitlines()
        self.assertEqual(lines[0], "2 of 4 changed rule(s) failed:")
        self.assertTrue(lines[1].startswith("rules/python/security/bad-two.yml: "))
        self.assertIn("boom-bad-two", lines[1])
        self.assertTrue(lines[2].startswith("rules/python/security/bad-zz.yml: "))
        self.assertEqual(len(lines), 3)
        # Passing rules are still validated, not skipped by fail-fast.
        self.assertEqual(
            out.splitlines(),
            [
                "validated rules/python/security/a-one.yml",
                "validated rules/python/security/c-three.yml",
            ],
        )

    def test_error_exit_code_is_one(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            paths = make_pair(root, "bad-one") + make_pair(root, "c-two")
            engine = make_engine(root)
            argv = ["gate", "--root", name, "--engine", str(engine), *paths]
            with (
                patch.object(sys, "argv", argv),
                redirect_stdout(io.StringIO()),
                patch("sys.stderr", new_callable=io.StringIO) as err,
            ):
                self.assertEqual(gate.main(), 1)
            self.assertIn("1 of 2 changed rule(s) failed", err.getvalue())

    def test_negative_control_serial_matches_concurrent(self) -> None:
        ids = ["a-one", "bad-two", "c-three", "bad-zz", "d-four"]
        self.assertEqual(self.run_gate(ids, 1), self.run_gate(ids, 4))
        ok = ["a-one", "c-three"]
        self.assertEqual(self.run_gate(ok, 1), self.run_gate(ok, 3))

    def test_worker_count_is_bounded(self) -> None:
        with patch.object(gate.os, "cpu_count", return_value=64):
            self.assertEqual(gate.worker_count(100), gate.MAX_WORKERS)
            self.assertEqual(gate.worker_count(2), 2)
        with patch.object(gate.os, "cpu_count", return_value=None):
            self.assertEqual(gate.worker_count(10), 1)
        self.assertEqual(gate.worker_count(0), 1)


if __name__ == "__main__":
    unittest.main()
