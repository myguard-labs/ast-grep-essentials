"""Contracts for the resumable harvest pipeline orchestrator."""

import contextlib
import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "rule_harvest", ROOT / "tools" / "rule-harvest.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load rule-harvest.py")
HARVEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARVEST)


def args(work, **changes):
    values = {
        "work": Path(work),
        "root": None,
        "repos": None,
        "category": "correctness",
        "dry_run": False,
    }
    values.update(changes)
    return SimpleNamespace(**values)


class RuleHarvestTests(unittest.TestCase):
    def test_packet_replies_are_sorted_and_exactly_name_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            packets = work / "cluster/packets"
            replies = work / "cluster/replies"
            packets.mkdir(parents=True)
            replies.mkdir(parents=True)
            for name in ("z.json", "a.json", "ignored.txt"):
                (packets / name).write_text("{}", encoding="utf-8")
            (replies / "a.json").write_text("{}", encoding="utf-8")
            (replies / "z.json").mkdir()
            self.assertEqual(
                HARVEST.packet_paths(work),
                [packets / "a.json", packets / "z.json"],
            )
            self.assertEqual(HARVEST.missing_replies(work), [packets / "z.json"])

    def test_run_uses_fixed_argv_and_dry_run_only_prints(self):
        command = ["tool with space", "argument;not-shell"]
        with (
            patch.object(HARVEST.subprocess, "run") as invoked,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(HARVEST.run(command, dry_run=True), 0)
        invoked.assert_not_called()
        self.assertEqual(output.getvalue().strip(), HARVEST.command_text(command))

        completed = subprocess.CompletedProcess(command, 7)
        with patch.object(HARVEST.subprocess, "run", return_value=completed) as invoked:
            self.assertEqual(HARVEST.run(command), 1)
        invoked.assert_called_once_with(command, cwd=HARVEST.ROOT, check=False)
        completed = subprocess.CompletedProcess(command, 0)
        with patch.object(HARVEST.subprocess, "run", return_value=completed):
            self.assertEqual(HARVEST.run(command), 0)

    def test_candidates_requires_inputs_and_builds_bounded_outputs(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            contextlib.redirect_stderr(io.StringIO()) as errors,
        ):
            self.assertEqual(HARVEST.candidates(args(directory)), 1)
        self.assertIn("require --root and --repos", errors.getvalue())

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(HARVEST, "run", return_value=0) as invoked,
        ):
            work = Path(directory)
            source = work.parent / "sources"
            self.assertEqual(
                HARVEST.candidates(
                    args(work, root=source, repos=["one", "two"], dry_run=True)
                ),
                0,
            )
        command = invoked.call_args.args[0]
        self.assertEqual(
            command[:2], [sys.executable, str(HARVEST.TOOLS / "harvest-history.py")]
        )
        self.assertEqual(
            command[-4:],
            [
                "--out",
                str(work / "candidates.jsonl"),
                "--index",
                str(work / "candidates.md"),
            ],
        )
        self.assertTrue(invoked.call_args.kwargs["dry_run"])

    def test_enrich_rejects_missing_corpus_and_propagates_emit_failure(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            contextlib.redirect_stderr(io.StringIO()) as errors,
        ):
            work = Path(directory)
            self.assertEqual(HARVEST.enrich(args(work)), 1)
            self.assertIn("run candidates first", errors.getvalue())
            (work / "candidates.jsonl").write_text("", encoding="utf-8")
            with patch.object(HARVEST, "run", return_value=9) as invoked:
                self.assertEqual(HARVEST.enrich(args(work)), 9)
            self.assertIn("--mechanical", invoked.call_args.args[0])

    def test_enrich_dry_run_prints_every_command_without_reading_state(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(HARVEST, "run", return_value=0) as invoked,
        ):
            self.assertEqual(HARVEST.enrich(args(directory, dry_run=True)), 0)
        self.assertEqual(invoked.call_count, 3)
        self.assertEqual(
            [call.args[0][2] for call in invoked.call_args_list],
            ["cluster-emit", "cluster-ingest", "dedupe"],
        )
        self.assertTrue(all(call.kwargs["dry_run"] for call in invoked.call_args_list))

    def test_enrich_stops_for_handoff_then_ingests_complete_replies(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "candidates.jsonl").write_text("", encoding="utf-8")
            packets = work / "cluster/packets"
            packets.mkdir(parents=True)
            (packets / "go-bounds.json").write_text("{}", encoding="utf-8")
            with (
                patch.object(HARVEST, "run", return_value=0),
                contextlib.redirect_stderr(io.StringIO()) as errors,
            ):
                self.assertEqual(HARVEST.enrich(args(work)), 2)
            message = errors.getvalue()
            self.assertIn("handoff ready: 1 packet", message)
            self.assertIn(str(work / "cluster/PROMPT.md"), message)

            replies = work / "cluster/replies"
            replies.mkdir()
            (replies / "go-bounds.json").write_text("{}", encoding="utf-8")
            with patch.object(HARVEST, "run", side_effect=(0, 0, 6)) as invoked:
                self.assertEqual(HARVEST.enrich(args(work)), 6)
            self.assertEqual(
                [call.args[0][2] for call in invoked.call_args_list],
                ["cluster-emit", "cluster-ingest", "dedupe"],
            )
            with patch.object(HARVEST, "run", side_effect=(0, 0, 0)):
                self.assertEqual(HARVEST.enrich(args(work)), 0)

    def test_prepare_status_and_generate_delegate_exactly(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(HARVEST, "run", side_effect=(3, 4, 5, 6)) as invoked,
        ):
            work = Path(directory)
            self.assertEqual(
                HARVEST.prepare(args(work, category="security", dry_run=True)), 3
            )
            self.assertEqual(HARVEST.status(args(work, dry_run=True)), 4)
            self.assertEqual(HARVEST.generate(args(work, dry_run=True)), 5)
            self.assertEqual(HARVEST.generate(args(work)), 6)
        commands = [call.args[0] for call in invoked.call_args_list]
        self.assertEqual(
            commands[0][-5:],
            ["--work", str(work), "--category", "security", "--dry-run"],
        )
        self.assertTrue(invoked.call_args_list[1].kwargs["dry_run"])
        self.assertEqual(commands[2][-1], "check-plans")
        self.assertEqual(commands[3][-1], "regenerate-all")

    def test_parser_rejects_repository_work_and_accepts_external_work(self):
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            HARVEST.parse_args(["status", "--work", str(ROOT / "scratch")])
        self.assertEqual(raised.exception.code, 2)
        with tempfile.TemporaryDirectory() as directory:
            parsed = HARVEST.parse_args(["status", "--work", directory])
            self.assertEqual(parsed.category, "correctness")

    def test_main_stops_all_at_handoff_and_bounds_os_errors(self):
        handlers = {
            "candidates": lambda _args: 0,
            "enrich": lambda _args: 2,
            "prepare": lambda _args: self.fail("prepare ran after handoff"),
            "status": HARVEST.status,
            "generate": HARVEST.generate,
        }
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(HARVEST, "STAGE_HANDLERS", handlers):
                self.assertEqual(
                    HARVEST.main(
                        [
                            "all",
                            "--work",
                            directory,
                            "--root",
                            "/src",
                            "--repos",
                            "one",
                        ]
                    ),
                    2,
                )

            handlers["status"] = lambda _args: 0
            with patch.object(HARVEST, "STAGE_HANDLERS", handlers):
                self.assertEqual(HARVEST.main(["status", "--work", directory]), 0)

            handlers["status"] = lambda _args: (_ for _ in ()).throw(OSError("offline"))
            with (
                patch.object(HARVEST, "STAGE_HANDLERS", handlers),
                contextlib.redirect_stderr(io.StringIO()) as errors,
            ):
                self.assertEqual(HARVEST.main(["status", "--work", directory]), 1)
        self.assertIn("rule-harvest: offline", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
