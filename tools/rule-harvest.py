#!/usr/bin/env python3
"""Run the deterministic ast-grep harvest pipeline as one resumable workflow.

The working directory must be outside this repository. It holds the candidate
corpus, bounded proposal packets, externally supplied replies, and draft plan.
This command never calls a model: ``enrich`` exits 2 when proposal replies are
missing, after printing the exact handoff directories. Use the packet prompt
and JSON files with a trusted dispatcher, place replies in the indicated
directory, and rerun the same command.

Stages:
  candidates  Harvest fixes from one or more local Git repositories.
  enrich      Emit proposal packets, ingest supplied replies, and deduplicate.
  prepare     Route validated proposals through rule-batch.py.
  status      Report packet/reply state.
  generate    Check plans in dry-run mode, otherwise regenerate approved plans.
  all         Run candidates, enrich, and prepare, stopping at any handoff.

Exit 0 means the requested stages completed, 1 means a tool failed, and 2
means an external reply handoff is ready. ``--dry-run`` writes nothing.
"""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"


def command_text(command: list[str]) -> str:
    """Render a diagnostic-only command without invoking a shell."""
    return shlex.join(command)


def run(command: list[str], *, dry_run: bool = False) -> int:
    """Run one repository tool, or print the exact argv in dry-run mode."""
    if dry_run:
        print(command_text(command))
        return 0
    returncode = subprocess.run(command, cwd=ROOT, check=False).returncode
    return 0 if returncode == 0 else 1


def tool(name: str, *args: object) -> list[str]:
    return [sys.executable, str(TOOLS / name), *(str(arg) for arg in args)]


def packet_paths(work: Path) -> list[Path]:
    return sorted((work / "cluster" / "packets").glob("*.json"))


def missing_replies(work: Path) -> list[Path]:
    replies = work / "cluster" / "replies"
    return [
        packet for packet in packet_paths(work) if not (replies / packet.name).is_file()
    ]


def candidates(args: argparse.Namespace) -> int:
    if not args.root or not args.repos:
        print("candidates/all require --root and --repos", file=sys.stderr)
        return 1
    return run(
        tool(
            "harvest-history.py",
            "--root",
            args.root,
            "--repos",
            *args.repos,
            "--out",
            args.work / "candidates.jsonl",
            "--index",
            args.work / "candidates.md",
        ),
        dry_run=args.dry_run,
    )


def enrich(args: argparse.Namespace) -> int:
    corpus = args.work / "candidates.jsonl"
    if not args.dry_run and not corpus.is_file():
        print(f"rule-harvest: missing {corpus}; run candidates first", file=sys.stderr)
        return 1
    emit = tool(
        "harvest-packets.py",
        "cluster-emit",
        "--mechanical",
        "--corpus",
        corpus,
        "--work",
        args.work,
    )
    rc = run(emit, dry_run=args.dry_run)
    if rc:
        return rc
    if args.dry_run:
        for stage in ("cluster-ingest", "dedupe"):
            run(tool("harvest-packets.py", stage, "--work", args.work), dry_run=True)
        return 0
    pending = missing_replies(args.work)
    if pending:
        stage = args.work / "cluster"
        print(
            f"handoff ready: {len(pending)} packet(s); prompt={stage / 'PROMPT.md'} "
            f"packets={stage / 'packets'} replies={stage / 'replies'}",
            file=sys.stderr,
        )
        return 2
    for stage in ("cluster-ingest", "dedupe"):
        rc = run(tool("harvest-packets.py", stage, "--work", args.work))
        if rc:
            return rc
    return 0


def prepare(args: argparse.Namespace) -> int:
    command = tool("rule-batch.py", "--work", args.work, "--category", args.category)
    if args.dry_run:
        command.append("--dry-run")
    return run(command)


def status(args: argparse.Namespace) -> int:
    return run(
        tool("harvest-packets.py", "status", "--work", args.work),
        dry_run=args.dry_run,
    )


def generate(args: argparse.Namespace) -> int:
    action = "check-plans" if args.dry_run else "regenerate-all"
    return run(tool("rule-mechanics.py", action))


STAGE_HANDLERS = {
    "candidates": candidates,
    "enrich": enrich,
    "prepare": prepare,
    "status": status,
    "generate": generate,
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("stage", choices=(*STAGE_HANDLERS, "all"))
    parser.add_argument(
        "--work",
        required=True,
        type=Path,
        help="resumable directory outside this repository",
    )
    parser.add_argument(
        "--root", type=Path, help="directory holding source repositories"
    )
    parser.add_argument(
        "--repos", nargs="+", help="repository paths relative to --root"
    )
    parser.add_argument(
        "--category",
        choices=("security", "correctness"),
        default="correctness",
        help="category assigned by prepare",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="show/check without writing"
    )
    args = parser.parse_args(argv)
    work_is_in_repository = True
    try:
        args.work.resolve().relative_to(ROOT.resolve())
    except ValueError:
        work_is_in_repository = False
    if work_is_in_repository:
        parser.error("--work must be outside the repository")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    stages = (
        ("candidates", "enrich", "prepare") if args.stage == "all" else (args.stage,)
    )
    try:
        for stage in stages:
            rc = STAGE_HANDLERS[stage](args)
            if rc:
                return rc
    except (OSError, UnicodeError) as error:
        print(f"rule-harvest: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised by CLI integration
    sys.exit(main())
