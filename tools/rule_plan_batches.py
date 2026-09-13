"""Execution and result classification for batched rule-plan mutants."""

import re
import subprocess
from collections.abc import Callable, Iterable
from typing import TypeAlias

MutationPath: TypeAlias = str
Outcome: TypeAlias = tuple[str, str]
Outcomes: TypeAlias = dict[MutationPath, Outcome]
EngineResult: TypeAlias = subprocess.CompletedProcess[str]
Invoke: TypeAlias = Callable[[], EngineResult]


def batch_error(paths: Iterable[MutationPath], malformed: Outcomes,
                detail: str) -> Outcomes:
    outcomes = dict.fromkeys(paths, ("error", detail))
    outcomes.update(malformed)
    return outcomes


def raise_batch_error(outcomes: Outcomes) -> None:
    """Fail on attributed engine errors before interpreting mutant semantics."""
    for path in sorted(outcomes):
        outcome, detail = outcomes[path]
        if outcome == "error":
            raise RuntimeError(f"MUTATION_PREFLIGHT_ERROR: {path}: {detail}")


def classify(result: EngineResult, id_to_path: dict[str, MutationPath],
             malformed: Outcomes) -> Outcomes | None:
    output = result.stdout + result.stderr
    if result.returncode != 0 and "Error: test failed." not in output:
        return None
    failed_ids = set(re.findall(r"^FAIL\s+(\S+)", output, flags=re.MULTILINE))
    outcomes = {
        path: (("killed", "test-failure") if mutant_id in failed_ids
               else ("survived", "ok"))
        for mutant_id, path in id_to_path.items()
    }
    outcomes.update(malformed)
    return outcomes


def execute(id_to_path: dict[str, MutationPath], malformed: Outcomes,
            invoke: Invoke) -> tuple[EngineResult | None, Outcomes | None]:
    """Execute one materialized batch and return its result or attributed errors."""
    try:
        result = invoke()
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        return None, batch_error(
            id_to_path.values(), malformed, f"engine-error={error}")
    return result, None


def unloadable_outcome(result: EngineResult, item: tuple[MutationPath, str],
                       malformed: Outcomes) -> Outcomes:
    output = result.stdout + result.stderr
    detail = " | ".join(output.splitlines()[-6:])[:600]
    kind = "invalid" if "file is not a valid ast-grep rule" in output else "error"
    return {**malformed, item[0]: (kind, detail)}
