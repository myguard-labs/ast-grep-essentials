"""Stable counters emitted by rule-plan validation."""

from dataclasses import dataclass


@dataclass
class PhaseTelemetry:  # pylint: disable=too-many-instance-attributes
    """Deterministic work counters plus informational wall-clock time."""

    engine_processes: int = 0
    plans: int = 0
    valid_cases: int = 0
    invalid_cases: int = 0
    exclusions: int = 0
    bytes: int = 0
    mutants: int = 0
    surviving_mutants: int = 0
    invalid_mutants: int = 0
    error_mutants: int = 0
    load_validate_ms: int = 0
    render_ms: int = 0
    preflight_ms: int = 0
    wall_ms: int = 0

    def report(self) -> dict:
        return {
            "version": 1,
            "counts": {
                "engine_processes": self.engine_processes, "plans": self.plans,
                "valid_cases": self.valid_cases, "invalid_cases": self.invalid_cases,
                "exclusions": self.exclusions, "bytes": self.bytes,
                "mutants": self.mutants, "survived": self.surviving_mutants,
                "invalid": self.invalid_mutants, "errors": self.error_mutants,
            },
            "wall_clock_ms_informational": {
                "load_validate": self.load_validate_ms, "render": self.render_ms,
                "preflight": self.preflight_ms, "batched_engine": self.wall_ms,
            },
        }
