"""Contracts for canonical plans and mechanical validation helpers."""

import importlib.util
import sys
from pathlib import Path

__all__ = ["ROOT", "load_tool", "minimal_plan"]

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def minimal_plan(**updates):
    plan = {
        "version": 1,
        "id": "py-sample",
        "language": "python",
        "category": "security",
        "message": "sample message",
        "note": "sample note",
        "rule": {"pattern": "danger()"},
        "cases": {"invalid": ["danger()"], "valid": ["safe()"]},
    }
    plan.update(updates)
    return plan
