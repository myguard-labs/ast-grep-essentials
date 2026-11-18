"""Fail when the ast-grep pin in package.json and the baseline engine differ.

The pin is read the way ``ci/promote.py`` reads it: ``pinned_engine_version``
takes ``data["devDependencies"]["@ast-grep/cli"]`` and accepts only an exact
``X.Y.Z`` version. A range such as ``^0.51.3``, ``~0.51.3`` or ``=0.51.3`` is
rejected with a clear message instead of being normalized. A missing
``devDependencies`` or ``@ast-grep/cli`` key, or a missing ``engine`` key in
the baseline, fails with an AssertionError that names the missing key.

Only ``test_repository_pin_matches_baseline_engine`` reads the real files. The
other tests use synthetic JSON so they keep passing after a legitimate pin bump.
"""

import json
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_JSON = REPO_ROOT / "package.json"
PROMOTION_JSON = REPO_ROOT / "ci" / "baselines" / "promotion.json"
EXACT_VERSION = re.compile(r"\d+\.\d+\.\d+")


def check_pin_matches(package_text: str, promotion_text: str) -> None:
    """Raise AssertionError unless the package pin equals the baseline engine."""
    package = json.loads(package_text)
    dev_deps = package.get("devDependencies") if isinstance(package, dict) else None
    if not isinstance(dev_deps, dict) or "devDependencies" not in package:
        raise AssertionError(
            "package.json has no devDependencies object; expected "
            'devDependencies["@ast-grep/cli"] to hold the ast-grep pin'
        )
    if "@ast-grep/cli" not in dev_deps:
        raise AssertionError(
            'package.json devDependencies has no "@ast-grep/cli" key; '
            "the ast-grep pin is missing"
        )
    pin = dev_deps["@ast-grep/cli"]
    promotion = json.loads(promotion_text)
    if not isinstance(promotion, dict) or "engine" not in promotion:
        raise AssertionError(
            'ci/baselines/promotion.json has no "engine" key; regenerate the '
            "baseline with `promote.py baseline`"
        )
    engine = promotion["engine"]
    if not isinstance(pin, str) or not EXACT_VERSION.fullmatch(pin):
        raise AssertionError(
            "@ast-grep/cli pin in package.json must be an exact X.Y.Z version, "
            f"got {pin!r}; remove any ^, ~ or = prefix"
        )
    if pin != engine:
        raise AssertionError(
            f"ast-grep pin {pin} in package.json differs from baseline engine "
            f"{engine} in ci/baselines/promotion.json; regenerate the baseline "
            "with `promote.py baseline` after bumping the pin"
        )


def _package_text(pin: str) -> str:
    return json.dumps({"devDependencies": {"@ast-grep/cli": pin}})


def _promotion_text(engine: str) -> str:
    return json.dumps({"engine": engine})


class PinBaselineEngineTests(unittest.TestCase):
    def test_repository_pin_matches_baseline_engine(self):
        check_pin_matches(
            PACKAGE_JSON.read_text(encoding="utf-8"),
            PROMOTION_JSON.read_text(encoding="utf-8"),
        )

    def test_matching_synthetic_pin_passes(self):
        check_pin_matches(_package_text("1.2.3"), _promotion_text("1.2.3"))

    def test_injected_mismatch_fails_with_both_values(self):
        with self.assertRaises(AssertionError) as ctx:
            check_pin_matches(_package_text("1.2.3"), _promotion_text("1.2.0"))
        message = str(ctx.exception)
        self.assertIn("1.2.3", message)
        self.assertIn("1.2.0", message)
        self.assertIn("promote.py baseline", message)

    def test_range_prefix_in_pin_fails_clearly(self):
        for pin in ("^1.2.3", "~1.2.3", "=1.2.3"):
            with self.subTest(pin=pin):
                with self.assertRaises(AssertionError) as ctx:
                    check_pin_matches(_package_text(pin), _promotion_text("1.2.3"))
                self.assertIn("exact X.Y.Z", str(ctx.exception))

    def test_missing_devdependencies_fails_naming_key(self):
        with self.assertRaises(AssertionError) as ctx:
            check_pin_matches(json.dumps({"name": "x"}), _promotion_text("1.2.3"))
        self.assertIn("devDependencies", str(ctx.exception))

    def test_missing_ast_grep_cli_key_fails_naming_key(self):
        package = json.dumps({"devDependencies": {"other": "1.0.0"}})
        with self.assertRaises(AssertionError) as ctx:
            check_pin_matches(package, _promotion_text("1.2.3"))
        self.assertIn("@ast-grep/cli", str(ctx.exception))

    def test_missing_engine_fails_naming_key_and_baseline_command(self):
        with self.assertRaises(AssertionError) as ctx:
            check_pin_matches(_package_text("1.2.3"), json.dumps({"other": 1}))
        message = str(ctx.exception)
        self.assertIn("engine", message)
        self.assertIn("promote.py baseline", message)


if __name__ == "__main__":
    unittest.main()
