"""Fail when the ast-grep pin in package.json and the baseline engine differ.

The pin is read exactly as ``ci/promote.py`` reads it: an exact ``X.Y.Z``
version. A range such as ``^0.51.3``, ``~0.51.3`` or ``=0.51.3`` is rejected
with a clear message instead of being normalized.
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
    pin = json.loads(package_text)["devDependencies"]["@ast-grep/cli"]
    engine = json.loads(promotion_text)["engine"]
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


class PinBaselineEngineTests(unittest.TestCase):
    def test_repository_pin_matches_baseline_engine(self):
        check_pin_matches(
            PACKAGE_JSON.read_text(encoding="utf-8"),
            PROMOTION_JSON.read_text(encoding="utf-8"),
        )

    def test_injected_mismatch_fails_with_both_values(self):
        package = PACKAGE_JSON.read_text(encoding="utf-8")
        promotion = json.loads(PROMOTION_JSON.read_text(encoding="utf-8"))
        promotion["engine"] = "0.51.0"
        with self.assertRaises(AssertionError) as ctx:
            check_pin_matches(package, json.dumps(promotion))
        message = str(ctx.exception)
        self.assertIn("0.51.3", message)
        self.assertIn("0.51.0", message)
        self.assertIn("promote.py baseline", message)

    def test_range_prefix_in_pin_fails_clearly(self):
        package = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
        package["devDependencies"]["@ast-grep/cli"] = "^0.51.3"
        promotion = PROMOTION_JSON.read_text(encoding="utf-8")
        with self.assertRaises(AssertionError) as ctx:
            check_pin_matches(json.dumps(package), promotion)
        self.assertIn("exact X.Y.Z", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
