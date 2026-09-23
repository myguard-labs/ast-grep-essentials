#!/usr/bin/env python3
"""Test only changed rules and fixtures with the latest ast-grep CLI.

The latest CLI is installed in a temporary prefix. Each affected rule is then
copied with its mirrored fixture into an isolated config, so one PR cannot pass
because another rule or language happened to load successfully.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

SUPPORTED_LANGUAGES = frozenset(
    {
        "bash",
        "c",
        "cpp",
        "csharp",
        "go",
        "html",
        "java",
        "javascript",
        "kotlin",
        "lua",
        "php",
        "python",
        "ruby",
        "rust",
        "scala",
        "swift",
        "typescript",
    }
)
NPM_REGISTRY = "https://registry.npmjs.org/"
PASS_LINE = re.compile(r"(?m)^test result: ok\. 1 passed; 0 failed;\s*$")


class ValidationError(RuntimeError):
    """A changed-rule gate failed with a bounded operator-facing reason."""


def _tail(result: subprocess.CompletedProcess[str]) -> str:
    output = (result.stderr + result.stdout).strip()
    return output[-1000:] or f"exit {result.returncode}"


def _run(
    command: Sequence[str | Path],
    *,
    cwd: Path,
    timeout: int,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            [str(part) for part in command],
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValidationError(f"cannot run {command[0]}: {error}") from error
    if result.returncode:
        raise ValidationError(f"{command[0]} failed: {_tail(result)}")
    return result


def changed_paths(root: Path, base: str) -> list[str]:
    result = _run(
        [
            "git",
            "diff",
            "--name-only",
            "--no-renames",
            "--diff-filter=ACMRD",
            base,
            "--",
        ],
        cwd=root,
        timeout=30,
    )
    return [line for line in result.stdout.splitlines() if line]


def _safe_path(value: str) -> PurePosixPath | None:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValidationError(f"changed path is not repository-relative: {value}")
    return path if path.suffix in {".yml", ".yaml"} else None


def mirrored_fixture(rule_path: PurePosixPath) -> str:
    return PurePosixPath("tests", *rule_path.parts[1:]).as_posix()


def _rule_body(data: bytes) -> bytes:
    """Everything from the first line that is not a blank or a comment.

    Only the leading banner is set aside: a ``#`` line further down may sit in
    a block scalar, where it is pattern text rather than a comment. Only YAML
    whitespace (space and tab) may precede a banner ``#``; any other byte,
    including a BOM or a no-break space, starts the body.
    """
    lines = data.splitlines(keepends=True)
    for index, line in enumerate(lines):
        stripped = line.lstrip(b" \t")
        if stripped.rstrip(b"\r\n") and not stripped.startswith(b"#"):
            return b"".join(lines[index:])
    return b""


def _base_blob(root: Path, base: str, path: PurePosixPath) -> bytes | None:
    try:
        result = subprocess.run(
            [
                "git",
                "cat-file",
                "blob",
                "--end-of-options",
                f"{base}:{path.as_posix()}",
            ],
            cwd=root,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return None if result.returncode else result.stdout


def header_only_rule_changes(
    root: Path, base: str, paths: Sequence[str]
) -> frozenset[str]:
    """Changed rules whose bytes differ from ``base`` only in the banner."""
    exempt = set()
    for value in paths:
        path = _safe_path(value)
        if path is None or len(path.parts) != 4 or path.parts[0] != "rules":
            continue
        current = root / path
        if not current.exists():
            continue
        _require_contained_regular(root, current, "rule")
        previous = _base_blob(root, base, path)
        if previous is None:
            continue  # An added rule, or an unreadable base, is never exempt.
        body = _rule_body(current.read_bytes())
        if body and body == _rule_body(previous):
            exempt.add(value)
    return frozenset(exempt)


def missing_fixture_changes(
    paths: Sequence[str], exempt: frozenset[str] = frozenset()
) -> list[str]:
    changed = set(paths)
    missing = set()
    for value in paths:
        path = _safe_path(value)
        if value in exempt:
            continue
        if path is not None and len(path.parts) == 4 and path.parts[0] == "rules":
            fixture = mirrored_fixture(path)
            if fixture not in changed:
                missing.add(fixture)
    return sorted(missing)


def _require_supported_language(path: PurePosixPath) -> None:
    if path.parts[1] not in SUPPORTED_LANGUAGES:
        raise ValidationError(f"unsupported rule language: {path.parts[1]}")


def _fixture_rule(root: Path, path: PurePosixPath) -> PurePosixPath:
    if len(path.parts) != 4:
        raise ValidationError(f"unsupported fixture layout: {path}")
    _require_supported_language(path)
    rule = PurePosixPath("rules", *path.parts[1:])
    if (root / path).exists() and not (root / rule).is_file():
        raise ValidationError(f"fixture does not mirror a rule: {path}")
    return rule


def _snapshot_rule(root: Path, path: PurePosixPath) -> PurePosixPath | None:
    found = find_rule(root, path.name.removesuffix("-snapshot.yml"))
    if found is not None:
        return PurePosixPath(found.relative_to(root).as_posix())
    if (root / path).exists():
        raise ValidationError(f"snapshot does not name an existing rule: {path}")
    return None


def changed_rule_paths(root: Path, paths: Sequence[str]) -> list[PurePosixPath]:
    rules = set()
    for value in paths:
        path = _safe_path(value)
        if path is None:
            continue
        if not path.parts or path.parts[0] not in {"rules", "tests"}:
            continue
        if path.suffix != ".yml":
            raise ValidationError(f"unsupported rule or fixture extension: {path}")
        if path.parts[0] == "rules":
            if len(path.parts) != 4:
                raise ValidationError(f"unsupported rule layout: {path}")
            _require_supported_language(path)
            rules.add(path)
            continue
        if (
            len(path.parts) == 3
            and path.parts[:2] == ("tests", "__snapshots__")
            and path.name.endswith("-snapshot.yml")
        ):
            rule = _snapshot_rule(root, path)
            if rule is not None:
                rules.add(rule)
            continue
        rules.add(_fixture_rule(root, path))
    return sorted(rules, key=PurePosixPath.as_posix)


def find_rule(root: Path, rule_id: str) -> Path | None:
    hits = list((root / "rules").glob(f"*/*/{rule_id}.yml"))
    if len(hits) > 1:
        raise ValidationError(f"multiple rule files have id {rule_id}")
    return hits[0] if hits else None


def _require_contained_regular(root: Path, path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ValidationError(f"missing {label}: {path.relative_to(root)}") from error
    except OSError as error:
        raise ValidationError(
            f"cannot inspect {label}: {path.relative_to(root)}"
        ) from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ValidationError(
            f"{label} must be a regular file: {path.relative_to(root)}"
        )
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise ValidationError(
            f"{label} escapes the checkout: {path.relative_to(root)}"
        ) from error


def validate_rule(root: Path, engine: Path, rule_path: Path) -> None:
    relative = rule_path.relative_to(root / "rules")
    if len(relative.parts) != 3 or relative.parts[0] not in SUPPORTED_LANGUAGES:
        raise ValidationError(f"unsupported rule layout: {rule_path.relative_to(root)}")
    _require_contained_regular(root, rule_path, "rule")
    fixture = root / "tests" / relative
    _require_contained_regular(root, fixture, "mirrored fixture")
    snapshot = root / "tests" / "__snapshots__" / f"{rule_path.stem}-snapshot.yml"
    has_snapshot = os.path.lexists(snapshot)
    if has_snapshot:
        _require_contained_regular(root, snapshot, "snapshot")

    with tempfile.TemporaryDirectory(prefix="ast-grep-latest-rule-") as name:
        isolated = Path(name)
        rules = isolated / "rules"
        tests = isolated / "tests"
        snapshots = tests / "__snapshots__"
        rules.mkdir()
        snapshots.mkdir(parents=True)
        shutil.copy2(rule_path, rules / rule_path.name)
        shutil.copy2(fixture, tests / fixture.name)
        if has_snapshot:
            shutil.copy2(snapshot, snapshots / snapshot.name)
        config = isolated / "sgconfig.yml"
        config.write_text(
            "ruleDirs: [rules]\ntestConfigs: [{testDir: tests}]\n",
            encoding="utf-8",
        )
        command: list[str | Path] = [
            engine,
            "test",
            "--include-off",
            "-c",
            config,
        ]
        if not has_snapshot:
            command.append("--skip-snapshot-tests")
        result = _run(command, cwd=isolated, timeout=60)
    if PASS_LINE.search(result.stdout) is None:
        raise ValidationError(
            f"ast-grep did not execute one fixture for {rule_path.stem}: {_tail(result)}"
        )


@contextmanager
def latest_engine() -> Iterator[tuple[Path, str]]:
    with tempfile.TemporaryDirectory(prefix="ast-grep-latest-cli-") as name:
        prefix = Path(name)
        global_npmrc = prefix / "global-npmrc"
        user_npmrc = prefix / "user-npmrc"
        global_npmrc.write_text("", encoding="utf-8")
        user_npmrc.write_text("", encoding="utf-8")
        environment = {
            **{
                key: value
                for key, value in os.environ.items()
                if not key.casefold().startswith("npm_config_")
            },
            "npm_config_fetch_retries": "2",
            "npm_config_fetch_retry_mintimeout": "1000",
            "npm_config_fetch_retry_maxtimeout": "10000",
            "npm_config_fetch_timeout": "30000",
            "npm_config_globalconfig": str(global_npmrc),
            "npm_config_registry": NPM_REGISTRY,
            "npm_config_userconfig": str(user_npmrc),
        }
        registry = _run(
            [
                "npm",
                "view",
                "@ast-grep/cli",
                "dist-tags.latest",
                f"--registry={NPM_REGISTRY}",
            ],
            cwd=prefix,
            timeout=30,
            env=environment,
        ).stdout.strip()
        _run(
            [
                "npm",
                "install",
                "--ignore-scripts",
                "--no-save",
                "--package-lock=false",
                f"--registry={NPM_REGISTRY}",
                "--prefix",
                prefix,
                f"@ast-grep/cli@{registry}",
            ],
            cwd=prefix,
            timeout=180,
            env=environment,
        )
        package = prefix / "node_modules" / "@ast-grep" / "cli" / "package.json"
        engine = prefix / "node_modules" / ".bin" / "ast-grep"
        try:
            installed = json.loads(package.read_text(encoding="utf-8"))["version"]
        except (OSError, KeyError, TypeError, ValueError) as error:
            raise ValidationError(
                "cannot identify installed ast-grep version"
            ) from error
        if not engine.is_file() or not os.access(engine, os.X_OK):
            raise ValidationError("latest ast-grep executable was not installed")
        if installed != registry:
            raise ValidationError(
                f"installed ast-grep {installed}, registry latest is {registry}"
            )
        yield engine, installed


def validate_changed(
    root: Path, engine: Path, paths: Sequence[str], base: str | None = None
) -> int:
    exempt = header_only_rule_changes(root, base, paths) if base else frozenset()
    missing = missing_fixture_changes(paths, exempt)
    if missing:
        raise ValidationError(
            "changed rules require changed mirrored fixtures: " + ", ".join(missing)
        )
    validated = 0
    for relative in changed_rule_paths(root, paths):
        rule = root / relative
        if not rule.is_file():  # A removed rule and fixture have nothing left to load.
            continue
        validate_rule(root, engine, rule)
        print(f"validated {rule.relative_to(root)}")
        validated += 1
    return validated


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=os.environ.get("BASE_SHA"))
    parser.add_argument("--engine", type=Path)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="candidate checkout to validate",
    )
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args()
    if not args.paths and not args.base:
        parser.error("--base or explicit changed paths are required")
    count = 0
    version = "unknown"
    try:
        try:
            root = args.root.resolve(strict=True)
        except OSError as error:
            raise ValidationError("--root must name a checkout directory") from error
        if not root.is_dir():
            raise ValidationError("--root must name a checkout directory")
        paths = args.paths or changed_paths(root, args.base)
        if args.engine is not None:
            engine = args.engine.resolve()
            if not engine.is_file() or not os.access(engine, os.X_OK):
                raise ValidationError("--engine must name an executable file")
            count = validate_changed(root, engine, paths, args.base)
            version = _run([engine, "--version"], cwd=root, timeout=15).stdout.strip()
        else:
            with latest_engine() as (engine, version):
                count = validate_changed(root, engine, paths, args.base)
    except ValidationError as error:
        print(f"validate-changed-rules: {error}", file=sys.stderr)
        return 1
    print(f"latest ast-grep {version}: {count} changed rule(s) passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
