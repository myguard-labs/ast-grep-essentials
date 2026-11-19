#!/usr/bin/env python3
"""Test only changed rules and fixtures with the latest ast-grep CLI.

The latest CLI is installed in a temporary prefix. Each affected rule is then
copied with its mirrored fixture into an isolated config, so one PR cannot pass
because another rule or language happened to load successfully. The
repository's global utils (``utils/``) are copied read-only into that config so
``matches: <util>`` resolves; a changed util re-validates every rule that
references it.
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
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any

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
# Languages whose parser is a customLanguages library in the root sgconfig.yml.
# The isolated per-rule config this gate builds has no such library, so the
# latest ast-grep cannot load or test them. A change to such a rule is accepted
# only when nothing but its ``metadata:`` block differs from base (see
# ``unparseable_metadata_only_changes``); anything else is refused.
UNPARSEABLE_LANGUAGES = frozenset({"powershell"})
NPM_REGISTRY = "https://registry.npmjs.org/"
MAX_WORKERS = 4
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


NON_MATCHING_KEYS = frozenset({"metadata", "note"})
# Top-level keys whose REMOVAL alone is not a matcher change: the stray
# ``ast-grep-essentials: true`` marker, which the latest ast-grep rejects as an
# unknown field. Adding it, or changing its value while kept, is never exempt.
REMOVABLE_KEYS = frozenset({"ast-grep-essentials"})


# Bounds on YAML alias use while comparing rule documents (billion-laughs guard).
# A file with more than MAX_ALIASES alias events, or whose alias-expanded tree
# visits more than MAX_EXPANDED_NODES nodes (a shared node counts once per
# visit), is refused and never exempt. Exactly at either bound is accepted.
MAX_ALIASES = 64
MAX_EXPANDED_NODES = 20000


def _expand(node: Any, budget: list[int], active: set[int]) -> object:
    """Resolve ``node`` to tagged scalars, lists and dicts, aliases expanded.

    A scalar becomes ``(resolved tag, exact source text)`` so ``null`` and
    ``"null"`` (or ``1`` and ``"1"``) differ while distinct text with one tag
    (``1.0``/``1.00``, ``yes``/``true``) still never compares equal. A mapping
    key is compared the same way, but a ``str``-tagged key is stored as its
    plain text so the ``NON_MATCHING_KEYS``/``REMOVABLE_KEYS`` lookups keep
    working; any other tag stores the ``(tag, text)`` pair, so key ``1`` and
    ``"1"`` stay distinct. Duplicate detection stays on the key text.

    ``budget`` is the remaining node-visit allowance; ``active`` holds the ids
    of the nodes on the current path so a self-referential alias is refused
    instead of recursing forever. A mapping with a duplicate, ``<<`` or
    non-scalar (sequence or mapping) key raises ``ValueError``.
    """
    import yaml  # pylint: disable=import-outside-toplevel

    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError("alias expansion exceeds the node bound")
    if isinstance(node, yaml.ScalarNode):
        return (node.tag, node.value)
    marker = id(node)
    if marker in active:
        raise ValueError("recursive alias")
    active.add(marker)
    try:
        if isinstance(node, yaml.SequenceNode):
            return [_expand(item, budget, active) for item in node.value]
        if isinstance(node, yaml.MappingNode):
            result: dict[object, object] = {}
            keys: set[str] = set()
            for key_node, value_node in node.value:
                key = _expand(key_node, budget, active)
                if not isinstance(key, tuple):
                    # A sequence or mapping key has no unambiguous string form.
                    raise ValueError("non-scalar mapping key")
                tag, text = key
                if text == "<<" or text in keys:
                    raise ValueError("duplicate or merge mapping key")
                keys.add(text)
                str_tag = "tag:yaml.org,2002:str"
                result[text if tag == str_tag else key] = _expand(
                    value_node, budget, active
                )
            return result
        raise ValueError("unsupported YAML node")
    finally:
        active.discard(marker)


def _strict_documents(data: bytes) -> list[object]:
    """Parse ``data`` with no value coercion or key ambiguity.

    Nodes are only composed with ``yaml.SafeLoader`` (no Python object is
    constructed); each scalar is kept as ``(resolved tag, exact text)``, so
    ``null``/``"null"`` and ``1``/``"1"`` differ, and distinct text such as
    ``1.0``/``1.00``, ``0x10``/``16``, ``yes``/``true`` or ``~``/``null`` never
    compares equal. Anchors and aliases are accepted and compared by
    their EXPANDED value (anchor names and placement are irrelevant), bounded
    by ``MAX_ALIASES`` and ``MAX_EXPANDED_NODES``; a recursive alias, a ``<<``
    merge key or a duplicate mapping key (at any depth) raises ``ValueError``.
    """
    import yaml  # pylint: disable=import-outside-toplevel

    aliases = 0
    for event in yaml.parse(data, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.AliasEvent):
            aliases += 1
            if aliases > MAX_ALIASES:
                raise ValueError("too many aliases")

    loader = yaml.SafeLoader(data)
    try:
        budget = [MAX_EXPANDED_NODES]
        documents: list[object] = []
        while loader.check_node():  # type: ignore[no-untyped-call]
            node = loader.get_node()  # type: ignore[no-untyped-call]
            documents.append(_expand(node, budget, set()))
        return documents
    finally:
        loader.dispose()  # type: ignore[no-untyped-call]


def _matcher_document(
    data: bytes, ignored: frozenset[str] = NON_MATCHING_KEYS
) -> dict[object, object] | None:
    """The single YAML mapping in ``data`` minus the non-matching keys.

    ``metadata`` and ``note`` are ignored by the ast-grep matcher, so a fixture
    cannot test them. Scalars compare by resolved tag plus exact text (no value
    coercion).
    Anything that is not exactly one plain mapping document (a parse failure,
    an empty or scalar document, a multi-document file, a duplicate or merge
    key, a recursive or over-bound alias expansion, or a missing PyYAML) returns ``None`` and is
    therefore never exempt.
    """
    try:
        import yaml  # pylint: disable=import-outside-toplevel
    except ImportError:
        return None
    try:
        documents = _strict_documents(data)
    except (yaml.YAMLError, ValueError, RecursionError):
        return None
    if len(documents) != 1 or not isinstance(documents[0], dict):
        return None
    return {k: v for k, v in documents[0].items() if k not in ignored}


def non_matching_rule_changes(
    root: Path,
    base: str,
    paths: Sequence[str],
    ignored: frozenset[str] = NON_MATCHING_KEYS,
    removable: frozenset[str] = REMOVABLE_KEYS,
    languages: frozenset[str] | None = None,
) -> frozenset[str]:
    """Changed rules whose parsed document differs from ``base`` only in the
    non-matching keys ``metadata`` and ``note``, or by the removal of a
    ``REMOVABLE_KEYS`` key (present in ``base``, absent now).

    Only the mirrored-fixture requirement is waived: ``validate_changed`` still
    runs ``validate_rule`` on every exempt rule. An added rule, an unreadable
    base, a parse failure, a multi-document file, or a change to any other key
    (rule, constraints, utils, transform, fix, language, id, severity, message,
    files, ignores, ...) is never exempt.
    """
    exempt = set()
    for value in paths:
        path = _safe_path(value)
        if path is None or len(path.parts) != 4 or path.parts[0] != "rules":
            continue
        if languages is not None and path.parts[1] not in languages:
            continue
        current = root / path
        if not current.exists():
            continue
        _require_contained_regular(root, current, "rule")
        previous = _base_blob(root, base, path)
        if previous is None:
            continue
        document = _matcher_document(current.read_bytes(), ignored)
        before = _matcher_document(previous, ignored)
        if document is None or before is None:
            continue
        # Only a removal is waived: drop a removable key from the base copy
        # when the current document no longer carries it.
        before = {
            k: v
            for k, v in before.items()
            if not (k in removable and k not in document)
        }
        if document == before:
            exempt.add(value)
    return frozenset(exempt)


def unparseable_metadata_only_changes(
    root: Path, base: str, paths: Sequence[str]
) -> frozenset[str]:
    """Changed rules in ``UNPARSEABLE_LANGUAGES`` whose parsed document differs
    from ``base`` only in ``metadata``. ``note`` and removable keys do not
    qualify here: the rule cannot be loaded, so only the block that ast-grep
    never reads is accepted. Added, deleted or logic-changed rules, and any
    fixture or snapshot path, are not returned and are refused downstream.
    """
    return non_matching_rule_changes(
        root,
        base,
        paths,
        ignored=frozenset({"metadata"}),
        removable=frozenset(),
        languages=UNPARSEABLE_LANGUAGES,
    )


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


_ID_LINE = re.compile(rb"(?m)^id:[ \t]*['\"]?([^\s'\"#]+)")


def _load_documents(data: bytes) -> list[object] | None:
    """Parsed YAML documents, or ``None`` when PyYAML or the parse fails."""
    try:
        import yaml  # pylint: disable=import-outside-toplevel
    except ImportError:
        return None
    try:
        return list(yaml.safe_load_all(data))
    except (yaml.YAMLError, ValueError, RecursionError):
        return None


def _walk_matches(node: object, found: set[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "matches" and isinstance(value, str):
                found.add(value)
            _walk_matches(value, found)
    elif isinstance(node, list):
        for item in node:
            _walk_matches(item, found)


def _util_ids_in(data: bytes | None, path: PurePosixPath) -> set[str]:
    """Ids a util is referenced by in one version: its ``id``, else its stem."""
    if data:
        documents = _load_documents(data)
        if documents is not None:
            ids = {
                doc["id"]
                for doc in documents
                if isinstance(doc, dict) and isinstance(doc.get("id"), str)
            }
            if ids:
                return ids
        else:
            found = _ID_LINE.search(data)
            if found:
                return {found.group(1).decode("utf-8", "replace")}
    return {path.stem}


def _util_ids(root: Path, base: str | None, path: PurePosixPath) -> set[str]:
    """Every id a changed util went by: the base and the head version.

    A renamed id keeps its old name so rules still using it are selected (and
    then fail as undefined); a deleted util contributes its base ids only.
    """
    ids: set[str] = set()
    if (root / path).is_file():
        ids |= _util_ids_in((root / path).read_bytes(), path)
    if base:
        previous = _base_blob(root, base, path)
        if previous is not None:
            ids |= _util_ids_in(previous, path)
    return ids or {path.stem}


def _references(path: Path, ids: set[str]) -> bool:
    """Whether the YAML at ``path`` has a ``matches:`` value naming an id.

    Walks the parsed document, so flow mappings, quoting and trailing text are
    all handled. Only when the file cannot be parsed does it fall back to a
    text scan (reported on stderr).
    """
    try:
        data = path.read_bytes()
    except OSError:
        return False
    documents = _load_documents(data)
    if documents is not None:
        found: set[str] = set()
        _walk_matches(documents, found)
        return bool(found & ids)
    print(
        f"validate-changed-rules: cannot parse {path.name}; "
        "using text scan for util references",
        file=sys.stderr,
    )
    text = data.decode("utf-8", errors="replace")
    for util_id in ids:
        quoted = re.escape(util_id)
        if re.search(
            rf"(?:^|[\s{{,\[])['\"]?matches['\"]?[ \t]*:[ \t]*['\"]?{quoted}['\"]?(?![\w.-])",
            text,
            re.MULTILINE,
        ):
            return True
    return False


def util_affected_rules(
    root: Path, base: str | None, paths: Sequence[str]
) -> list[PurePosixPath]:
    """Rules that reference a changed ``utils/**`` file, directly or through
    another util (``matches: <id>``). Returned for validation only: no mirrored
    fixture change is demanded for them. A util nothing references selects
    nothing."""
    ids = set()
    for value in paths:
        path = _safe_path(value)
        if path is not None and path.parts[:1] == ("utils",):
            ids |= _util_ids(root, base, path)
    if not ids:
        return []
    utils = sorted((root / "utils").glob("**/*.yml")) if (root / "utils").is_dir() else []
    grown = True
    while grown:  # a util that matches a changed util is itself changed
        grown = False
        for util in utils:
            own = _util_ids(root, None, PurePosixPath(util.relative_to(root).as_posix()))
            if not own <= ids and _references(util, ids):
                ids |= own
                grown = True
    affected = []
    for language in sorted(SUPPORTED_LANGUAGES):
        for rule in sorted((root / "rules" / language).glob("*/*.yml")):
            if _references(rule, ids):
                affected.append(PurePosixPath(rule.relative_to(root).as_posix()))
    return affected


def _copy_utils(root: Path, isolated: Path) -> None:
    source = root / "utils"
    if not source.is_dir():
        return
    for util in sorted(source.glob("**/*.yml")):
        _require_contained_regular(root, util, "util")
        target = isolated / "utils" / util.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(util, target)


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
        _copy_utils(root, isolated)
        config = isolated / "sgconfig.yml"
        config.write_text(
            "ruleDirs: [rules]\nutilDirs: [utils]\n"
            "testConfigs: [{testDir: tests}]\n",
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


def worker_count(rule_count: int) -> int:
    return max(1, min(os.cpu_count() or 1, MAX_WORKERS, rule_count))


def validate_changed(
    root: Path,
    engine: Path,
    paths: Sequence[str],
    base: str | None = None,
    workers: int | None = None,
) -> int:
    """Validate every changed rule; report all failures in rule order.

    Rules run on a bounded thread pool (each check is an isolated subprocess);
    ``workers=1`` forces serial execution with identical output.
    """
    if base:
        # Metadata-only edits of rules the validator cannot parse are accepted
        # without a load/test (there is no parser); every other path remains.
        skipped = unparseable_metadata_only_changes(root, base, paths)
        paths = [value for value in paths if value not in skipped]
    exempt = (
        header_only_rule_changes(root, base, paths)
        | non_matching_rule_changes(root, base, paths)
        if base
        else frozenset()
    )
    missing = missing_fixture_changes(paths, exempt)
    if missing:
        raise ValidationError(
            "changed rules require changed mirrored fixtures: " + ", ".join(missing)
        )
    selected = {
        *changed_rule_paths(root, paths),
        *util_affected_rules(root, base, paths),
    }
    rules = [
        root / relative
        for relative in sorted(selected, key=PurePosixPath.as_posix)
        # A removed rule and fixture have nothing left to load.
        if (root / relative).is_file()
    ]
    if not rules:
        return 0
    if workers is None:
        workers = worker_count(len(rules))

    def check(rule: Path) -> str | None:
        try:
            validate_rule(root, engine, rule)
        except ValidationError as error:
            return str(error)
        return None

    if workers <= 1:
        outcomes = [check(rule) for rule in rules]
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            outcomes = list(pool.map(check, rules))  # map keeps input order
    failures = []
    for rule, failure in zip(rules, outcomes):
        relative = rule.relative_to(root)
        if failure is None:
            print(f"validated {relative}")
        else:
            failures.append(f"{relative}: {failure}")
    if failures:
        raise ValidationError(
            f"{len(failures)} of {len(rules)} changed rule(s) failed:\n"
            + "\n".join(failures)
        )
    return len(rules)


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
