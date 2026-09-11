"""Contracts for offline harvest inputs, reply gates, and rule scaffolding."""

import contextlib
import importlib.util
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
CI = os.environ.get("CI", "").lower() in ("1", "true", "yes", "on")


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HISTORY = load_tool("harvest-history")
PACKETS = load_tool("harvest-packets")
PROBE = load_tool("rule-probe")
SCAFFOLD = load_tool("rule-scaffold")


@contextlib.contextmanager
def ascii_text_defaults():
    """Exercise implicit encoding/newline behavior independently of the host."""
    original_open = Path.open
    original_temporary = tempfile.NamedTemporaryFile

    def open_path(path, mode="r", buffering=-1, encoding=None, errors=None, newline=None):
        if "b" not in mode and encoding in (None, "locale"):
            encoding = "ascii"
        if "b" not in mode and any(flag in mode for flag in "wax+") and newline is None:
            newline = "\r\n"
        return original_open(path, mode, buffering, encoding, errors, newline)

    def temporary(*args, **kwargs):
        if "b" not in kwargs.get("mode", "w+b"):
            kwargs.setdefault("encoding", "ascii")
            kwargs.setdefault("newline", "\r\n")
        return original_temporary(*args, **kwargs)

    with patch.object(Path, "open", open_path), \
            patch.object(tempfile, "NamedTemporaryFile", temporary):
        yield


@contextlib.contextmanager
def coverage_cases(cases):
    """Provide actual witness JSON without changing the shared JSON decoder."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "tests").mkdir()
        (root / "tests/arm_coverage.json").write_text(
            json.dumps({"cases": cases}), encoding="utf-8")
        with patch.object(PROBE, "ROOT", root):
            yield


def copy_relative_files(root, sources):
    """Copy repository files under the same relative paths in a test root."""
    for source in sources:
        target = root / source.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())


class HistoryTests(unittest.TestCase):
    def test_node_available_for_ci_url_checks(self):
        if CI:
            self.assertIsNotNone(NODE, "Node.js is required for WHATWG URL security checks")

    def test_legacy_url_parser_receives_normalized_fallback(self):
        original = HISTORY.urlsplit
        userinfo = "fixture-user:fixture-password"
        clean_input = "https://" + userinfo + "@example.test/project/commit/"

        def legacy_urlsplit(value):
            if value and ord(value[0]) <= 0x20:
                return original("relative")._replace(path=value)
            return original(value)

        for code in range(0x21):
            with self.subTest(leading_byte=code), \
                    patch.object(HISTORY, "urlsplit", side_effect=legacy_urlsplit) as parser, \
                    patch.object(HISTORY, "run", return_value="/local/repo"):
                raw = chr(code) + clean_input
                self.assertEqual(legacy_urlsplit(raw).netloc, "")
                prefix = HISTORY.commit_url_prefix(ROOT, raw)
                self.assertEqual(prefix, "https://example.test/project/commit/")
                self.assertTrue(parser.call_args.args[0] == clean_input,
                                "parse the normalized input, not raw leading controls")
                candidate = {"short": "abc", "repo": "sample", "subject": "fix",
                             "churn": 1, "density": 1, "signals": [], "url": prefix + "abc"}
                with tempfile.TemporaryDirectory() as directory:
                    index = Path(directory) / "index.md"
                    HISTORY.write_index(index, [candidate])
                    for rendered in (json.dumps(candidate), index.read_text()):
                        self.assertFalse(userinfo in rendered, "legacy parser leaked userinfo")

    @unittest.skipUnless(NODE, "Node.js required for WHATWG URL cross-check")
    def test_nonspecial_opaque_authorities_preserve_encoded_host(self):
        cases = [("custom://host%2fname/commit/", "custom://host%2fname/commit/"),
                 ("custom://host%40name/commit/", "custom://host%40name/commit/"),
                 ("custom://fixture-user:fixture-password@host%2fname/commit/",
                  "custom://host%2fname/commit/")]
        javascript = """
const fs = require('fs');
const u = new URL(JSON.parse(fs.readFileSync(0, 'utf8')));
process.stdout.write(JSON.stringify({
  host: u.hostname, userinfo: Boolean(u.username || u.password)
}));
"""
        for number, (raw, expected) in enumerate(cases):
            with self.subTest(case=number), \
                    patch.object(HISTORY, "run", return_value="/local/repo"):
                prefix = HISTORY.commit_url_prefix(ROOT, raw)
                self.assertEqual(prefix, expected)
                parsed = subprocess.run(["node", "-e", javascript], input=json.dumps(prefix),
                                        capture_output=True, text=True, check=True, timeout=10)
                self.assertEqual(json.loads(parsed.stdout),
                                 {"host": HISTORY.urlsplit(expected).hostname, "userinfo": False})

    @unittest.skipUnless(NODE, "Node.js required for WHATWG URL cross-check")
    def test_file_fallbacks_without_userinfo_are_preserved(self):
        urls = ["file:///tmp/project/", "file:///C:/project/", "file://localhost/tmp/project/"]
        javascript = """
const fs = require('fs');
const urls = JSON.parse(fs.readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(urls.map(raw => {
  const u = new URL(raw);
  return Boolean(u.username || u.password);
})));
"""
        parsed = subprocess.run(["node", "-e", javascript], input=json.dumps(urls),
                                capture_output=True, text=True, check=True, timeout=10)
        self.assertEqual(json.loads(parsed.stdout), [False] * len(urls))
        for raw in urls:
            with self.subTest(raw=raw), patch.object(HISTORY, "run", return_value="/local/repo"):
                self.assertEqual(HISTORY.commit_url_prefix(ROOT, raw), raw)

    def test_rejected_scp_origin_uses_sanitized_fallback(self):
        userinfo = "fixture-user:fixture-password"
        origin = "git@\\:" + userinfo + "@example.test/path.git"
        fallback = "https://" + userinfo + "@fallback.test/project/commit/"
        with patch.object(HISTORY, "run", return_value=origin):
            prefix = HISTORY.commit_url_prefix(ROOT, fallback)
        self.assertEqual(prefix, "https://fallback.test/project/commit/")

    @unittest.skipUnless(NODE, "Node.js required for WHATWG URL cross-check")
    def test_shared_prefix_policy_rejects_ambiguous_authorities(self):
        userinfo = "fixture-user:fixture-password"
        suffix = userinfo + "@example.test/path/"
        fallbacks = [scheme + delimiter + suffix
                     for scheme in ("http", "https", "ftp", "ws", "wss")
                     for delimiter in ("://\\/", ":///", ":\\\\")]
        fallbacks += [delimiter + suffix for delimiter in ("//\\/", "///", "/\\/", "\\\\")]
        fallbacks += ["\x01https://\\/" + suffix, "https:\t//\\/" + suffix]
        javascript = """
const fs = require('fs');
const urls = JSON.parse(fs.readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(urls.map(raw => {
  const u = new URL(raw, 'https://base.test/');
  return {host: u.hostname, userinfo: Boolean(u.username || u.password)};
})));
"""
        parsed = subprocess.run(["node", "-e", javascript], input=json.dumps(fallbacks),
                                capture_output=True, text=True, check=True, timeout=10)
        self.assertEqual(json.loads(parsed.stdout),
                         [{"host": "example.test", "userinfo": True}] * len(fallbacks))
        cases = [("fallback", raw) for raw in fallbacks]
        cases += [("origin", scheme + "://\\/" + suffix.removesuffix("/") + ".git")
                  for scheme in ("http", "https")]
        cases += [("origin", "git@\\:" + suffix.removesuffix("/") + ".git")]
        for case, (source, raw) in enumerate(cases):
            with self.subTest(source=source, case=case), \
                    patch.object(HISTORY, "run", return_value=raw if source == "origin"
                                 else "/local/repo"):
                prefix = HISTORY.commit_url_prefix(ROOT, raw if source == "fallback" else None)
                candidate = {"short": "abc", "repo": "sample", "subject": "fix",
                             "churn": 1, "density": 1, "signals": [],
                             "url": prefix + "abc" if prefix else ""}
                with tempfile.TemporaryDirectory() as directory:
                    index = Path(directory) / "index.md"
                    HISTORY.write_index(index, [candidate])
                    for rendered in (json.dumps(candidate), index.read_text()):
                        self.assertFalse(userinfo in rendered,
                                         "ambiguous authority leaked userinfo")
                self.assertIsNone(prefix)

    def test_shared_prefix_policy_encoded_hosts_and_safe_authorities(self):
        for encoded in ("%2f", "%5c", "%40", "%3a", "%00", "%20"):
            for source in ("fallback", "origin", "network-relative"):
                raw = ("//" if source == "network-relative" else "https://") + encoded + "/path/"
                with self.subTest(encoded=encoded, source=source), \
                        patch.object(HISTORY, "run", return_value=raw if source == "origin"
                                     else "/local/repo"):
                    self.assertIsNone(HISTORY.commit_url_prefix(
                        ROOT, None if source == "origin" else raw))
        valid = ("https://example.test/path/", "http://127.0.0.1:8080/path/",
                 "https://[::1]/path/", "ftp://example.test/path/", "ws://example.test/path/",
                 "wss://example.test/path/", "//example.test/path/", "custom:opaque\\path/",
                 "relative@name/[unclosed", "custom://[unclosed")
        for raw in valid:
            with self.subTest(raw=raw), patch.object(HISTORY, "run", return_value="/local/repo"):
                self.assertEqual(HISTORY.commit_url_prefix(ROOT, raw), raw)
        for raw, expected in (("https://example.test/owner/repo.git",
                               "https://example.test/owner/repo/commit/"),
                              ("git@example.test:owner/repo.git",
                               "https://example.test/owner/repo/commit/")):
            with self.subTest(origin=raw), patch.object(HISTORY, "run", return_value=raw):
                self.assertEqual(HISTORY.commit_url_prefix(ROOT, None), expected)

    def test_authorityless_http_fallbacks_are_not_published(self):
        userinfo = "fixture-user:fixture-password"
        for scheme in ("http", "https"):
            for delimiter in ("///", "////", "\\\\", "/\\", "\\/", "//\\"):
                with self.subTest(scheme=scheme, delimiter=delimiter), \
                        patch.object(HISTORY, "run", return_value="/local/repo"):
                    prefix = HISTORY.commit_url_prefix(
                        ROOT, scheme + ":" + delimiter + userinfo + "@example.test/path/")
                    candidate = {"short": "abc", "repo": "sample", "subject": "fix",
                                 "churn": 1, "density": 1, "signals": [],
                                 "url": prefix + "abc" if prefix else ""}
                    with tempfile.TemporaryDirectory() as directory:
                        index = Path(directory) / "index.md"
                        HISTORY.write_index(index, [candidate])
                        for rendered in (json.dumps(candidate), index.read_text()):
                            self.assertFalse(userinfo in rendered,
                                             "authorityless HTTP userinfo reached output")
                    self.assertIsNone(prefix)
        for fallback in ("https://example.test/path/", "http://localhost:8080/path/",
                         "https://[::1]/path/", "custom:///opaque/path/", "relative/path/",
                         "https://example.test/path\\part/", "custom:opaque\\path/"):
            with self.subTest(fallback=fallback), \
                    patch.object(HISTORY, "run", return_value="/local/repo"):
                self.assertEqual(HISTORY.commit_url_prefix(ROOT, fallback), fallback)

    def test_fallback_http_userinfo_is_not_published(self):
        for scheme in ("http", "https", " http", " https", "\thttp", "\thttps",
                       "\nhttp", "\nhttps", "ssh", "custom", " ssh", "\tcustom", "\nssh"):
            for userinfo in ("fixture-token", "fixture-user:fixture-password"):
                with self.subTest(scheme=scheme, password=":" in userinfo), \
                        patch.object(HISTORY, "run", return_value="/local/repo"):
                    prefix = HISTORY.commit_url_prefix(
                        ROOT, f"{scheme}://{userinfo}@example.test/project/commit/")
                    candidate = {"short": "abc", "repo": "sample", "subject": "fix",
                                 "churn": 1, "density": 1, "signals": [], "url": prefix + "abc"}
                    with tempfile.TemporaryDirectory() as directory:
                        index = Path(directory) / "index.md"
                        HISTORY.write_index(index, [candidate])
                        for rendered in (json.dumps(candidate), index.read_text()):
                            self.assertFalse(userinfo in rendered,
                                             "fallback userinfo reached output")
                    self.assertTrue(prefix == f"{scheme.strip()}://example.test/project/commit/",
                                    "fallback userinfo must not reach published URLs")
        for fallback in ("relative/commit/", "git@example.test:project/commit/",
                         " relative/commit/", "custom://[unclosed", "relative@name/[unclosed"):
            with patch.object(HISTORY, "run", return_value="/local/repo"):
                self.assertEqual(HISTORY.commit_url_prefix(ROOT, fallback), fallback)
        with patch.object(HISTORY, "run", return_value="git@example.test:owner/project.git"):
            self.assertEqual(HISTORY.commit_url_prefix(ROOT, "relative/"),
                             "https://example.test/owner/project/commit/")

    def test_malformed_fallback_userinfo_is_rejected(self):
        schemes = ["ssh://", "custom://", " custom://", "\tssh://", "//"]
        schemes += [scheme + ":" + control + "//" for scheme in ("http", "ssh", "custom")
                    for control in ("\t", "\n", "\r")]
        schemes += ["/" + control + "/" for control in ("\t", "\n", "\r")]
        schemes += [chr(code) + "//" for code in range(0x21)]
        for scheme in schemes:
            with self.subTest(scheme=scheme), \
                    patch.object(HISTORY, "run", return_value="/local/repo"):
                prefix = HISTORY.commit_url_prefix(
                    ROOT, scheme + "fixture-user:fixture-password@[unclosed/path/")
                self.assertTrue(prefix is None, "malformed fallback must not publish userinfo")

    def test_parse_failure_preserves_opaque_fallbacks(self):
        # Current urlsplit accepts these; inject failure to exercise the exception contract.
        fallbacks = ["relative@name/[unclosed", "git@example.test:project/commit/",
                     "relative@name/\t[unclosed", "git@\nexample.test:project/commit/"]
        fallbacks += [chr(code) + "relative@name/[unclosed" for code in range(0x21)]
        for fallback in fallbacks:
            with self.subTest(fallback=fallback), \
                    patch.object(HISTORY, "urlsplit", side_effect=ValueError("parse failure")), \
                    patch.object(HISTORY, "run", return_value="/local/repo"):
                self.assertEqual(HISTORY.commit_url_prefix(ROOT, fallback), fallback)

    def test_per_commit_timeout_emits_partial_corpus_and_fails_cli(self):
        history = "\n".join(char * 40 + "\x1ffix bounds\x1f2026-09-08" for char in "abc")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sample/.git").mkdir(parents=True)
            corpus, index = root / "corpus.jsonl", root / "index.md"
            with patch.object(HISTORY, "commit_url_prefix", return_value=None), \
                    patch.object(HISTORY, "run", return_value=history), \
                    patch.object(HISTORY, "changed_source_files", return_value=[
                        HISTORY.SourceChange("x.c", 1, 1)]), \
                    patch.object(HISTORY, "diff_body", side_effect=(
                        "-old\n+new", subprocess.TimeoutExpired(["git", "show"], 60),
                        "-old\n+new")), \
                    patch.object(HISTORY, "cosmetic_commit", return_value=False), \
                    patch.object(HISTORY, "dedupe_by_patch_id", side_effect=lambda _, rows: rows), \
                    patch("sys.argv", ["harvest", "--root", str(root), "--repos", "sample",
                                       "--out", str(corpus), "--index", str(index)]), \
                    contextlib.redirect_stderr(io.StringIO()) as stderr:
                result = HISTORY.main()
            rows = [json.loads(line) for line in corpus.read_text().splitlines()]
            self.assertEqual([row["sha"] for row in rows], ["a" * 40, "c" * 40])
            self.assertIn("a" * 12, index.read_text())
            self.assertIn("c" * 12, index.read_text())
            self.assertRegex(stderr.getvalue(), r"timed-out-commits=\s*1")
            self.assertIn("skip sample:" + "b" * 40, stderr.getvalue())
            self.assertEqual(result, 1)
            self.assertIn("incomplete harvest", stderr.getvalue())

    def test_dedupe_sha_aliases_preserve_first_repo_and_packet_uniqueness(self):
        for order in (("fast", "slow"), ("slow", "fast"), ("fast", "alias", "slow")):
            with self.subTest(order=order):
                candidates = [{"repo": repo,
                               "sha": ("a" if repo == "fast" and len(order) == 3
                                       else "b") * 40,
                               "short": ("a" if repo == "fast" and len(order) == 3
                                         else "b") * 12,
                               "subject": "fix bounds", "files": ["x.c"],
                               "diff": "-old\n+new"} for repo in order]

                def patch_id(command, **_kwargs):
                    return subprocess.CompletedProcess(command, 0, b"same-patch\n")

                with patch.object(HISTORY.subprocess, "run", side_effect=patch_id), \
                        contextlib.redirect_stderr(io.StringIO()):
                    result = HISTORY.dedupe_by_patch_id(ROOT, candidates)
                self.assertEqual(len(result), 1)
                self.assertIs(result[0], candidates[0])
                self.assertEqual(result[0]["repo"], order[0])
                self.assertEqual(result[0]["also_in"], list(order[1:]))
                packets = PACKETS.label_packets(result)
                self.assertEqual(len(packets), 1)
                self.assertEqual(next(iter(packets.values()))["repo"], order[0])

    def test_dedupe_timeouts_preserve_candidates_with_sha_identity(self):
        candidates = [{"repo": repo, "sha": sha * 40, "language": "c", "diff": repo}
                      for repo, sha in (("first", "a"), ("slow", "b"),
                                        ("last", "c"), ("fork", "b"))]

        def patch_id(command, **kwargs):
            if kwargs["input"] == b"slow":
                raise subprocess.TimeoutExpired(command, 60)
            return subprocess.CompletedProcess(command, 0, kwargs["input"] + b"\n")

        with patch.object(HISTORY.subprocess, "run", side_effect=patch_id), \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            result = HISTORY.dedupe_by_patch_id(ROOT, candidates)
        self.assertEqual([row["repo"] for row in result], ["first", "slow", "last"])
        self.assertIs(result[1], candidates[1])
        self.assertEqual(result[1]["also_in"], ["fork"])
        self.assertIn("using SHA fallback", stderr.getvalue())
        # The fork's known SHA bypasses a second identity lookup and timeout.
        self.assertIn("timed-out-candidates=1", stderr.getvalue())

    def test_dedupe_keeps_identical_patches_for_different_languages(self):
        candidates = [
            {"repo": "mixed", "sha": "a" * 40, "language": language,
             "diff": "-old\n+new"}
            for language in ("c", "go")
        ]
        completed = subprocess.CompletedProcess(
            ["git", "patch-id", "--stable"], 0, b"same-patch\n")
        with patch.object(HISTORY.subprocess, "run", return_value=completed):
            self.assertEqual(HISTORY.dedupe_by_patch_id(ROOT, candidates), candidates)

    def test_history_listing_timeout_reports_incomplete_corpus(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("first", "slow", "last"):
                (root / name / ".git").mkdir(parents=True)

            def history(repo, *_args):
                if repo.name == "slow":
                    raise subprocess.TimeoutExpired(["git", "log"], 60)
                sha = "a" * 40 if repo.name == "first" else "c" * 40
                return sha + "\x1ffix bounds\x1f2026-09-08"

            with patch.object(HISTORY, "commit_url_prefix", return_value=None), \
                    patch.object(HISTORY, "run", side_effect=history), \
                    patch.object(HISTORY, "changed_source_files", return_value=[
                        HISTORY.SourceChange("x.c", 1, 1)]), \
                    patch.object(HISTORY, "diff_body", return_value="-old\n+new"), \
                    patch.object(HISTORY, "cosmetic_commit", return_value=False), \
                    patch.object(HISTORY, "dedupe_by_patch_id", side_effect=lambda _, rows: rows), \
                    patch("sys.argv", ["harvest", "--root", str(root), "--repos",
                                       "first", "slow", "last"]), \
                    contextlib.redirect_stdout(io.StringIO()) as stdout, \
                    contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(HISTORY.main(), 1)
            self.assertEqual([json.loads(line)["repo"]
                              for line in stdout.getvalue().splitlines()], ["first", "last"])
            self.assertIn("incomplete harvest", stderr.getvalue())
            self.assertIn("incomplete-repos=1", stderr.getvalue())
            self.assertIn("skip slow", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_per_commit_timeouts_preserve_same_repo_neighbors(self):
        history = "\n".join(char * 40 + "\x1ffix bounds\x1f2026-09-08" for char in "abc")
        for phase in ("source-files", "diff", "file-content"):
            with self.subTest(phase=phase):
                def source_files(_repo, sha, target=phase):
                    if sha == "b" * 40 and target == "source-files":
                        raise subprocess.TimeoutExpired(["git", "show", "--numstat"], 60)
                    return [HISTORY.SourceChange("x.c", 1, 1)]

                def diff(_repo, sha, _paths, target=phase):
                    if sha == "b" * 40 and target == "diff":
                        raise subprocess.TimeoutExpired(["git", "show"], 60)
                    return "-old\n+new"

                def cosmetic(_repo, sha, _changes, target=phase):
                    if sha == "b" * 40 and target == "file-content":
                        raise subprocess.TimeoutExpired(["git", "show", "revision:x.c"], 60)
                    return False

                with patch.object(HISTORY, "commit_url_prefix", return_value=None), \
                        patch.object(HISTORY, "run", return_value=history), \
                        patch.object(HISTORY, "changed_source_files", side_effect=source_files), \
                        patch.object(HISTORY, "diff_body", side_effect=diff), \
                        patch.object(HISTORY, "cosmetic_commit", side_effect=cosmetic), \
                        contextlib.redirect_stderr(io.StringIO()) as stderr:
                    rows, timed_out = HISTORY.harvest(ROOT, "sample", 3, 60, None)
                self.assertEqual(timed_out, 1)
                self.assertEqual([row["sha"] for row in rows], ["a" * 40, "c" * 40])
                self.assertRegex(stderr.getvalue(), r"timed-out-commits=\s*1")
                self.assertIn("skip sample:" + "b" * 40, stderr.getvalue())

    def test_timeouts_retain_candidates_and_report_incomplete_repos(self):
        for phase in ("harvest", "patch-id"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name in ("first", "slow", "last"):
                    (root / name / ".git").mkdir(parents=True)

                def harvest(_repo, name, *_args, target=phase):
                    if name == "slow" and target == "harvest":
                        raise subprocess.TimeoutExpired(["git", "log"], 60)
                    return [{"repo": name, "sha": name, "short": name,
                             "subject": "fix", "date": "2026-09-11", "language": "c",
                             "files": ["x.c"], "url": "", "diff": name,
                             "signals": [], "churn": 1}], 0

                def patch_id(command, *, target=phase, **kwargs):
                    if kwargs["input"] == b"slow" and target == "patch-id":
                        raise subprocess.TimeoutExpired(command, 60)
                    return subprocess.CompletedProcess(command, 0, kwargs["input"] + b"\n")

                with patch.object(HISTORY, "harvest", side_effect=harvest), \
                        patch.object(HISTORY.subprocess, "run", side_effect=patch_id), \
                        patch("sys.argv", ["harvest", "--root", str(root), "--repos",
                                           "first", "slow", "last"]), \
                        contextlib.redirect_stdout(io.StringIO()) as stdout, \
                        contextlib.redirect_stderr(io.StringIO()) as stderr:
                    self.assertEqual(HISTORY.main(), int(phase == "harvest"))
                self.assertEqual([json.loads(line)["repo"]
                                  for line in stdout.getvalue().splitlines()],
                                 ["first", "last"] if phase == "harvest"
                                 else ["first", "slow", "last"])
                status = ("incomplete-repos=1" if phase == "harvest"
                          else "timed-out-candidates=1")
                self.assertIn(status, stderr.getvalue())
                self.assertIn("skip slow" if phase == "harvest" else "retain slow",
                              stderr.getvalue())
                self.assertNotIn("Traceback", stderr.getvalue())

    def test_output_stages_preserve_legacy_subject_bytes(self):
        raw_subject = "fix café ".encode() + b"\xff"
        candidate = {"short": "abc", "sha": "a" * 40, "repo": "sample",
                     "subject": raw_subject.decode("utf-8", "surrogateescape"),
                     "churn": 1, "signals": [], "url": "", "diff": "+new\udcfe\n",
                     "language": "c", "files": ["x.c"]}
        for file_output in (False, True):
            with self.subTest(file_output=file_output), \
                    tempfile.TemporaryDirectory() as directory, \
                    io.TextIOWrapper(io.BytesIO(), encoding="ascii", errors="strict") as stdout:
                root = Path(directory)
                (root / "sample/.git").mkdir(parents=True)
                index, output = root / "index.md", root / "corpus.jsonl"
                argv = ["harvest", "--root", str(root), "--repos", "sample", "--index", str(index)]
                if file_output:
                    argv += ["--out", str(output)]
                with patch.object(HISTORY, "harvest", return_value=([dict(candidate)], 0)), \
                        patch.object(HISTORY, "dedupe_by_patch_id",
                                     side_effect=lambda _, rows: rows), \
                        patch("sys.argv", argv), ascii_text_defaults(), \
                        contextlib.redirect_stdout(stdout), \
                        contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(UnicodeEncodeError):
                        stdout.write("☃")
                    self.assertEqual(HISTORY.main(), 0)
                stdout.flush()
                payload = (output.read_bytes().decode("ascii") if file_output
                           else stdout.buffer.getvalue().decode("ascii"))
                row = json.loads(payload)
                self.assertEqual(row["subject"].encode("utf-8", "surrogateescape"), raw_subject)
                self.assertEqual(row["diff"], candidate["diff"])
                self.assertIn(raw_subject, index.read_bytes())
                if file_output:
                    args = SimpleNamespace(work=root / "packets", corpus=output,
                                           chunk=12, min_size=1, mechanical=True)
                    with patch.object(PACKETS, "shipped_rules", return_value=[]), \
                            patch.object(PACKETS, "rejected_entries", return_value=[]), \
                            contextlib.redirect_stderr(io.StringIO()):
                        self.assertEqual(PACKETS.cluster_emit(args), 0)
                    metrics = json.loads(
                        (args.work / "sift-metrics.json").read_text())
                    self.assertEqual(metrics["raw_diff_bytes"], len(b"+new\xfe\n"))

    def test_git_subprocesses_have_bounded_timeouts(self):
        def timeout(command, **kwargs):
            self.assertGreater(kwargs.get("timeout", 0), 0, "Git invocation must be bounded")
            self.assertLessEqual(kwargs["timeout"], 60)
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])

        with self.subTest(command="git"), \
                patch.object(HISTORY.subprocess, "run", side_effect=timeout), \
                self.assertRaises(subprocess.TimeoutExpired):
            HISTORY.run(ROOT, "log")
        with self.subTest(command="patch-id"), \
                patch.object(HISTORY, "run", return_value="diff"), \
                patch.object(HISTORY.subprocess, "run", side_effect=timeout), \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(HISTORY.dedupe_by_patch_id(
                ROOT, [{"repo": "sample", "sha": "a" * 40, "diff": "diff"}]),
                [{"repo": "sample", "sha": "a" * 40, "diff": "diff"}])
            self.assertIn("timed-out-candidates=1", stderr.getvalue())

    def test_unattributable_commit_does_not_abort_other_commits_or_repos(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("first", "second"):
                (root / name / ".git").mkdir(parents=True)

            def log(repo, *_args):
                shas = ("a" * 40, "b" * 40) if repo.name == "first" else ("c" * 40,)
                return "\n".join(sha + "\x1ffix bounds\x1f2026-09-08" for sha in shas)

            with patch.object(HISTORY, "run", side_effect=log), \
                    patch.object(HISTORY, "commit_url_prefix", return_value=None), \
                    patch.object(HISTORY, "changed_source_files", return_value=[
                        HISTORY.SourceChange("x.c", 1, 1)]), \
                    patch.object(HISTORY, "cosmetic_commit", return_value=False), \
                    patch.object(HISTORY, "diff_body", side_effect=("", "-a\n+b", "-b\n+c")), \
                    patch.object(HISTORY, "dedupe_by_patch_id", side_effect=lambda _, rows: rows), \
                    patch("sys.argv", ["harvest", "--root", str(root),
                                       "--repos", "first", "second"]), \
                    contextlib.redirect_stdout(io.StringIO()) as stdout, \
                    contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(HISTORY.main(), 0)
            rows = [json.loads(line) for line in stdout.getvalue().splitlines()]
            self.assertEqual([(row["repo"], row["sha"]) for row in rows],
                             [("first", "b" * 40), ("second", "c" * 40)])
            self.assertRegex(stderr.getvalue(), r"no-diff-skipped=\s*1")

    def test_origin_userinfo_never_reaches_published_urls(self):
        # Inert markers exercise URL credential forms; assertions never print them.
        for userinfo in ("fixture-token", "fixture-user:fixture-password",
                         "fixture-user:fixture%40password", ":fixture-password"):
            with self.subTest(form="password" if ":" in userinfo else "token"):
                with patch.object(HISTORY, "run", return_value=(
                        "https://" + userinfo + "@example.test/owner/project.git")):
                    prefix = HISTORY.commit_url_prefix(ROOT, None)
                candidate = {"short": "abc", "repo": "sample", "subject": "fix",
                             "churn": 1, "density": 1, "signals": [], "url": prefix + "abc"}
                with tempfile.TemporaryDirectory() as directory:
                    index = Path(directory) / "index.md"
                    HISTORY.write_index(index, [candidate])
                    for rendered in (json.dumps(candidate), index.read_text()):
                        self.assertFalse(userinfo in rendered, "origin userinfo reached output")
                        self.assertTrue(
                            "https://example.test/owner/project/commit/abc" in rendered,
                            "published commit URL must use only host and repository path")

    def test_blank_line_changes_preserve_line_sensitive_semantics(self):
        for source in ("int line = __LINE__;\n", "#define SITE __LINE__\nint line = SITE;\n",
                       "int line = __builtin_LINE();\n", "int line = EXTERNAL_LINE_MACRO;\n"):
            with self.subTest(source=source):
                self.assertFalse(HISTORY.is_cosmetic(source, "\n" + source))
        # Moving a blank line keeps the line count but still changes __LINE__.
        self.assertFalse(HISTORY.is_cosmetic("\nint line = __LINE__;\nint x;\n",
                                             "int line = __LINE__;\n\nint x;\n"))
        self.assertTrue(HISTORY.is_cosmetic(" int line = __LINE__;\n", "\tint line = __LINE__;\n"))

    def test_diff_paths_are_literal_git_filenames(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args, source=None):
                return subprocess.run(["git", "-C", str(root), *args], input=source,
                                      capture_output=True, check=True, timeout=10).stdout.decode()

            git("init", "-q")
            for name, value in ((":odd.c", "colon"), ("glob[1].c", "bracket"),
                                ("glob1.c", "decoy")):
                blob = git("hash-object", "-w", "--stdin",
                           source=f"int {value} = 1;\n".encode()).strip()
                git("update-index", "--add", "--cacheinfo", f"100644,{blob},{name}")
            tree = git("write-tree").strip()
            # An inert object fixture exercises git-show without creating a branch/ref.
            commit = git("hash-object", "-t", "commit", "-w", "--stdin", source=(
                f"tree {tree}\nauthor Test <test@example.test> 0 +0000\n"
                "committer Test <test@example.test> 0 +0000\n\nfixture\n").encode()).strip()
            nested = root / "nested"
            nested.mkdir()
            for repo in (root, nested):
                for name, wanted, excluded in ((":odd.c", "colon", "bracket"),
                                                ("glob[1].c", "bracket", "decoy")):
                    with self.subTest(repo=repo, path=name):
                        diff = HISTORY.diff_body(repo, commit, [name])
                        self.assertIn(f"int {wanted} = 1;", diff)
                        self.assertNotIn(f"int {excluded} = 1;", diff)

    def test_non_utf8_diff_preserves_bytes_and_patch_identity(self):
        raw = b"diff --git a/x.c b/x.c\n--- a/x.c\n+++ b/x.c\n@@ -1 +1 @@\n-old\xff\n+new\xfe\n"
        with patch.object(HISTORY.subprocess, "run", return_value=SimpleNamespace(stdout=raw)):
            diff = HISTORY.diff_body(ROOT, "HEAD", ["x.c"])
        self.assertEqual(diff.encode("utf-8", "surrogateescape"), raw)
        self.assertEqual(json.loads(json.dumps(diff)), diff)
        real_run = subprocess.run
        expected = real_run(["git", "patch-id", "--stable"], input=raw,
                            capture_output=True, check=True).stdout
        with patch.object(HISTORY, "run", return_value=diff), \
                patch.object(HISTORY.subprocess, "run", wraps=real_run) as runner:
            candidate = {"repo": "sample", "sha": "a" * 40, "diff": diff}
            self.assertEqual(HISTORY.dedupe_by_patch_id(ROOT, [candidate]), [candidate])
        self.assertEqual(runner.call_args.kwargs["input"], raw)
        self.assertTrue(expected.strip(), "control patch must have a real patch-id")

    def test_source_filter_excludes_binary_tests_and_docs(self):
        numstat = "1\t1\tmain.go\0" "2\t0\tmain_test.go\0-\t-\timage.c\0" "1\t0\tREADME.md\0"
        with patch.object(HISTORY, "run", return_value=numstat):
            self.assertEqual(HISTORY.changed_source_files(ROOT, "HEAD"),
                             [HISTORY.SourceChange("main.go", 1, 1)])

    def test_source_filter_accepts_every_native_rule_language(self):
        paths = ("main.sh", "main.c", "main.go", "Main.java", "main.js", "main.lua",
                 "main.php", "main.py")
        numstat = "".join(f"1\t0\t{path}\0" for path in (*paths, "main.rs"))
        with patch.object(HISTORY, "run", return_value=numstat):
            changes = HISTORY.changed_source_files(ROOT, "HEAD")
        self.assertEqual([change.path for change in changes], list(paths))

    def test_source_filter_rejects_uppercase_c_as_cpp(self):
        with patch.object(HISTORY, "run", return_value="1\t0\tmain.C\0"):
            self.assertEqual(HISTORY.changed_source_files(ROOT, "HEAD"), [])

    def test_source_filter_rejects_cross_language_renames(self):
        numstat = ("1\t1\t\0old.go\0new.py\0"
                   "1\t1\t\0old.go\0new.go\0")
        with patch.object(HISTORY, "run", return_value=numstat):
            self.assertEqual(HISTORY.changed_source_files(ROOT, "HEAD"), [
                HISTORY.SourceChange("new.go", 1, 1, "old.go")])

    def test_harvest_splits_a_mixed_language_commit(self):
        sha = "a" * 40
        changes = [HISTORY.SourceChange("main.go", 2, 1),
                   HISTORY.SourceChange("helper.py", 1, 1)]

        def diff(_repo, _sha, paths):
            return f"diff --git a/{paths[0]} b/{paths[0]}\n@@ -1 +1 @@\n-old\n+new\n"

        with patch.object(HISTORY, "commit_url_prefix", return_value=None), \
                patch.object(HISTORY, "run",
                             return_value=f"{sha}\x1ffix mixed bug\x1f2026-09-11"), \
                patch.object(HISTORY, "changed_source_files", return_value=changes), \
                patch.object(HISTORY, "diff_body", side_effect=diff), \
                patch.object(HISTORY, "cosmetic_commit", return_value=False), \
                contextlib.redirect_stderr(io.StringIO()):
            rows, incomplete = HISTORY.harvest(ROOT, "sample", 3, 60, None)
        self.assertEqual(incomplete, 0)
        self.assertEqual([row["language"] for row in rows], ["go", "python"])
        self.assertEqual([row["files"] for row in rows], [["main.go"], ["helper.py"]])
        self.assertEqual([row["short"] for row in rows],
                         [f"{sha[:12]}-go", f"{sha[:12]}-python"])

    def test_truncated_rename_numstat_is_an_explicit_error(self):
        prefix = "1\t0\tvalid.go\0"
        for numstat in (prefix + "1\t1\t\0", prefix + "1\t1\t\0old.c\0"):
            with self.subTest(numstat=numstat), \
                    patch.object(HISTORY, "run", return_value=numstat), \
                    self.assertRaisesRegex(HISTORY.TruncatedGitOutput,
                                           "truncated rename numstat for HEAD"):
                HISTORY.changed_source_files(ROOT, "HEAD")

    def test_truncated_numstat_skips_only_affected_commit_and_marks_incomplete(self):
        history = "\n".join(char * 40 + "\x1ffix bounds\x1f2026-09-08" for char in "abc")

        def source_files(_repo, sha):
            if sha == "b" * 40:
                raise HISTORY.TruncatedGitOutput("truncated rename numstat")
            return [HISTORY.SourceChange("valid.go", 1, 0)]

        with patch.object(HISTORY, "commit_url_prefix", return_value=None), \
                patch.object(HISTORY, "run", return_value=history), \
                patch.object(HISTORY, "changed_source_files", side_effect=source_files), \
                patch.object(HISTORY, "diff_body", return_value="-old\n+new"), \
                patch.object(HISTORY, "cosmetic_commit", return_value=False), \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            rows, incomplete = HISTORY.harvest(ROOT, "sample", 3, 60, None)
        self.assertEqual([row["sha"] for row in rows], ["a" * 40, "c" * 40])
        self.assertEqual(incomplete, 1)
        self.assertIn("malformed-commits=  1", errors.getvalue())

    def test_cosmetic_boundary(self):
        self.assertTrue(HISTORY.is_cosmetic("  x = 1\n", "\tx = 1\n"))
        self.assertFalse(HISTORY.is_cosmetic("// old\nx = 1", "// revised\nx = 1"))
        for before, after in (("*p = 1;", "*p = 2;"), ("int x;", "intx;"),
                              ('x = "a b";', 'x = "ab";'),
                              ("first();\nsecond();", "second();\nfirst();"),
                              ("a > > b", "a >> b"), ("x\r\n", "x\n"),
                              ("#define X \\\n  x", "#define X \\\n x")):
            with self.subTest(before=before):
                self.assertFalse(HISTORY.is_cosmetic(before, after))

    def test_raw_string_context_far_outside_changed_lines_is_retained(self):
        before = 'value := `\n' + 'unchanged\n' * 20 + '  // literal\n`'
        after = before.replace('  // literal', ' // literal')
        self.assertFalse(HISTORY.is_cosmetic(before, after))

    def test_pool_vocabulary(self):
        for spelling in ("sync.Pool{}", "p.Reset()", "p.Put(x)", "newTransaction()"):
            with self.subTest(spelling=spelling):
                self.assertIn("pool-reuse", HISTORY.signal_terms(spelling, "fix"))

    def test_directive_comments_and_indentation_are_retained(self):
        for directive in ("//go:build linux", "// +build linux", "//line source.go:5"):
            before = directive + "\n\npackage x\n"
            self.assertFalse(HISTORY.is_cosmetic(before, before.replace("linux", "windows")))
            self.assertFalse(HISTORY.is_cosmetic(before, " " + before))

    def test_rename_uses_real_paths_and_preserves_small_edit_churn(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args, source=None):
                return subprocess.run(["git", "-C", str(root), *args], input=source,
                    capture_output=True, check=True, timeout=10).stdout.decode()

            git("init", "-q")
            original = "".join(f"int value_{index} = {index};\n" for index in range(100))
            blob = git("hash-object", "-w", "--stdin", source=original.encode()).strip()
            git("update-index", "--add", "--cacheinfo", f"100644,{blob},old.c")
            tree = git("write-tree").strip()
            git("update-index", "--force-remove", "old.c")
            edited = original.replace("value_99 = 99", "value_99 = 100")
            blob = git("hash-object", "-w", "--stdin", source=edited.encode()).strip()
            target = "new\tname.c"
            git("update-index", "--add", "--cacheinfo", f"100644,{blob},{target}")
            numstat = git("diff", "--cached", "--find-renames", "--numstat", "-z", tree)
            with patch.object(HISTORY, "run", return_value=numstat):
                changes = HISTORY.changed_source_files(root, "unused")
            self.assertEqual(len(changes), 1)
            self.assertEqual(changes, [HISTORY.SourceChange(target, 1, 1, "old.c")])
            diff = git("diff", "--cached", "--find-renames", tree, "--", "old.c", target)
            self.assertIn("-int value_99 = 99;", diff)
            self.assertIn("+int value_99 = 100;", diff)
            self.assertLess(sum(change.added + change.deleted for change in changes), 60)
            self.assertFalse(HISTORY.cosmetic_commit(root, "unused", changes))

    def test_subject_with_separator_keeps_subject_and_date(self):
        record = "a" * 40 + "\x1ffix: a\x1fb\x1f2026-09-07 12:00:00 +0200"
        with patch.object(HISTORY, "run", return_value=record), \
                patch.object(HISTORY, "commit_url_prefix", return_value=None), \
                patch.object(HISTORY, "changed_source_files",
                             return_value=[HISTORY.SourceChange("x.c", 1, 1)]), \
                patch.object(HISTORY, "diff_body", return_value="-x\n+y"), \
                patch.object(HISTORY, "cosmetic_commit", return_value=False), \
                contextlib.redirect_stderr(io.StringIO()):
            rows, timed_out = HISTORY.harvest(ROOT, "sample", 3, 60, None)
        self.assertEqual(timed_out, 0)
        self.assertEqual(rows[0]["subject"], "fix: a\x1fb")
        self.assertEqual(rows[0]["date"], "2026-09-07")

    def test_origin_url_and_missing_origin(self):
        for origin in ("git@github.com:example/project.git", "https://github.com/example/project.git"):
            with self.subTest(origin=origin), patch.object(HISTORY, "run", return_value=origin):
                self.assertEqual(HISTORY.commit_url_prefix(ROOT, None),
                                 "https://github.com/example/project/commit/")
        with patch.object(HISTORY, "run", side_effect=subprocess.CalledProcessError(2, "git")):
            self.assertEqual(HISTORY.commit_url_prefix(ROOT, "fallback/"), "fallback/")


class ReplyTests(unittest.TestCase):
    def test_changed_excerpt_drops_context_and_classifies_edit_shape(self):
        rewrite = ("diff --git a/x.go b/x.go\n@@ -1,3 +1,3 @@\n context\n"
                   "-oldCall(value)\n+newCall(value)\n context two\n")
        excerpt = PACKETS.changed_excerpt(rewrite)
        self.assertIn("diff --git", excerpt)
        self.assertIn("@@ ", excerpt)
        self.assertIn("-oldCall", excerpt)
        self.assertIn("context two", excerpt)
        self.assertEqual(PACKETS.edit_kind(rewrite), "rewrite")
        insertion = "--- a/x.go\n+++ b/x.go\n@@ -1 +1,2 @@\n+guard()\n"
        self.assertEqual(PACKETS.edit_kind(insertion), "insert")
        self.assertEqual(PACKETS.edit_kind("@@ -1 +0,0 @@\n-bad()\n"), "delete")
        self.assertEqual(PACKETS.edit_kind("diff --git a/x.go b/x.go\n"), "empty")

    def test_changed_excerpt_distinguishes_headers_from_operator_edits(self):
        diff = ("diff --git a/x.c b/x.c\n--- a/x.c\n+++ b/x.c\n"
                "@@ -1,2 +1,2 @@\n--- counter;\n+++ counter;\n")
        excerpt = PACKETS.changed_excerpt(diff)
        self.assertNotIn("--- a/x.c", excerpt)
        self.assertNotIn("+++ b/x.c", excerpt)
        self.assertIn("--- counter;", excerpt)
        self.assertIn("+++ counter;", excerpt)
        self.assertEqual(PACKETS.edit_kind(diff), "rewrite")

    def test_mechanical_cluster_skips_labels_and_bounds_candidate_context(self):
        with tempfile.TemporaryDirectory() as directory, \
                contextlib.redirect_stderr(io.StringIO()):
            root = Path(directory)
            args = SimpleNamespace(work=root, corpus=root / "corpus.jsonl", chunk=12,
                                   min_size=1, mechanical=True)
            corpus = [
                {"short": "rewrite", "repo": "sample", "subject": "fix index",
                 "files": ["x.go"], "diff": "@@ -1,2 +1,2 @@\n keep\n-x[i]\n+x[0]\n",
                 "signals": ["bounds"], "density": 3, "url": ""},
                {"short": "insert", "repo": "sample", "subject": "add guard",
                 "files": ["x.go"], "diff": "@@ -1 +1,2 @@\n keep\n+if ok {}\n",
                 "signals": [], "density": 2, "url": ""},
            ]
            PACKETS.write_jsonl(args.corpus, corpus)
            prior = [{"id": f"go-index-{i}", "message": "index guard"} for i in range(20)]
            with patch.object(PACKETS, "shipped_rules", return_value=prior), \
                    patch.object(PACKETS, "rejected_entries", return_value=[]):
                self.assertEqual(PACKETS.cluster_emit(args), 0)
            packets = [json.loads(path.read_text())
                       for path in sorted((root / "cluster/packets").glob("*.json"))]
            routed = [candidate["short"] for packet in packets
                      for candidate in packet["candidates"]]
            self.assertEqual(sorted(routed), ["insert", "rewrite"])
            self.assertEqual({packet["class"] for packet in packets},
                             {"general-insert", "bounds-rewrite"})
            self.assertFalse((root / "label").exists())
            self.assertTrue((root / "sift.tsv").exists())
            by_kind = {packet["class"]: packet for packet in packets}
            rewrite = by_kind["bounds-rewrite"]
            insert = by_kind["general-insert"]
            self.assertEqual(rewrite["route"], "cheap-model")
            self.assertEqual(insert["route"], "semantic-model")
            self.assertEqual(rewrite["candidates"][0]["route_reason"], "simple-rewrite")
            self.assertEqual(insert["candidates"][0]["route_reason"], "edit-insert")
            self.assertIn(" keep", rewrite["candidates"][0]["diff"])
            self.assertLessEqual(len(rewrite["shipped_rules"]), PACKETS.RELATED_LIMIT)
            metrics = json.loads((root / "sift-metrics.json").read_text())
            self.assertEqual(metrics["candidates"], 2)
            self.assertEqual(metrics["cheap_model"], 1)
            self.assertEqual(metrics["semantic_model"], 1)
            self.assertEqual(metrics["semantic_diff_truncated"], 0)
            self.assertEqual(metrics["route_reasons"],
                             {"edit-insert": 1, "simple-rewrite": 1})
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(PACKETS.queue(SimpleNamespace(
                    work=root, route="all", limit=1, json=True)), 0)
            queued = json.loads(output.getvalue())
            self.assertEqual(len(queued["tasks"]), 1)
            self.assertEqual(queued["remaining"], 1)
            self.assertTrue(queued["tasks"][0]["packet"].endswith(".json"))

    def test_semantic_packet_defers_fuller_diff_and_binds_evidence(self):
        with tempfile.TemporaryDirectory() as directory, \
                contextlib.redirect_stderr(io.StringIO()):
            work = Path(directory)
            corpus_path = work / "corpus.jsonl"
            diff = "@@ -1 +1 @@\n-old()\n+new()\n" + "far context\n" * 300
            candidate = {"short": "abc", "repo": "sample", "subject": "fix logic",
                         "language": "go", "files": ["x.go"], "diff": diff,
                         "signals": [], "density": 1, "url": ""}
            PACKETS.write_jsonl(corpus_path, [candidate])
            args = SimpleNamespace(work=work, corpus=corpus_path, chunk=12,
                                   min_size=1, mechanical=True)
            with patch.object(PACKETS, "shipped_rules", return_value=[]), \
                    patch.object(PACKETS, "rejected_entries", return_value=[]):
                self.assertEqual(PACKETS.cluster_emit(args), 0)
            packet_path = next((work / "cluster/packets").glob("*.json"))
            packet = json.loads(packet_path.read_text())
            self.assertEqual(packet_path.read_bytes(),
                             PACKETS.packet_text(packet).encode("utf-8"))
            rendered = packet["candidates"][0]
            self.assertLess(rendered["diff"].count("far context"), 300)
            evidence_path = work / rendered["evidence"]
            self.assertIn("far context", json.loads(evidence_path.read_text())["diff"])
            metrics = json.loads((work / "sift-metrics.json").read_text())
            self.assertEqual(metrics["on_demand_evidence"], 1)
            self.assertGreater(metrics["deferred_diff_bytes"], 0)
            packet_bytes = sum(path.stat().st_size
                               for path in (work / "cluster/packets").glob("*.json"))
            prompt_bytes = (work / "cluster/PROMPT.md").stat().st_size
            self.assertEqual(metrics["packet_bytes"], packet_bytes)
            self.assertEqual(metrics["prompt_bytes"], prompt_bytes)
            self.assertEqual(metrics["dispatch_input_bytes"], packet_bytes + prompt_bytes)
            evidence_path.write_text("{}", encoding="utf-8")
            self.assertIsNone(PACKETS.cluster_manifest(work / "cluster"))

    def test_native_languages_and_repository_id_prefixes_are_consistent(self):
        cases = {
            "bash": ("x.sh", "sh-test-rule"), "c": ("x.c", "nginx-test-rule"),
            "go": ("x.go", "go-test-rule"), "java": ("X.java", "java-test-rule"),
            "javascript": ("x.js", "js-test-rule"), "lua": ("x.lua", "lua-test-rule"),
            "php": ("x.php", "wp-test-rule"), "python": ("x.py", "py-test-rule"),
        }
        for language, (filename, rule_id) in cases.items():
            with self.subTest(language=language):
                candidate = {"files": [filename], "language": language}
                self.assertEqual(PACKETS.language_of(candidate), language)
                proposal = {"id": rule_id, "language": language, "claim": "claim",
                            "classification": "syntactic", "positive": "bad()",
                            "near_miss": "good()", "rationale": "reason",
                            "supporting": ["abc"], "overlaps": []}
                self.assertIsNone(PACKETS.validate_proposal(proposal, {"abc"}))
        with self.assertRaisesRegex(SystemExit, "unsupported"):
            PACKETS.language_of({"files": ["source.C"]})

    def test_mechanical_route_escalates_ambiguous_context_and_keeps_fuller_diff(self):
        base = {"short": "abc", "repo": "sample", "subject": "fix bounds",
                "files": ["x.go"], "signals": ["bounds"], "density": 1, "url": ""}
        simple_diff = "diff --git a/x.go b/x.go\n@@ -1 +1 @@\n-old()\n+new()\n"
        cases = (
            ("simple", {}, "cheap-model", "simple-rewrite"),
            ("function-context", {"diff":
             "diff --git a/x.go b/x.go\n@@ -1 +1 @@ func f()\n-old()\n+new()\n"},
             "cheap-model", "simple-rewrite"),
            ("general", {"signals": []}, "semantic-model", "unrecognized-signal"),
            ("multi", {"files": ["x.go", "y.go"]}, "semantic-model", "multi-file"),
            ("hunks", {"diff": simple_diff + "@@ -3 +3 @@\n-a()\n+b()\n@@ -5 +5 @@\n-c()\n+d()\n"},
             "semantic-model", "complex-hunks"),
            ("truncated", {"diff": "@@ -1 +1 @@\n-" + "a" * 1900 + "\n+ok\n"},
             "semantic-model", "excerpt-truncated"),
        )
        for name, mutation, route, reason in cases:
            with self.subTest(name=name):
                candidate = {**base, "diff": simple_diff, **mutation}
                kind = PACKETS.edit_kind(candidate["diff"])
                self.assertEqual(PACKETS.model_route(
                    candidate, kind, PACKETS.signal_family(candidate)), (route, reason))

        candidate = {**base, "diff":
                     "@@ -1 +1 @@\n-old()\n+new()\n context one\n context two\n"
                     + "far context\n" * 300}
        member = {"id": "abc", "edit": "rewrite", "route": "semantic-model",
                  "route_reason": "unrecognized-signal"}
        rendered = PACKETS.packet_candidate(member, {"abc": candidate}, True)
        self.assertNotIn("far context", rendered["diff"])
        self.assertEqual(rendered["evidence"], "cluster/evidence/abc.json")
        evidence = PACKETS.packet_evidence(
            {"go-general": {"candidates": [rendered]}}, {"abc": candidate})
        self.assertIn("far context", evidence["abc"]["diff"])

    def test_mechanical_cluster_rejects_zero_chunk_and_malformed_corpus(self):
        with tempfile.TemporaryDirectory() as directory, \
                contextlib.redirect_stderr(io.StringIO()):
            root = Path(directory)
            args = SimpleNamespace(work=root, corpus=root / "corpus.jsonl", chunk=0,
                                   min_size=1, mechanical=True)
            valid = {"short": "abc", "subject": "fix", "files": ["x.go"],
                     "diff": "+fix()", "signals": [], "density": 1, "url": ""}
            PACKETS.write_jsonl(args.corpus, [valid])
            self.assertEqual(PACKETS.cluster_emit(args), 1)
            self.assertFalse((root / "cluster").exists())
            args.chunk = 12
            args.min_size = 2
            self.assertEqual(PACKETS.cluster_emit(args), 1)
            self.assertFalse((root / "cluster").exists())
            args.min_size = 1
            for mutation in ({**valid, "files": ["x.rs"]},
                             {**valid, "files": ["x.go", "x.c"]},
                             {**valid, "signals": "bounds"},
                             {**valid, "density": "high"}):
                with self.subTest(mutation=mutation), self.assertRaises(SystemExit):
                    PACKETS.write_jsonl(args.corpus, [mutation])
                    PACKETS.cluster_emit(args)

    def test_proposals_require_at_least_one_supporting_commit(self):
        proposal = self.proposal()
        proposal["supporting"] = []
        self.assertIn("supporting", PACKETS.validate_proposal(proposal, {"abc"}) or "")
        proposal["supporting"] = ["abc"]
        self.assertIsNone(PACKETS.validate_proposal(proposal, {"abc"}))
        self.assertEqual(PACKETS.validate_cluster(
            {"cluster": "go-bounds", "proposals": [],
             "dispositions": [["abc", "no-generalization"]]},
            "go-bounds", {"abc"}, "go"), (None, []))

    def test_cluster_emit_requires_current_validated_label_replies(self):
        for mutation in ("class", "summary", "language", "deleted", "malformed", "labels"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory, \
                    contextlib.redirect_stderr(io.StringIO()):
                root = Path(directory)
                args = SimpleNamespace(work=root, corpus=root / "corpus.jsonl",
                                       chunk=12, min_size=1)
                PACKETS.write_jsonl(args.corpus, [{"short": "abc", "repo": "sample",
                    "subject": "fix", "files": ["x.go"], "diff": "+x[i]",
                    "signals": ["bounds"], "density": 1, "url": ""}])
                self.assertEqual(PACKETS.label_emit(args), 0)
                reply_path = root / "label/replies/abc.json"
                reply_path.write_text(json.dumps(self.label()))
                self.assertEqual(PACKETS.label_ingest(args), 0)
                labels_path = root / "label/labels.jsonl"
                originals = {p: p.read_bytes() for p in (reply_path, labels_path)}
                if mutation == "deleted":
                    reply_path.unlink()
                elif mutation == "malformed":
                    reply_path.write_text("{")
                elif mutation == "labels":
                    labels = PACKETS.read_jsonl(labels_path)
                    labels[0]["summary"] = "edited aggregate"
                    PACKETS.write_jsonl(labels_path, labels)
                else:
                    reply = self.label()
                    reply[mutation] = {"class": "logic", "summary": "edited reply",
                                       "language": "c"}[mutation]
                    reply_path.write_text(json.dumps(reply))
                before = labels_path.read_bytes()
                self.assertEqual(PACKETS.cluster_emit(args), 1)
                self.assertFalse((root / "cluster").exists())
                self.assertEqual(labels_path.read_bytes(), before)
                for path, content in originals.items():
                    path.write_bytes(content)
                self.assertEqual(PACKETS.cluster_emit(args), 0)

    def test_prompt_bytes_survive_platform_text_defaults(self):
        original_open = Path.open

        def platform_open(path, mode="r", buffering=-1, encoding=None, errors=None, newline=None):
            # Model a legacy locale and Windows text-mode newline translation.
            if "b" not in mode and "w" in mode:
                encoding = "cp1252" if encoding in (None, "locale") else encoding
                newline = "\r\n" if newline is None else newline
            return original_open(path, mode, buffering, encoding, errors, newline)

        for stage_name in ("label", "cluster"):
            with self.subTest(stage=stage_name), tempfile.TemporaryDirectory() as directory, \
                    patch.object(Path, "open", platform_open):
                stage = Path(directory) / stage_name
                prompt = "Classify café.\nRetain exact bytes.\n"
                packets = {"sample": {"id": "sample"}}
                self.assertTrue(PACKETS.emit_packets(stage, packets, prompt))
                self.assertEqual((stage / "PROMPT.md").read_bytes(), prompt.encode("utf-8"))
                self.assertTrue(PACKETS.packet_state(stage, packets, prompt))
                self.assertTrue(PACKETS.emit_packets(stage, packets, prompt))

    def test_emission_rejects_label_and_evidence_path_keys(self):
        with tempfile.TemporaryDirectory() as directory, \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            root = Path(directory)
            corpus_path = root / "corpus.jsonl"
            candidate = {"short": "../../target", "repo": "sample",
                         "subject": "fix", "files": ["x.c"], "language": "c",
                         "diff": "+guard();", "signals": [], "density": 1,
                         "url": ""}
            PACKETS.write_jsonl(corpus_path, [candidate])
            self.assertEqual(PACKETS.label_emit(SimpleNamespace(
                work=root, corpus=corpus_path, chunk=12)), 1)
            self.assertFalse((root / "target.json").exists())

            packets = {"safe": {"candidates": [{
                "short": candidate["short"], "evidence": "cluster/evidence/x.json"}]}}
            evidence = PACKETS.packet_evidence(
                packets, {candidate["short"]: candidate})
            self.assertFalse(PACKETS.emit_packets(
                root / "cluster", packets, PACKETS.CLUSTER_PROMPT, evidence=evidence))
            self.assertFalse((root / "target.json").exists())
            self.assertGreaterEqual(errors.getvalue().count("basename identifier"), 2)

            boundary = "a" * 250
            boundary_stage = root / "boundary"
            self.assertTrue(PACKETS.emit_packets(
                boundary_stage, {boundary: {"id": boundary}}, PACKETS.CLUSTER_PROMPT))
            self.assertTrue((boundary_stage / "packets" / f"{boundary}.json").is_file())
            for key in ("a" * 251, "NUL", "com1.log"):
                stage = root / f"invalid-{len(key)}-{key[:4]}"
                self.assertFalse(PACKETS.emit_packets(
                    stage, {key: {"id": key}}, PACKETS.CLUSTER_PROMPT))
                self.assertFalse((stage / "PROMPT.md").exists())

            collision = {"abc": {}, "ABC": {}}
            cases = (("packets", collision, {}),
                     ("evidence", {"safe": {}}, collision))
            for namespace, packets, evidence in cases:
                with self.subTest(namespace=namespace):
                    stage = root / f"collision-{namespace}"
                    self.assertFalse(PACKETS.emit_packets(
                        stage, packets, PACKETS.CLUSTER_PROMPT, evidence=evidence))
                    self.assertFalse((stage / "PROMPT.md").exists())

    def test_prompt_changes_refuse_stale_replies_without_overwriting_evidence(self):
        for stage_name, constant in (("label", "LABEL_PROMPT"), ("cluster", "CLUSTER_PROMPT")):
            with self.subTest(stage=stage_name), tempfile.TemporaryDirectory() as directory, \
                    contextlib.redirect_stderr(io.StringIO()):
                root = Path(directory)
                args = SimpleNamespace(work=root, corpus=root / "corpus.jsonl", chunk=12, min_size=1)
                PACKETS.write_jsonl(args.corpus, [{"short": "abc", "repo": "sample",
                    "subject": "fix", "files": ["x.go"], "diff": "+x[i]",
                    "signals": ["bounds"], "density": 1, "url": ""}])
                self.assertEqual(PACKETS.label_emit(args), 0)
                (root / "label/replies/abc.json").write_text(json.dumps(self.label()))
                self.assertEqual(PACKETS.label_ingest(args), 0)
                if stage_name == "cluster":
                    self.assertEqual(PACKETS.cluster_emit(args), 0)
                    (root / "cluster/replies/go-bounds.json").write_text(json.dumps(
                        {"cluster": "go-bounds", "proposals": [],
                         "dispositions": [["abc", "no-generalization"]]}))
                emit = getattr(PACKETS, f"{stage_name}_emit")
                ingest = getattr(PACKETS, f"{stage_name}_ingest")
                self.assertEqual(ingest(args), 0)
                stage = root / stage_name
                before = {p.relative_to(stage): p.read_bytes() for p in stage.rglob("*")
                          if p.is_file()}
                with patch.object(PACKETS, constant, getattr(PACKETS, constant) + "\nchanged"):
                    self.assertEqual(ingest(args), 1)
                    self.assertEqual(emit(args), 1)
                self.assertEqual({p.relative_to(stage): p.read_bytes() for p in stage.rglob("*")
                                  if p.is_file()}, before)
                self.assertEqual(ingest(args), 0)
                prompt = stage / "PROMPT.md"
                original = prompt.read_bytes()
                prompt.write_bytes(original + b"\nchanged")
                self.assertEqual(ingest(args), 1)
                self.assertEqual(emit(args), 1)
                self.assertEqual(prompt.read_bytes(), original + b"\nchanged")
                for path, content in before.items():
                    if path.parts[0] == "replies":
                        self.assertEqual((stage / path).read_bytes(), content)
                prompt.write_bytes(original)
                self.assertEqual(ingest(args), 0)
                self.assertEqual(emit(args), 0)

    def test_proposal_language_must_match_emitted_cluster(self):
        with tempfile.TemporaryDirectory() as directory, \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            root = Path(directory)
            args = SimpleNamespace(work=root, corpus=root / "corpus.jsonl", chunk=12, min_size=1)
            PACKETS.write_jsonl(args.corpus, [{"short": "abc", "repo": "sample",
                "subject": "fix", "files": ["x.go"], "diff": "+x[i]",
                "signals": ["bounds"], "density": 1, "url": ""}])
            self.assertEqual(PACKETS.label_emit(args), 0)
            (root / "label/replies/abc.json").write_text(json.dumps(self.label()))
            self.assertEqual(PACKETS.label_ingest(args), 0)
            self.assertEqual(PACKETS.cluster_emit(args), 0)
            reply = root / "cluster/replies/go-bounds.json"
            reply.write_text(json.dumps({"cluster": "go-bounds", "proposals": [
                {**self.proposal(), "id": "c-index-check", "language": "c"}],
                "dispositions": [["abc", ["c-index-check"]]]}))
            self.assertEqual(PACKETS.cluster_ingest(args), 1)
            self.assertEqual(PACKETS.read_jsonl(root / "cluster/proposals.jsonl"), [])
            self.assertIn("language", errors.getvalue())
            reply.write_text(json.dumps({"cluster": "go-bounds", "proposals": [self.proposal()],
                                         "dispositions": [["abc", ["go-index-check"]]]}))
            self.assertEqual(PACKETS.cluster_ingest(args), 0)
            self.assertEqual(PACKETS.read_jsonl(root / "cluster/proposals.jsonl")[0]["language"], "go")

    def test_label_language_must_match_corpus(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()) as errors:
            root = Path(directory)
            args = SimpleNamespace(work=root, corpus=root / "corpus.jsonl")
            PACKETS.write_jsonl(args.corpus, [{"short": "abc", "repo": "sample",
                "subject": "fix", "files": ["x.c"], "diff": "+x[i]",
                "signals": ["bounds"], "density": 1, "url": ""}])
            self.assertEqual(PACKETS.label_emit(args), 0)
            reply = root / "label/replies/abc.json"
            reply.write_text(json.dumps(self.label()))
            self.assertEqual(PACKETS.label_ingest(args), 1)
            self.assertEqual(PACKETS.read_jsonl(root / "label/labels.jsonl"), [])
            self.assertIn("language", errors.getvalue())
            reply.write_text(json.dumps({**self.label(), "language": "c"}))
            self.assertEqual(PACKETS.label_ingest(args), 0)
            self.assertTrue(PACKETS.read_jsonl(root / "label/labels.jsonl")[0]["agreed"])

    def test_duplicate_proposal_ids_rejected_across_replies(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()) as errors:
            root = Path(directory)
            stage = root / "cluster"
            packets = {name: {"language": "go", "candidates": [{"short": short}]}
                       for name, short in (("go-bounds-1", "abc"), ("go-bounds-2", "def"))}
            self.assertTrue(PACKETS.emit_packets(stage, packets, PACKETS.CLUSTER_PROMPT))
            for name, packet in packets.items():
                proposal = {**self.proposal(), "supporting": [packet["candidates"][0]["short"]]}
                (stage / "replies" / f"{name}.json").write_text(json.dumps(
                    {"cluster": name, "proposals": [proposal],
                     "dispositions": [[packet["candidates"][0]["short"],
                                       [proposal["id"]]]]}))
            self.assertEqual(PACKETS.cluster_ingest(SimpleNamespace(work=root)), 1)
            self.assertIn("duplicate proposal id", errors.getvalue())
            queue_args = SimpleNamespace(work=root, route="all", limit=10, json=True)
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(PACKETS.queue(queue_args), 0)
            queued = json.loads(output.getvalue())
            self.assertEqual({task["cluster"] for task in queued["tasks"]}, set(packets))
            self.assertTrue(all(task["state"] == "retry" for task in queued["tasks"]))
            self.assertTrue(all("duplicate proposal id" in task["error"]
                                for task in queued["tasks"]))
            proposals_path = stage / "proposals.jsonl"
            self.assertEqual(PACKETS.read_jsonl(proposals_path), [])
            with self.assertRaisesRegex(SystemExit, "no proposal"):
                SCAFFOLD.load_proposal(proposals_path, self.proposal()["id"])
            second = stage / "replies/go-bounds-2.json"
            reply = json.loads(second.read_text())
            reply["proposals"][0]["id"] = "go-second-check"
            reply["dispositions"][0][1] = ["go-second-check"]
            second.write_text(json.dumps(reply))
            self.assertEqual(PACKETS.cluster_ingest(SimpleNamespace(work=root)), 0)
            self.assertEqual({tuple(p["supporting"]) for p in PACKETS.read_jsonl(proposals_path)},
                             {("abc",), ("def",)})
            dispositions = PACKETS.read_jsonl(stage / "dispositions.jsonl")
            self.assertEqual({row["candidate"] for row in dispositions}, {"abc", "def"})

    def test_cluster_packet_snapshot_schema_is_validated(self):
        malformed = ({}, {"candidates": {}, "language": "go"},
                     {"candidates": [], "language": "go"},
                     {"candidates": [{"short": "abc"}], "language": 7},
                     {"candidates": [{"short": "abc"}], "language": ""},
                     {"candidates": [{"short": ""}], "language": "go"},
                     {"candidates": [{"short": 7}], "language": "go"})
        for packet in malformed:
            with self.subTest(packet=packet):
                loaded, error = PACKETS.cluster_packet_fields(packet)
                self.assertIsNone(loaded)
                self.assertIn("invalid packet", error)

    def test_cluster_ingest_uses_verified_manifest_snapshot(self):
        with tempfile.TemporaryDirectory() as directory, \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            root = Path(directory)
            stage = root / "cluster"
            packets = stage / "packets"
            replies = stage / "replies"
            snapshot = {"go-bounds": {
                "language": "go", "candidates": [{"short": "abc"}]}}
            self.assertTrue(PACKETS.emit_packets(stage, snapshot, PACKETS.CLUSTER_PROMPT))
            (replies / "go-bounds.json").write_text(json.dumps(
                {"cluster": "go-bounds", "proposals": [
                    {**self.proposal(), "supporting": ["abc"]}],
                 "dispositions": [["abc", ["go-index-check"]]]}))
            packet_state = PACKETS.packet_state

            def validate_then_mutate(*args, **kwargs):
                valid = packet_state(*args, **kwargs)
                self.assertTrue(valid)
                (packets / "go-bounds.json").write_text(json.dumps(
                    {"language": "c", "candidates": [{"short": "def"}]}))
                (packets / "go-extra.json").write_text(json.dumps(
                    {"language": "go", "candidates": [{"short": "xyz"}]}))
                (replies / "go-extra.json").write_text(json.dumps(
                    {"cluster": "go-extra", "proposals": [
                        {**self.proposal(), "id": "go-extra-check",
                         "supporting": ["xyz"]}],
                     "dispositions": [["xyz", ["go-extra-check"]]]}))
                return valid

            with patch.object(PACKETS, "packet_state", side_effect=validate_then_mutate):
                self.assertEqual(PACKETS.cluster_ingest(SimpleNamespace(work=root)), 0)
            proposals = PACKETS.read_jsonl(root / "cluster/proposals.jsonl")
            self.assertEqual([proposal["id"] for proposal in proposals], [self.proposal()["id"]])
            self.assertNotIn("REJECT", errors.getvalue())

    def test_cluster_ingest_reports_missing_reply_before_packet_schema(self):
        with tempfile.TemporaryDirectory() as directory, \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            root = Path(directory)
            with patch.object(PACKETS, "cluster_manifest", return_value={"go-bounds": {}}):
                self.assertEqual(PACKETS.cluster_ingest(SimpleNamespace(work=root)), 1)
            self.assertIn("MISSING go-bounds", errors.getvalue())
            self.assertNotIn("REJECT go-bounds", errors.getvalue())

    def test_cluster_ingest_rejects_reply_with_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as directory, \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            root = Path(directory)
            replies = root / "cluster/replies"
            replies.mkdir(parents=True)
            (replies / "go-bounds.json").write_bytes(b"\xff")
            snapshot = {"go-bounds": {
                "language": "go", "candidates": [{"short": "abc"}]}}
            with patch.object(PACKETS, "cluster_manifest", return_value=snapshot):
                self.assertEqual(PACKETS.cluster_ingest(SimpleNamespace(work=root)), 1)
            self.assertEqual(PACKETS.read_jsonl(root / "cluster/proposals.jsonl"), [])
            self.assertIn("REJECT go-bounds: cannot read reply", errors.getvalue())

    def test_cluster_ingest_rejects_reply_read_error(self):
        with tempfile.TemporaryDirectory() as directory, \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            root = Path(directory)
            reply = root / "cluster/replies/go-bounds.json"
            reply.parent.mkdir(parents=True)
            reply.write_text("{}")
            original_read = Path.read_text

            def refuse_reply(path, *args, **kwargs):
                if path == reply:
                    raise PermissionError("reply denied")
                return original_read(path, *args, **kwargs)

            snapshot = {"go-bounds": {
                "language": "go", "candidates": [{"short": "abc"}]}}
            with patch.object(PACKETS, "cluster_manifest", return_value=snapshot), \
                    patch.object(Path, "read_text", refuse_reply):
                self.assertEqual(PACKETS.cluster_ingest(SimpleNamespace(work=root)), 1)
            self.assertEqual(PACKETS.read_jsonl(root / "cluster/proposals.jsonl"), [])
            self.assertIn("REJECT go-bounds: cannot read reply: reply denied", errors.getvalue())

    def test_cluster_chunk_change_refused_and_manifest_requires_all_packets(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            root = Path(directory)
            args = SimpleNamespace(work=root, corpus=root / "corpus.jsonl", chunk=1, min_size=1)
            corpus = [{"short": name, "repo": "sample", "subject": "fix", "files": ["x.go"],
                       "diff": "+x[i]", "signals": ["bounds"], "density": 1, "url": ""}
                      for name in ("abc", "def")]
            PACKETS.write_jsonl(args.corpus, corpus)
            self.assertEqual(PACKETS.label_emit(args), 0)
            for name in ("abc", "def"):
                (root / f"label/replies/{name}.json").write_text(json.dumps({**self.label(), "id": name}))
            self.assertEqual(PACKETS.label_ingest(args), 0)
            self.assertEqual(PACKETS.cluster_emit(args), 0)
            packets = root / "cluster/packets"
            before = {p.name: p.read_bytes() for p in packets.glob("*.json")}
            self.assertEqual(len(before), 2)
            args.chunk = 3
            self.assertEqual(PACKETS.cluster_emit(args), 1)
            self.assertEqual({p.name: p.read_bytes() for p in packets.glob("*.json")}, before)
            for name in before:
                packet = json.loads((packets / name).read_text())
                short = packet["candidates"][0]["short"]
                (root / "cluster/replies" / name).write_text(json.dumps(
                    {"cluster": Path(name).stem, "proposals": [],
                     "dispositions": [[short, "no-generalization"]]}))
            self.assertEqual(PACKETS.cluster_ingest(args), 0)
            next(packets.glob("*.json")).unlink()
            self.assertEqual(PACKETS.cluster_ingest(args), 1)

    def test_pool_label_uses_producer_signal(self):
        self.assertIn(PACKETS.TAXONOMY["pool-reset"], HISTORY.signal_terms("p.Reset()", "fix"))

    def test_packet_lifecycle_preserves_stale_work_and_rejects_missing_state(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            stage = Path(directory) / "label"
            original = {"abc": {"id": "abc", "diff": "old"}}
            self.assertFalse(PACKETS.packet_state(stage, original, "prompt"))
            self.assertTrue(PACKETS.emit_packets(stage, original, "prompt"))
            reply = stage / "replies/abc.json"
            reply.write_text('{"id":"abc"}')
            before = {p.relative_to(stage): p.read_bytes() for p in stage.rglob("*") if p.is_file()}
            for changed in ({}, {"abc": {"id": "abc", "diff": "new"}},
                            {**original, "def": {"id": "def"}}):
                self.assertFalse(PACKETS.emit_packets(stage, changed, "prompt"))
                after = {p.relative_to(stage): p.read_bytes() for p in stage.rglob("*") if p.is_file()}
                self.assertEqual(before, after)
            self.assertTrue(PACKETS.emit_packets(stage, original, "prompt"))

    def test_nonempty_corpus_without_packets_cannot_ingest(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            root = Path(directory)
            args = SimpleNamespace(work=root, corpus=root / "corpus.jsonl")
            PACKETS.write_jsonl(args.corpus, [{"short": "abc", "repo": "sample",
                "subject": "fix", "files": ["x.go"], "diff": "x"}])
            self.assertEqual(PACKETS.label_ingest(args), 1)
            self.assertFalse((root / "label/labels.jsonl").exists())
            self.assertEqual(PACKETS.cluster_ingest(args), 1)

    def test_shipped_message_yaml_styles(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(PACKETS, "ROOT", Path(directory)):
            rules = Path(directory) / "rules/go/security"
            rules.mkdir(parents=True)
            for name, scalar in (("plain", "Check the index"), ("quoted", '"Check the index"'),
                                 ("folded", ">-\n  Check the index"),
                                 ("literal", "|\n  Check the index")):
                (rules / f"{name}.yml").write_text(f"message: {scalar}\n")
            self.assertEqual([row["message"] for row in PACKETS.shipped_rules("go")],
                             ["Check the index"] * 4)
            (rules / "incomplete.yml").write_text("")
            with self.assertRaisesRegex(SystemExit, "expected a YAML mapping"):
                PACKETS.shipped_rules("go")

    def test_missing_stage_input_refused(self):
        with tempfile.TemporaryDirectory() as directory, \
                self.assertRaisesRegex(SystemExit, "preceding stage"):
            PACKETS.read_jsonl(Path(directory) / "missing.jsonl")

    @staticmethod
    def label():
        return {"id": "abc", "class": "bounds", "language": "go",
                "confidence": "high", "summary": "Check index before access"}

    @staticmethod
    def proposal():
        return {"id": "go-index-check", "language": "go", "claim": "Check index",
                "classification": "syntactic", "positive": "x[i]", "near_miss": "x[0]",
                "supporting": ["abc"], "overlaps": [], "rationale": "Repeated syntax"}

    def test_label_types_and_boundaries(self):
        self.assertIsNone(PACKETS.validate_label(self.label(), "abc"))
        for field, value in (("class", []), ("class", "unknown"), ("id", "wrong"),
                             ("summary", ""), ("summary", "x" * 161),
                             ("language", None), ("confidence", "maybe")):
            with self.subTest(field=field, value=value):
                self.assertIsNotNone(PACKETS.validate_label({**self.label(), field: value}, "abc"))
        self.assertIsNone(PACKETS.validate_label({**self.label(), "summary": "x" * 160}, "abc"))

    def test_cluster_rejects_wrong_types_and_foreign_support(self):
        valid = {"cluster": "go-bounds", "proposals": [self.proposal()],
                 "dispositions": [["abc", ["go-index-check"]]]}
        self.assertEqual(PACKETS.validate_cluster(valid, "go-bounds", {"abc"}, "go"),
                         (None, valid["proposals"]))
        for field, value in (("id", 12), ("language", "python"), ("positive", None),
                             ("near_miss", "x[i]"), ("claim", ""), ("supporting", [[]]),
                             ("supporting", ["foreign"]), ("overlaps", "rule"),
                             ("rationale", "x" * 301)):
            reply = {"cluster": "go-bounds", "proposals": [{**self.proposal(), field: value}],
                     "dispositions": [["abc", ["go-index-check"]]]}
            with self.subTest(field=field, value=value):
                error, props = PACKETS.validate_cluster(reply, "go-bounds", {"abc"}, "go")
                self.assertIsNotNone(error)
                self.assertEqual(props, [])

    def test_cluster_requires_complete_consistent_candidate_dispositions(self):
        proposal = self.proposal()
        valid = {"cluster": "go-bounds", "proposals": [proposal],
                 "dispositions": [["abc", [proposal["id"]]], ["def", "noise"]]}
        self.assertEqual(PACKETS.validate_cluster(
            valid, "go-bounds", {"abc", "def"}, "go"), (None, [proposal]))
        mutations = (
            ("missing", {**valid, "dispositions": [["abc", [proposal["id"]]]]}),
            ("repeated", {**valid, "dispositions": [
                ["abc", [proposal["id"]]], ["abc", "noise"]]}),
            ("foreign", {**valid, "dispositions": [
                ["abc", [proposal["id"]]], ["xyz", "noise"]]}),
            ("bad-reason", {**valid, "dispositions": [
                ["abc", [proposal["id"]]], ["def", "semantic"]]}),
            ("unknown-proposal", {**valid, "dispositions": [
                ["abc", ["go-other-rule"]], ["def", "noise"]]}),
            ("support-mismatch", {**valid, "dispositions": [
                ["abc", "unclear"], ["def", "noise"]]}),
        )
        for name, reply in mutations:
            with self.subTest(name=name):
                error, proposals = PACKETS.validate_cluster(
                    reply, "go-bounds", {"abc", "def"}, "go")
                self.assertIsNotNone(error)
                self.assertEqual(proposals, [])

    def test_label_ingest_missing_malformed_and_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = SimpleNamespace(work=root, corpus=root / "corpus.jsonl")
            PACKETS.write_jsonl(args.corpus, [{"short": "abc", "repo": "sample",
                "subject": "fix index", "files": ["x.go"], "diff": "+x[i]",
                "signals": ["bounds"], "density": 1, "url": ""}])
            with contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(PACKETS.label_emit(args), 0)
                self.assertEqual(PACKETS.label_ingest(args), 1)
                reply = root / "label/replies/abc.json"
                reply.write_text("{")
                self.assertEqual(PACKETS.label_ingest(args), 1)
                self.assertEqual(PACKETS.read_jsonl(root / "label/labels.jsonl"), [])
                reply.write_text(json.dumps(self.label()))
                self.assertEqual(PACKETS.label_ingest(args), 0)
            self.assertIn("MISSING abc", errors.getvalue())
            self.assertIn("REJECT abc: invalid JSON", errors.getvalue())
            labels = PACKETS.read_jsonl(root / "label/labels.jsonl")
            self.assertEqual([(row["id"], row["agreed"]) for row in labels], [("abc", True)])


class ProbeTests(unittest.TestCase):
    def test_unknown_discovery_extension_returns_explicit_json_failure(self):
        with patch.object(PROBE, "EXTENSIONS", {}), \
                patch("sys.argv", ["probe", "go-tls-min-version", "--json"]), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(PROBE.main(), 1)
        report = json.loads(output.getvalue())
        discovery = next(check for check in report["checks"] if check["name"] == "discovery")
        self.assertFalse(discovery["ok"])
        self.assertIn("unsupported discovery language", discovery["detail"])
        self.assertNotIn("positive.None", discovery["detail"])

    def test_invalid_diagnostics_return_failed_json_checks(self):
        rule_path, fixture_path = PROBE.find_rule("go-tls-min-version")
        rule = yaml.safe_load(rule_path.read_text())
        fixture = yaml.safe_load(fixture_path.read_text())
        for field in ("message", "note"):
            for value in (42, True, ["text"], {"text": "value"}, " ", "\t\n"):
                with self.subTest(field=field, value=value):
                    with patch.object(PROBE, "load_inputs", return_value=(
                            {**rule, field: value}, fixture["valid"], fixture["invalid"])), \
                            patch("sys.argv", ["probe", "go-tls-min-version", "--json"]), \
                            contextlib.redirect_stdout(io.StringIO()) as output:
                        self.assertEqual(PROBE.main(), 1)
                    report = json.loads(output.getvalue())
                    self.assertFalse(report["ok"])
                    diagnostic = next(check for check in report["checks"]
                                      if check["name"] == f"{field}-literal")
                    self.assertFalse(diagnostic["ok"])

    def test_subprocess_timeouts_return_failed_json_checks(self):
        original_run = subprocess.run
        original_test = PROBE.Isolated.test

        def make_isolated_test(state):
            def isolated_test(iso, rule=None):
                state.phase = "fixture-run" if rule is None else "arm-kills"
                try:
                    return original_test(iso, rule)
                finally:
                    state.phase = None
            return isolated_test

        def make_run(state, records, target):
            def run(command, *args, **kwargs):
                verb = command[1:2]
                if verb == ["test"] and "-U" in command:
                    owner = "snapshot-update"
                elif verb == ["test"]:
                    owner = state.phase
                    if owner not in ("fixture-run", "arm-kills"):
                        records["unexpected"].append(command)
                        return original_run(command, *args, **kwargs)
                elif verb == ["scan"]:
                    owner = "fixture-counts" if "--inline-rules" in command else "discovery"
                elif verb == ["run"]:
                    owner = "pattern-expressions"
                else:
                    return original_run(command, *args, **kwargs)
                if owner == target:
                    records["timeouts"] += 1
                    timeout = kwargs.get("timeout")
                    if timeout is None:
                        records["missing_timeouts"].append(command)
                        return original_run(command, *args, **kwargs)
                    raise subprocess.TimeoutExpired(command, timeout)
                return original_run(command, *args, **kwargs)
            return run

        phases = (("fixture-counts", []), ("fixture-run", []), ("arm-kills", []),
                  ("discovery", []), ("pattern-expressions", ["--sexp"]),
                  ("snapshot-update", ["--snapshot"]))
        for phase, options in phases:
            with self.subTest(phase=phase):
                calls = {"timeouts": 0, "unexpected": [], "missing_timeouts": []}
                state = SimpleNamespace(phase=None)
                isolated_test = make_isolated_test(state)
                run = make_run(state, calls, phase)

                with patch.object(PROBE.Isolated, "test", isolated_test), \
                        patch.object(PROBE.subprocess, "run", side_effect=run), \
                        patch("sys.argv", ["probe", "py-jwt-decode-unverified", "--json", *options]), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(PROBE.main(), 1)
                self.assertEqual(calls["unexpected"], [], "all test calls need an explicit phase")
                self.assertEqual(calls["missing_timeouts"], [], "target calls need a timeout")
                self.assertGreater(calls["timeouts"], 0, "the target subprocess must be reached")
                report = json.loads(output.getvalue())
                self.assertFalse(report["ok"])
                failed = next(check for check in report["checks"] if check["name"] == phase)
                self.assertFalse(failed["ok"])
                self.assertIn("timed out", failed["detail"])
                if phase == "snapshot-update":
                    self.assertNotIn("snapshot", report)

    def test_successful_snapshot_update_with_unreadable_output_is_json_failure(self):
        source_rule, source_fixture = PROBE.find_rule("go-tls-min-version")
        original = SimpleNamespace(run=subprocess.run, read_text=Path.read_text)
        for failure in (PermissionError("injected snapshot read failure"),
                        UnicodeError("injected snapshot encoding failure"), None):
            with self.subTest(failure=str(failure)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for source in (source_rule, source_fixture):
                    target = root / source.relative_to(ROOT)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(source.read_bytes())
                (root / "sgconfig.yml").write_text("ruleDirs: [rules]\ntestConfigs: [{testDir: tests}]\n")
                snapshot = root / "tests/__snapshots__/go-tls-min-version-snapshot.yml"
                updates = []

                def run(command, *args, records=updates, **kwargs):
                    result = original.run(command, *args, **kwargs)
                    if "-U" in command:
                        records.append(result.returncode)
                    return result

                def read(path, *args, fail=failure, target=snapshot, records=updates, **kwargs):
                    if fail is not None and path == target and records:
                        raise fail
                    return original.read_text(path, *args, **kwargs)

                with patch.object(PROBE, "ROOT", root), patch.object(Path, "read_text", read), \
                        patch.object(PROBE.subprocess, "run", side_effect=run), \
                        patch("sys.argv", ["probe", "go-tls-min-version", "--json", "--snapshot"]), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(PROBE.main(), int(failure is not None))
                self.assertEqual(updates, [0], "the real scoped snapshot update must succeed")
                report = json.loads(output.getvalue())
                self.assertEqual(report["ok"], failure is None)
                self.assertEqual("snapshot" in report, failure is None)
                update = next(check for check in report["checks"] if check["name"] == "snapshot-update")
                self.assertEqual(update["ok"], failure is None)
                if failure is not None:
                    self.assertIn(str(failure), update["detail"])

    def test_malformed_arm_witness_file_returns_json_failure_and_recovers(self):
        coverage = ROOT / "tests/arm_coverage.json"
        original = SimpleNamespace(read_text=Path.read_text)
        valid_text = coverage.read_text()
        retained = next(case for case in json.loads(valid_text)["cases"]
                        if case["rule"] == "py-jwt-decode-unverified")
        malformed = ["{", "[]", "{}", '{"cases": {}}', '{"cases": [null]}',
                     '{"cases": [{}]}']
        for field in ("rule", "classification", "path", "index", "source", "expected", "deleted_expected"):
            malformed.append(json.dumps({"cases": [{k: v for k, v in retained.items() if k != field}]}))
        for field, value in (("expected", True), ("deleted_expected", 2.0),
                             ("expected", -1), ("index", []), ("source", None),
                             ("classification", "unsupported")):
            malformed.append(json.dumps({"cases": [{**retained, field: value}]}))
        malformed.append(json.dumps({"cases": [retained, {**retained, "expected": 99}]}))
        for text, expected in [*((text, 1) for text in malformed), (valid_text, 0)]:
            def read(path, *args, contents=text, **kwargs):
                return contents if path == coverage else original.read_text(path, *args, **kwargs)

            with self.subTest(contents=text[:80]), patch.object(Path, "read_text", read), \
                    patch("sys.argv", ["probe", "py-jwt-decode-unverified", "--json"]), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(PROBE.main(), expected)
                report = json.loads(output.getvalue())
                self.assertEqual(report["ok"], expected == 0)
                arm = next(check for check in report["checks"] if check["name"] == "arm-kills")
                self.assertEqual(arm["ok"], expected == 0)
                if expected:
                    self.assertTrue(arm["detail"].startswith("invalid arm_coverage.json:"),
                                    arm["detail"])

    def test_orphan_snapshot_key_rejected_and_valid_snapshot_recovers(self):
        rule_path, fixture_path = PROBE.find_rule("go-tls-min-version")
        source_snapshot = ROOT / "tests/__snapshots__/go-tls-min-version-snapshot.yml"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for source in (rule_path, fixture_path, source_snapshot):
                target = root / source.relative_to(ROOT)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read_bytes())
            snapshot = root / source_snapshot.relative_to(ROOT)
            document = yaml.safe_load(snapshot.read_text())
            document["snapshots"]["orphan input"] = next(iter(document["snapshots"].values()))
            cases = ((yaml.safe_dump(document), 1, "snapshot-keys"),
                     ("[]\n", 1, "snapshot-shape"),
                     ("snapshots: []\n", 1, "snapshot-keys"),
                     (source_snapshot.read_text(), 0, "snapshot-keys"))
            for text, expected, check_name in cases:
                snapshot.write_text(text)
                with self.subTest(snapshot=text[:40]), patch.object(PROBE, "ROOT", root), \
                        patch("sys.argv", ["probe", "go-tls-min-version", "--json"]), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(PROBE.main(), expected)
                report = json.loads(output.getvalue())
                self.assertEqual(report["ok"], expected == 0)
                checks = {item["name"]: item for item in report["checks"]}
                self.assertEqual(checks[check_name]["ok"], expected == 0)

    def test_probe_mapping_read_errors_return_json_failure(self):
        source_rule, source_fixture = PROBE.find_rule("go-tls-min-version")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rule = root / source_rule.relative_to(ROOT)
            fixture = root / source_fixture.relative_to(ROOT)
            for target, source in ((rule, source_rule), (fixture, source_fixture)):
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read_bytes())
            original = SimpleNamespace(read_text=Path.read_text)
            for failure in ("encoding", "permission"):
                rule.write_bytes(b"\xff" if failure == "encoding" else source_rule.read_bytes())

                def read(path, *args, fail=failure, **kwargs):
                    if fail == "permission" and path == rule:
                        raise PermissionError("injected unreadable rule")
                    return original.read_text(path, *args, **kwargs)

                with self.subTest(failure=failure), patch.object(PROBE, "ROOT", root), \
                        patch.object(Path, "read_text", read), \
                        patch("sys.argv", ["probe", "go-tls-min-version", "--json"]), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(PROBE.main(), 1)
                    report = json.loads(output.getvalue())
                    self.assertFalse(report["ok"])
                    self.assertTrue(any(check["name"] == "rule-shape" and not check["ok"]
                                        for check in report["checks"]))

    def test_snapshot_update_failure_cannot_return_old_snapshot(self):
        source_rule, source_fixture = PROBE.find_rule("go-tls-min-version")
        source_snapshot = ROOT / "tests/__snapshots__/go-tls-min-version-snapshot.yml"
        real_run = subprocess.run
        real_load_mapping = PROBE.load_mapping
        updates = []
        loaded = []

        def fail_update(command, *args, **kwargs):
            if "-U" in command:
                updates.append(command)
                return subprocess.CompletedProcess(command, 2, "", "injected snapshot write failure")
            return real_run(command, *args, **kwargs)

        def record_load(path, *args, **kwargs):
            loaded.append(path)
            return real_load_mapping(path, *args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_relative_files(root, (source_rule, source_fixture, source_snapshot))
            snapshot = root / source_snapshot.relative_to(ROOT)
            with patch.object(PROBE, "ROOT", root), \
                    patch.object(PROBE, "load_mapping", side_effect=record_load), \
                    patch.object(PROBE.subprocess, "run", side_effect=fail_update), \
                    patch("sys.argv", ["probe", "go-tls-min-version", "--json", "--snapshot"]), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(PROBE.main(), 1)
            self.assertEqual(len(updates), 1)
            config_index = updates[0].index("-c") + 1
            self.assertEqual(Path(updates[0][config_index]), root / "sgconfig.yml")
            self.assertIn(snapshot.resolve(), [Path(path).resolve() for path in loaded])
            self.assertEqual(snapshot.read_bytes(), source_snapshot.read_bytes())
            report = json.loads(output.getvalue())
            self.assertFalse(report["ok"])
            self.assertNotIn("snapshot", report)
            self.assertIn("injected snapshot write failure", output.getvalue())
            checks = {item["name"]: item["ok"] for item in report["checks"]}
            for name in ("fixture-counts", "fixture-run", "arm-kills", "discovery"):
                self.assertTrue(checks[name], name)

    def test_probe_handles_missing_and_unquoted_off_severity(self):
        off_ids = []
        for path in sorted((ROOT / "rules").rglob("*.yml")):
            rule = yaml.safe_load(path.read_text())
            if rule.get("severity") in ("off", False):
                off_ids.append(rule["id"])
        self.assertEqual(sorted(off_ids), sorted(PROBE.COMPATIBILITY_ALIAS_IDS))

        source_rule, source_fixture = PROBE.find_rule("nginx-string-sizeof-includes-nul")
        source_snapshot = (
            ROOT / "tests/__snapshots__/nginx-string-sizeof-includes-nul-snapshot.yml"
        )
        coverage = ROOT / "tests/arm_coverage.json"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_relative_files(
                root, (source_rule, source_fixture, source_snapshot, coverage)
            )
            rule = root / source_rule.relative_to(ROOT)
            original = rule.read_text()

            rule.write_text(original.replace("severity: 'off'\n", "severity: off\n"))
            unquoted = yaml.safe_load(rule.read_text())
            self.assertIs(unquoted["severity"], False)
            invalid = yaml.safe_load(source_fixture.read_text())["invalid"][0]
            self.assertEqual(PROBE.scan_stdin(unquoted, invalid), (1, ""))
            with patch.object(PROBE, "ROOT", root), \
                    patch("sys.argv", ["probe", source_rule.stem, "--json"]), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(PROBE.main(), 0)
            report = json.loads(output.getvalue())
            self.assertTrue(report["ok"])
            self.assertEqual(
                next(item for item in report["checks"] if item["name"] == "severity")["detail"],
                "off",
            )

            rule.write_text(original)
            with patch.object(PROBE, "ROOT", root), \
                    patch.object(PROBE, "COMPATIBILITY_ALIAS_IDS", set()), \
                    patch("sys.argv", ["probe", source_rule.stem, "--json"]), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(PROBE.main(), 1)
            report = json.loads(output.getvalue())
            severity = next(
                item for item in report["checks"] if item["name"] == "severity"
            )
            self.assertFalse(severity["ok"])
            self.assertIsNone(PROBE.promoted_rule_id({
                "id": "work-in-progress", "severity": "off"
            }))
            discovery = next(
                item for item in report["checks"] if item["name"] == "discovery"
            )
            self.assertFalse(discovery["ok"])

            document = yaml.safe_load(original)
            del document["severity"]
            rule.write_text(yaml.safe_dump(document))
            with patch.object(PROBE, "ROOT", root), \
                    patch("sys.argv", ["probe", source_rule.stem, "--json"]), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(PROBE.main(), 1)
            report = json.loads(output.getvalue())
            severity = next(
                item for item in report["checks"] if item["name"] == "severity"
            )
            self.assertFalse(severity["ok"])
            self.assertTrue(all(
                item["ok"] for item in report["checks"] if item["name"] != "severity"
            ))

    def test_jwt_witnesses_validate_each_deleted_arm(self):
        rule_path, fixture_path = PROBE.find_rule("py-jwt-decode-unverified")
        rule = yaml.safe_load(rule_path.read_text())
        cases = [case for case in json.loads((ROOT / "tests/arm_coverage.json").read_text())["cases"]
                 if case["rule"] == rule["id"]]
        self.assertEqual(len(cases), 2)
        for case in cases:
            with self.subTest(index=case["index"]):
                path = tuple(int(part) if part.isdigit() else part for part in case["path"].split("/"))
                self.assertEqual(PROBE.scan_stdin(rule, case["source"]), (1, ""))
                self.assertEqual(PROBE.scan_stdin(PROBE.delete_arm(rule, path, case["index"]),
                                                 case["source"]), (2, ""))
        iso = PROBE.Isolated(rule_path, fixture_path)
        try:
            passed, detail = PROBE.check_arms(iso, rule)
        finally:
            iso.close()
        self.assertTrue(passed, detail)
        for case in cases:
            self.assertIn(f"{case['path']}[{case['index']}]: 1 -> 2", detail)

    def test_witness_classification_is_closed(self):
        case = {"rule": "test-rule", "path": "any", "index": 0,
                "classification": "weak-count-oracle", "source": "inert",
                "expected": 1, "deleted_expected": 2}
        for classification in ("missing-fixture", "weak-count-oracle"):
            PROBE.validate_witness_case({**case, "classification": classification})
        PROBE.validate_witness_case({"rule": "test-rule", "classification": "equivalent"})
        for classification in ("unsupported", "Equivalent", "weak-count-oracle "):
            with self.subTest(classification=classification), \
                    self.assertRaisesRegex(ValueError, "classification"):
                PROBE.validate_witness_case({**case, "classification": classification})

    def test_duplicate_witness_identities_are_rejected(self):
        case = {"rule": "test-rule", "path": "any", "index": 0,
                "classification": "weak-count-oracle", "source": "inert",
                "expected": 1, "deleted_expected": 2}
        for duplicate in (dict(case), {**case, "expected": 99}):
            for cases in ([case, duplicate], [duplicate, case]):
                with self.subTest(cases=cases), \
                        coverage_cases(cases), \
                        self.assertRaisesRegex(ValueError, "duplicate witness"):
                    self.assertEqual(json.loads('{"control": true}'), {"control": True})
                    PROBE.arm_witnesses({"id": "test-rule"})
        cases = [case, {**case, "rule": "other-rule"}, {**case, "path": "other/any"},
                 {**case, "index": 1}, {"rule": "test-rule", "classification": "equivalent"}]
        with coverage_cases(cases):
            self.assertEqual(set(PROBE.arm_witnesses({"id": "test-rule"})),
                             {("any", 0), ("other/any", 0), ("any", 1)})

    def test_witness_counts_must_match_both_expected_results(self):
        rule = {"id": "test-rule", "rule": {"any": [{"pattern": "a"}, {"pattern": "b"}]}}
        cases = [{"rule": "test-rule", "path": "any", "index": index,
                  "classification": "weak-count-oracle", "source": "inert",
                  "expected": 1, "deleted_expected": 2} for index in (0, 1)]
        iso = SimpleNamespace(test=lambda _rule: (0, "test result: ok. 1 passed; 0 failed;"))
        for counts, expected in (([(1, ""), (2, "")] * 2, True),
                                 ([(1, ""), (1, "")] * 2, False),
                                 ([(0, ""), (2, "")] * 2, False),
                                 ([(None, "failed"), (2, "")] * 2, False),
                                 ([(1, ""), (None, "failed")] * 2, False)):
            with self.subTest(counts=counts), \
                    coverage_cases(cases), \
                    patch.object(PROBE, "scan_stdin", side_effect=counts):
                self.assertEqual(json.loads('{"control": true}'), {"control": True})
                self.assertEqual(PROBE.check_arms(iso, rule)[0], expected)

    def test_snapshot_refresh_and_missing_output(self):
        source_rule, source_fixture = PROBE.find_rule("go-tls-min-version")
        real_run = subprocess.run
        for failure in (False, True):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                rule = root / source_rule.relative_to(ROOT)
                fixture = root / source_fixture.relative_to(ROOT)
                for target, source in ((rule, source_rule), (fixture, source_fixture)):
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(source.read_bytes())
                (root / "sgconfig.yml").write_text("ruleDirs: [rules]\ntestConfigs: [{testDir: tests}]\n")
                snapshot = root / "tests/__snapshots__/go-tls-min-version-snapshot.yml"
                if not failure:
                    snapshot.parent.mkdir()
                    snapshot.write_text("id: go-tls-min-version\nsnapshots: {}\n")

                def update(command, *args, fail=failure, **kwargs):
                    if fail and "-U" in command:
                        return subprocess.CompletedProcess(command, 2, "", "injected missing snapshot")
                    return real_run(command, *args, **kwargs)

                with patch.object(PROBE, "ROOT", root), \
                        patch.object(PROBE.subprocess, "run", side_effect=update), \
                        patch("sys.argv", ["probe", "go-tls-min-version", "--json", "--snapshot"]), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(PROBE.main(), int(failure))
                report = json.loads(output.getvalue())
                self.assertEqual(report["ok"], not failure)
                self.assertEqual("snapshot" in report, not failure)
                if failure:
                    self.assertFalse(snapshot.exists())
                    self.assertIn("injected missing snapshot", output.getvalue())
                else:
                    self.assertTrue(yaml.safe_load(report["snapshot"])["snapshots"])

    def test_real_probe_uses_running_interpreter_with_different_path(self):
        # A second environment on PATH must not choose the test's child runtime.
        with tempfile.TemporaryDirectory() as directory:
            shadow = Path(directory) / "python3"
            shadow.write_text("#!/bin/sh\necho wrong-PATH-interpreter >&2\nexit 97\n")
            shadow.chmod(0o755)
            with patch.dict(os.environ, {"PATH": directory + os.pathsep + os.environ["PATH"]}):
                control = subprocess.run(["python3", "--version"], capture_output=True,
                                         text=True, check=False, timeout=10)
                self.assertEqual(control.returncode, 97)
                self.assertIn("wrong-PATH-interpreter", control.stderr)
                self.test_real_rule_passes_all_probe_phases()

    def test_missing_binary_has_json_failure(self):
        with patch.object(PROBE, "AST_GREP", ROOT / "missing-ast-grep"), \
                patch("sys.argv", ["probe", "go-tls-min-version", "--json"]), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(PROBE.main(), 2)
        self.assertFalse(json.loads(output.getvalue())["ok"])
        self.assertIn("npm ci", output.getvalue())

    def test_brief_report_omits_successful_checks(self):
        report = {"rule": "rules/go/security/go-test.yml", "checks": [
            {"name": "layout", "ok": True, "detail": "expected layout"},
            {"name": "fixture-counts", "ok": False, "detail": "invalid[0]=0"},
        ]}
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(PROBE.finish(report, False, False, brief=True), 1)
        self.assertEqual(output.getvalue(), (
            "rules/go/security/go-test.yml: FAIL\n"
            "  [FAIL] fixture-counts: invalid[0]=0\n"
        ))

    def test_brief_report_keeps_independent_failed_gates(self):
        checks = [
            {"name": "fixture-counts", "ok": False, "detail": "invalid[0]=0"},
            {"name": "fixture-run", "ok": False, "detail": "test failed"},
            {"name": "arm-kills", "ok": False, "detail": "invalid mutant"},
            {"name": "discovery", "ok": False, "detail": "0 findings"},
            {"name": "note-literal", "ok": False, "detail": "missing note"},
        ]
        self.assertEqual([item["name"] for item in PROBE.brief_failures(checks)],
                         ["fixture-counts", "fixture-run", "arm-kills", "discovery",
                          "note-literal"])

    def test_brief_pass_is_one_line(self):
        report = {"rule": "rules/go/security/go-test.yml", "checks": [
            {"name": "layout", "ok": True, "detail": "expected layout"},
        ]}
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(PROBE.finish(report, True, False, brief=True), 0)
        self.assertEqual(output.getvalue(), "rules/go/security/go-test.yml: PASS\n")

    def test_empty_failed_fixture_run_has_json_failure(self):
        with patch.object(PROBE.Isolated, "test", return_value=(-9, "")), \
                patch("sys.argv", ["probe", "go-tls-min-version", "--json"]), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(PROBE.main(), 1)
        self.assertFalse(json.loads(output.getvalue())["ok"])
        self.assertIn("no output, exit -9", output.getvalue())
    def test_only_fixture_failure_counts_as_arm_kill(self):
        rule = {"rule": {"any": [{"pattern": "a"}, {"pattern": "b"}]}}
        for rc, output, expected in ((8, "Cannot parse rule", False), (2, "tool failure", False),
                                     (4, "Error: test failed.", True), (4, "", False),
                                     (0, "test result: ok. 1 passed; 0 failed;", False)):
            with self.subTest(rc=rc, output=output):
                iso = SimpleNamespace(test=lambda _rule, status=rc, text=output: (status, text))
                self.assertEqual(PROBE.check_arms(iso, rule)[0], expected)

    def test_malformed_fixture_returns_failed_report(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(PROBE, "ROOT", Path(directory)):
            root = Path(directory)
            rule = root / "rules/go/security/go-test.yml"
            fixture = root / "tests/go/security/go-test.yml"
            rule.parent.mkdir(parents=True)
            fixture.parent.mkdir(parents=True)
            rule.write_text("id: go-test\nlanguage: go\nrule: {pattern: bad($X)}\n")
            for text in ("", "scalar", "[", "id: go-test\nvalid: [safe]\n",
                         "id: go-test\nvalid: [safe]\ninvalid: [null]\n"):
                fixture.write_text(text)
                checks = []
                result = PROBE.load_inputs(rule, fixture, lambda *args, rows=checks: rows.append(args))
                self.assertIsNone(result, text)
                self.assertTrue(any(not item[1] for item in checks), text)

    def test_real_rule_passes_all_probe_phases(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/rule-probe.py"), "go-tls-min-version", "--json"],
            capture_output=True, text=True, check=False, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        report = json.loads(result.stdout)
        self.assertTrue(report["ok"])
        checks = {item["name"]: item["ok"] for item in report["checks"]}
        for name in ("fixture-counts", "fixture-run", "arm-kills", "discovery"):
            self.assertTrue(checks[name], name)

    def test_real_rule_accepts_an_immutable_input_root(self):
        rule_path, fixture_path = PROBE.find_rule("go-tls-min-version")
        snapshot = ROOT / "tests/__snapshots__/go-tls-min-version-snapshot.yml"
        private_id = "go-immutable-input-root"
        with tempfile.TemporaryDirectory() as directory:
            input_root = Path(directory)
            renamed = {
                rule_path: Path("rules/go/security") / f"{private_id}.yml",
                fixture_path: Path("tests/go/security") / f"{private_id}.yml",
                snapshot: Path("tests/__snapshots__") / f"{private_id}-snapshot.yml",
            }
            for source, relative in renamed.items():
                destination = input_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(source.read_text().replace("go-tls-min-version", private_id))
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/rule-probe.py"),
                 private_id, "--json", "--input-root", str(input_root)],
                capture_output=True, text=True, check=False, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertTrue(json.loads(result.stdout)["ok"])

    def test_real_rule_brief_pass_is_one_line(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/rule-probe.py"),
             "go-tls-min-version", "--brief"],
            capture_output=True, text=True, check=False, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(result.stdout,
                         "rules/go/security/go-tls-min-version.yml: PASS\n")

    def test_fixture_counts_reject_missing_positive_and_matching_negative(self):
        with patch.object(PROBE, "scan_sources", return_value=[(0, ""), (1, "")]):
            passed, detail, multiple = PROBE.fixture_counts({}, ["safe"], ["bad"])
        self.assertFalse(passed)
        self.assertEqual(detail, "invalid[0]=0; valid[0]=1")
        self.assertEqual(multiple, [])

    def test_fixture_counts_use_one_scan_and_preserve_per_source_counts(self):
        rule = {"id": "probe", "language": "go", "rule": {"pattern": "bad($X)"}}

        def run(command, **_kwargs):
            self.assertEqual(_kwargs["timeout"], 19)
            directory = Path(command[-1])
            self.assertNotEqual(directory, ROOT)
            self.assertNotIn(ROOT, directory.parents)
            findings = [
                {"ruleId": "probe", "file": str(directory / "invalid-0.go")},
                {"ruleId": "probe", "file": str(directory / "invalid-0.go")},
            ]
            return SimpleNamespace(returncode=1, stdout=json.dumps(findings), stderr="")

        with patch.object(PROBE.subprocess, "run", side_effect=run) as runner:
            passed, detail, multiple = PROBE.fixture_counts(rule, ["good(x)"], ["bad(x)"])
        self.assertTrue(passed)
        self.assertEqual(runner.call_count, 1)
        self.assertEqual(detail, "invalid[0]=2; valid[0]=0")
        self.assertEqual(multiple, ["invalid[0]=2"])

    def test_isolated_probe_uses_system_temporary_directory(self):
        rule = ROOT / "rules/go/security/go-tls-min-version.yml"
        fixture = ROOT / "tests/go/security/go-tls-min-version.yml"
        isolated = PROBE.Isolated(rule, fixture)
        try:
            directory = Path(isolated.tmp.name)
            self.assertNotEqual(directory, ROOT)
            self.assertNotIn(ROOT, directory.parents)
        finally:
            isolated.close()

    def test_discovery_uses_system_temporary_directory(self):
        rule = ROOT / "rules/go/security/go-tls-min-version.yml"

        def run(command, **_kwargs):
            target = Path(command[-1])
            self.assertNotEqual(target.parent, ROOT)
            self.assertNotIn(ROOT, target.parents)
            return SimpleNamespace(returncode=1, stdout=json.dumps([
                {"ruleId": "go-tls-min-version", "file": str(target)}]), stderr="")

        with patch.object(PROBE.subprocess, "run", side_effect=run):
            passed, _detail = PROBE.discover(rule, "go", "bad(x)")
        self.assertTrue(passed)

    def test_batched_scan_rejects_bad_process_or_attribution(self):
        rule = {"id": "probe", "language": "go", "rule": {"pattern": "bad($X)"}}
        cases = [
            SimpleNamespace(returncode=2, stdout="", stderr="engine failed"),
            SimpleNamespace(returncode=0, stdout="{}", stderr=""),
            SimpleNamespace(returncode=1,
                            stdout='[{"ruleId":"other","file":"foreign.go"}]', stderr=""),
        ]
        for result in cases:
            with self.subTest(result=result), patch.object(
                    PROBE.subprocess, "run", return_value=result):
                counts = PROBE.scan_sources(rule, [("invalid", 0, "bad(x)")])
            self.assertIsNone(counts[0][0])
            self.assertTrue(counts[0][1])

    def test_scan_rejects_tool_failure_and_malformed_output(self):
        rule = {"id": "probe"}
        for rc, stdout in ((2, ""), (0, "{"), (0, "{}"), (0, '[{"ruleId":"other"}]')):
            with self.subTest(rc=rc, stdout=stdout), patch.object(PROBE.subprocess, "run",
                    return_value=SimpleNamespace(returncode=rc, stdout=stdout, stderr="error")):
                self.assertIsNone(PROBE.scan_stdin(rule, "inert")[0])
        for rc, stdout, count in ((0, "[]", 0), (1, '[{"ruleId":"probe"}]', 1)):
            with patch.object(PROBE.subprocess, "run",
                    return_value=SimpleNamespace(returncode=rc, stdout=stdout, stderr="")):
                self.assertEqual(PROBE.scan_stdin(rule, "inert"), (count, ""))

    def test_nested_arm_removal_preserves_original(self):
        rule = {"rule": {"all": [{"any": [{"pattern": "a"}, {"pattern": "b"}]}]}}
        arms = list(PROBE.any_arms(rule["rule"]))
        self.assertEqual(arms, [(("all", 0, "any"), 0), (("all", 0, "any"), 1)])
        mutant = PROBE.delete_arm(rule, *arms[0])
        self.assertEqual(mutant["rule"]["all"][0]["any"], [{"pattern": "b"}])
        self.assertEqual(len(rule["rule"]["all"][0]["any"]), 2)


class ScaffoldTests(unittest.TestCase):
    @staticmethod
    def make_scaffold_case(root):
        guard = root / "tests/test_diagnostics.py"
        guard.parent.mkdir()
        guard.write_text("self.assertEqual(len(rules), 3)\nself.assertEqual(checked, 3)\n")
        matcher = root / "matcher.yml"
        matcher.write_text("pattern: bad($X)\n")
        argv = ["rule-scaffold", "--id", "go-test-rule", "--language", "go",
                "--category", "security", "--positive", "bad(x)",
                "--near-miss", "good(x)", "--claim", "Check call", "--matcher", str(matcher)]
        return guard, argv

    def test_count_temporary_files_are_ignored(self):
        self.assertIn(".rule-count-*", (ROOT / ".gitignore").read_text(
            encoding="utf-8").splitlines())

    def test_same_id_concurrent_scaffolds_are_revalidated_under_lock(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            guard, argv = self.make_scaffold_case(root)
            matcher = Path(argv[-1])
            first_validated = threading.Event()
            second_started = threading.Event()
            second_contended = threading.Event()
            release_first = threading.Event()
            timeout = 10
            thread_args = threading.local()
            original_prepare = SCAFFOLD.prepare_scaffold
            original_sleep = SCAFFOLD.sleep

            def prepare(args):
                result = original_prepare(args)
                if args.category == "security":
                    first_validated.set()
                    release_first.wait()
                return result

            def contention_sleep(_delay):
                if thread_args.value.category == "correctness":
                    second_contended.set()
                    release_first.wait()
                original_sleep(_delay)

            def run(category):
                thread_args.value = SimpleNamespace(
                    id="go-test-rule", proposal=None, language="go", category=category,
                    positive="bad(x)", near_miss="good(x)", claim="Check call",
                    matcher=matcher, severity="warning", dry_run=False)
                if category == "correctness":
                    second_started.set()
                return SCAFFOLD.main()

            with patch.object(SCAFFOLD.argparse.ArgumentParser, "parse_args",
                              side_effect=lambda: thread_args.value), \
                    patch.object(SCAFFOLD, "prepare_scaffold", side_effect=prepare), \
                    patch.object(SCAFFOLD, "sleep", side_effect=contention_sleep), \
                    patch("builtins.print"), ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(run, "security")
                try:
                    self.assertTrue(first_validated.wait(timeout))
                    second = pool.submit(run, "correctness")
                    self.assertTrue(second_started.wait(timeout))
                    self.assertTrue(second_contended.wait(timeout), "second scaffold did not contend")
                finally:
                    release_first.set()
                self.assertEqual(first.result(timeout=timeout), 0)
                with self.assertRaisesRegex(SystemExit, "already exists"):
                    second.result(timeout=timeout)
            self.assertTrue((root / "rules/go/security/go-test-rule.yml").exists())
            self.assertFalse((root / "rules/go/correctness/go-test-rule.yml").exists())
            self.assertEqual(guard.read_text(encoding="utf-8").count(", 4)"), 2)

    def test_cli_lock_timeout_is_reported_without_traceback(self):
        argv = ["rule-scaffold", "--id", "go-test-rule", "--category", "security",
                "--dry-run"]
        with patch("sys.argv", argv), \
                patch.object(SCAFFOLD, "scaffold_lock",
                             side_effect=TimeoutError("timed out waiting for the scaffold lock")), \
                self.assertRaisesRegex(SystemExit, "timed out waiting for the scaffold lock"):
            SCAFFOLD.main()

    def test_cli_lock_wrapper_does_not_relabel_body_timeouts(self):
        with patch.object(SCAFFOLD, "scaffold_lock", return_value=contextlib.nullcontext()), \
                self.assertRaisesRegex(TimeoutError, "body operation"), \
                SCAFFOLD.cli_scaffold_lock():
            raise TimeoutError("body operation timed out")

    def test_cli_lock_permission_failure_is_a_readable_refusal(self):
        with patch.object(SCAFFOLD, "scaffold_lock",
                          side_effect=PermissionError("read-only lock location")), \
                self.assertRaisesRegex(SystemExit,
                                       "cannot acquire scaffold lock: read-only lock location"), \
                SCAFFOLD.cli_scaffold_lock():
            self.fail("unavailable lock was acquired")

    def test_windows_lock_does_not_access_contents_before_locking(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "scaffold.lock"
            fake_msvcrt = SimpleNamespace(LK_NBLCK=1, LK_UNLCK=2, calls=[])
            fake_msvcrt.locking = lambda _fd, mode, count: fake_msvcrt.calls.append((mode, count))
            with patch.object(SCAFFOLD, "repository_lock_path", return_value=lock_path), \
                    patch.object(SCAFFOLD, "WINDOWS", True), \
                    patch.dict(sys.modules, {"msvcrt": fake_msvcrt}), SCAFFOLD.scaffold_lock():
                self.assertEqual(fake_msvcrt.calls, [(fake_msvcrt.LK_NBLCK, 1)])
            self.assertEqual(fake_msvcrt.calls, [
                (fake_msvcrt.LK_NBLCK, 1), (fake_msvcrt.LK_UNLCK, 1)])
            self.assertEqual(lock_path.read_bytes(), b"")

    def test_windows_lock_retries_sharing_violations(self):
        def failing_once(error_code):
            fake = SimpleNamespace(LK_NBLCK=1, LK_UNLCK=2, calls=[])

            def locking(_fd, mode, count):
                fake.calls.append((mode, count))
                if mode == fake.LK_NBLCK and fake.calls.count((mode, count)) == 1:
                    raise OSError(error_code, "temporarily locked")

            fake.locking = locking
            return fake

        for error_code in (SCAFFOLD.errno.EACCES, SCAFFOLD.errno.EDEADLK):
            with self.subTest(error_code=error_code), tempfile.TemporaryDirectory() as directory:
                lock_path = Path(directory) / "scaffold.lock"
                fake_msvcrt = failing_once(error_code)
                with patch.object(SCAFFOLD, "repository_lock_path", return_value=lock_path), \
                        patch.object(SCAFFOLD, "WINDOWS", True), \
                        patch.dict(sys.modules, {"msvcrt": fake_msvcrt}), \
                        patch.object(SCAFFOLD, "sleep") as sleeper, \
                        SCAFFOLD.scaffold_lock():
                    pass
                self.assertEqual(fake_msvcrt.calls, [
                    (fake_msvcrt.LK_NBLCK, 1), (fake_msvcrt.LK_NBLCK, 1),
                    (fake_msvcrt.LK_UNLCK, 1)])
                sleeper.assert_called_once_with(SCAFFOLD.LOCK_POLL_SECONDS)

    def test_windows_lock_timeout_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "scaffold.lock"
            fake_msvcrt = SimpleNamespace(LK_NBLCK=1, LK_UNLCK=2)

            def unavailable(*_args):
                raise OSError(SCAFFOLD.errno.EACCES, "still locked")

            fake_msvcrt.locking = unavailable
            with patch.object(SCAFFOLD, "repository_lock_path", return_value=lock_path), \
                    patch.object(SCAFFOLD, "WINDOWS", True), \
                    patch.dict(sys.modules, {"msvcrt": fake_msvcrt}), \
                    patch.object(SCAFFOLD, "monotonic", side_effect=[0, 61]), \
                    patch.object(SCAFFOLD, "sleep") as sleeper, \
                    self.assertRaisesRegex(TimeoutError, "scaffold lock"), \
                    SCAFFOLD.scaffold_lock():
                self.fail("unavailable lock was acquired")
            sleeper.assert_not_called()

    def test_posix_lock_retries_contention_then_unlocks(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "scaffold.lock"
            fake_fcntl = SimpleNamespace(LOCK_EX=1, LOCK_NB=2, LOCK_UN=4, calls=[])
            lock_operation = fake_fcntl.LOCK_EX | fake_fcntl.LOCK_NB

            def flock(_fd, operation):
                fake_fcntl.calls.append(operation)
                if operation == lock_operation and fake_fcntl.calls.count(operation) == 1:
                    raise BlockingIOError(SCAFFOLD.errno.EAGAIN, "temporarily locked")

            fake_fcntl.flock = flock
            with patch.object(SCAFFOLD, "repository_lock_path", return_value=lock_path), \
                    patch.object(SCAFFOLD, "WINDOWS", False), \
                    patch.dict(sys.modules, {"fcntl": fake_fcntl}), \
                    patch.object(SCAFFOLD, "sleep") as sleeper, SCAFFOLD.scaffold_lock():
                pass
            self.assertEqual(fake_fcntl.calls, [lock_operation, lock_operation,
                                                fake_fcntl.LOCK_UN])
            sleeper.assert_called_once_with(SCAFFOLD.LOCK_POLL_SECONDS)

    def test_posix_lock_timeout_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "scaffold.lock"
            fake_fcntl = SimpleNamespace(LOCK_EX=1, LOCK_NB=2, LOCK_UN=4)

            def unavailable(_fd, _operation):
                raise BlockingIOError(SCAFFOLD.errno.EAGAIN, "still locked")

            fake_fcntl.flock = unavailable
            with patch.object(SCAFFOLD, "repository_lock_path", return_value=lock_path), \
                    patch.object(SCAFFOLD, "WINDOWS", False), \
                    patch.dict(sys.modules, {"fcntl": fake_fcntl}), \
                    patch.object(SCAFFOLD, "monotonic", side_effect=[0, 61]), \
                    patch.object(SCAFFOLD, "sleep") as sleeper, \
                    self.assertRaisesRegex(TimeoutError, "scaffold lock"), \
                    SCAFFOLD.scaffold_lock():
                self.fail("unavailable lock was acquired")
            sleeper.assert_not_called()

    def test_linked_worktree_lock_uses_relative_git_directory(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            gitdir = root / "metadata"
            gitdir.mkdir()
            (root / ".git").write_text("gitdir: metadata\n", encoding="utf-8")
            self.assertEqual(SCAFFOLD.repository_lock_path(), gitdir / "rule-scaffold.lock")

    def test_stale_linked_worktree_metadata_uses_repository_fallback(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            (root / ".git").write_text("gitdir: missing-metadata\n", encoding="utf-8")
            self.assertEqual(SCAFFOLD.repository_lock_path(), root / ".rule-scaffold.lock")

    def test_trailing_newline_id_is_refused(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            guard = Path(directory) / "tests/test_diagnostics.py"
            guard.parent.mkdir()
            guard.write_text("self.assertEqual(len(rules), 3)\nself.assertEqual(checked, 3)\n",
                             encoding="utf-8")
            argv = ["rule-scaffold", "--id", "c-check\n", "--language", "c",
                    "--category", "correctness", "--positive", "bad(x)",
                    "--near-miss", "good(x)", "--claim", "Check return value", "--dry-run"]
            with patch("sys.argv", argv), contextlib.redirect_stdout(io.StringIO()), \
                    self.assertRaisesRegex(SystemExit, "not kebab-case"):
                SCAFFOLD.main()
            self.assertFalse((Path(directory) / "rules").exists())

    def test_documented_manual_usage_dry_run(self):
        usage = SCAFFOLD.__doc__.split("Usage:\n", 1)[1].split("\nInputs:", 1)[0]
        commands = usage.replace("\\\n", "").splitlines()
        manual = next(line for line in commands if "--language c" in line)
        argv = shlex.split(manual.replace("[--dry-run]", "--dry-run"))
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            guard = Path(directory) / "tests/test_diagnostics.py"
            guard.parent.mkdir()
            original = "self.assertEqual(len(rules), 3)\nself.assertEqual(checked, 3)\n"
            guard.write_text(original, encoding="utf-8")
            held = False
            original_prepare = SCAFFOLD.prepare_scaffold

            @contextlib.contextmanager
            def observed_lock():
                nonlocal held
                held = True
                try:
                    yield
                finally:
                    held = False

            def prepare(args):
                self.assertTrue(held, "dry-run reads bypassed the scaffold lock")
                return original_prepare(args)

            with patch("sys.argv", argv), patch.object(SCAFFOLD, "scaffold_lock",
                                                       side_effect=observed_lock), \
                    patch.object(SCAFFOLD, "prepare_scaffold", side_effect=prepare), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(SCAFFOLD.main(), 0)
            self.assertIn("message:", output.getvalue())
            self.assertEqual(guard.read_text(encoding="utf-8"), original)
            self.assertFalse((Path(directory) / "rules").exists())

    def test_assess_seed_is_bounded_read_only_and_lock_free(self):
        argv = ["rule-scaffold", "--id", "go-test-rule", "--language", "go",
                "--category", "correctness", "--positive", "bad(x)",
                "--near-miss", "good(x)", "--claim", "Check call", "--seed",
                "--contrast", "--assess-seed"]
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)), patch("sys.argv", argv), \
                patch.object(SCAFFOLD, "seed_matcher", return_value={"pattern": "bad($X)"}), \
                patch.object(SCAFFOLD, "scaffold_lock", side_effect=AssertionError("lock used")), \
                patch.object(SCAFFOLD, "pattern_roots", return_value="call_expression"), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(SCAFFOLD.main(), 0)
            self.assertEqual(len(output.getvalue().splitlines()), 2)
            self.assertIn("SEED PASS", output.getvalue())
            self.assertFalse((Path(directory) / "rules").exists())

    def test_count_update_preserves_utf8_source_under_ascii_defaults(self):
        original = ("# café 🧪\r\nself.assertEqual(len(rules), 3)\n"
                    "self.assertEqual(checked, 3)\r\n").encode()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "tests/test_diagnostics.py"
            path.parent.mkdir()
            path.write_bytes(original)
            with patch.object(SCAFFOLD, "ROOT", root), ascii_text_defaults():
                self.assertEqual(SCAFFOLD.bump_count(True), (3, 4))
                self.assertEqual(path.read_bytes(), original)
                self.assertEqual(SCAFFOLD.bump_count(False), (3, 4))
            self.assertEqual(path.read_bytes(), original.replace(b", 3)", b", 4)"))

    def test_count_update_does_not_unlink_recreated_temp_path(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            guard = root / "tests/test_diagnostics.py"
            guard.parent.mkdir()
            guard.write_text("self.assertEqual(len(rules), 3)\nself.assertEqual(checked, 3)\n")
            original_replace = Path.replace
            recreated = None

            def replace_then_recreate(source, target):
                nonlocal recreated
                original_replace(source, target)
                recreated = source
                source.write_text("new owner")
                raise KeyboardInterrupt("after replace")

            with patch.object(Path, "replace", replace_then_recreate), \
                    contextlib.redirect_stderr(io.StringIO()) as stderr, \
                    self.assertRaisesRegex(KeyboardInterrupt, "after replace"):
                SCAFFOLD.bump_count(False)
            self.assertIsNotNone(recreated)
            self.assertEqual(recreated.read_text(), "new owner")
            self.assertEqual(guard.read_text().count(", 4)"), 2)
            self.assertIn("path ownership changed; left untouched", stderr.getvalue())

    @unittest.skipIf(os.name == "nt", "symlink creation is not generally available on Windows")
    def test_count_update_does_not_unlink_recreated_temp_symlink(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            guard = root / "tests/test_diagnostics.py"
            guard.parent.mkdir()
            guard.write_text("self.assertEqual(len(rules), 3)\nself.assertEqual(checked, 3)\n")
            original_replace = Path.replace
            recreated = None

            def replace_then_recreate(source, target):
                nonlocal recreated
                original_replace(source, target)
                recreated = source
                source.symlink_to(target)
                raise KeyboardInterrupt("after replace")

            with patch.object(Path, "replace", replace_then_recreate), \
                    contextlib.redirect_stderr(io.StringIO()) as stderr, \
                    self.assertRaisesRegex(KeyboardInterrupt, "after replace"):
                SCAFFOLD.bump_count(False)
            self.assertIsNotNone(recreated)
            self.assertTrue(recreated.is_symlink())
            self.assertEqual(guard.read_text().count(", 4)"), 2)
            self.assertIn("path ownership changed; left untouched", stderr.getvalue())

    def test_count_temp_cleanup_failure_is_reported_without_masking_original(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".rule-count-owned"
            path.write_text("partial")
            identity = path.lstat()
            with patch.object(Path, "unlink", side_effect=KeyboardInterrupt("cleanup")), \
                    contextlib.redirect_stderr(io.StringIO()) as stderr:
                SCAFFOLD.remove_owned_temp(path, identity)
            self.assertTrue(path.exists())
            self.assertIn("cleanup failed: cleanup", stderr.getvalue())

    def test_count_temp_identity_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".rule-count-owned"
            path.write_text("partial")
            identity = path.lstat()
            with patch.object(Path, "lstat", side_effect=PermissionError("verify")), \
                    contextlib.redirect_stderr(io.StringIO()) as stderr:
                SCAFFOLD.remove_owned_temp(path, identity)
            self.assertTrue(path.exists())
            self.assertIn("cannot verify ownership: verify", stderr.getvalue())

    def test_count_temp_missing_identity_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".rule-count-owned"
            path.write_text("partial")
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                SCAFFOLD.remove_owned_temp(path, None)
            self.assertTrue(path.exists())
            self.assertIn("ownership identity unavailable", stderr.getvalue())

    def test_windows_unavailable_file_identity_is_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".rule-count-owned"
            path.write_text("partial")
            unavailable = SimpleNamespace(st_dev=0, st_ino=0)
            with patch.object(SCAFFOLD, "WINDOWS", True), \
                    patch.object(Path, "lstat", return_value=unavailable), \
                    patch.object(Path, "unlink") as unlink, \
                    contextlib.redirect_stderr(io.StringIO()) as stderr:
                SCAFFOLD.remove_owned_temp(path, unavailable)
            unlink.assert_not_called()
            self.assertIn("filesystem identity unavailable; left untouched",
                          stderr.getvalue())

    def test_broken_temp_warning_does_not_mask_original_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".rule-count-owned"
            path.write_text("partial")
            identity = path.lstat()
            with patch.object(Path, "lstat", side_effect=PermissionError("verify")), \
                    patch("builtins.print", side_effect=BrokenPipeError("stderr closed")), \
                    self.assertRaisesRegex(KeyboardInterrupt, "original"):
                try:
                    raise KeyboardInterrupt("original")
                finally:
                    SCAFFOLD.remove_owned_temp(path, identity)

    def test_count_update_removes_owned_temp_after_partial_write(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            guard = root / "tests/test_diagnostics.py"
            guard.parent.mkdir()
            original = "self.assertEqual(len(rules), 3)\nself.assertEqual(checked, 3)\n"
            guard.write_text(original)
            named_temp = tempfile.NamedTemporaryFile

            @contextlib.contextmanager
            def partial_writer(*args, **kwargs):
                with named_temp(*args, **kwargs) as output:
                    class Writer:
                        name = output.name

                        @staticmethod
                        def fileno():
                            return output.fileno()

                        @staticmethod
                        def write(text):
                            output.write(text[:10])
                            output.flush()
                            raise OSError("partial write")

                    yield Writer()

            with patch.object(SCAFFOLD.tempfile, "NamedTemporaryFile", partial_writer), \
                    self.assertRaisesRegex(OSError, "partial write"):
                SCAFFOLD.bump_count(False)
            self.assertEqual(guard.read_text(), original)
            self.assertEqual(list(guard.parent.glob(".rule-count-*")), [])

    def test_missing_matcher_is_controlled_refusal(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            args = SimpleNamespace(id="go-test-rule", language="go", proposal=None,
                                   positive="bad(x)", near_miss="good(x)", claim="Check",
                                   category="security", matcher=root / "missing.yml", severity="warning")
            with self.assertRaisesRegex(SystemExit, r"cannot read --matcher.*missing.yml"):
                SCAFFOLD.prepare_scaffold(args)
            self.assertFalse((root / "rules").exists())

    def test_language_prefix_boundary(self):
        for language, rule_id, valid in (("go", "golang-test-rule", False),
                ("c", "cast-test-rule", False), ("java", "javascript-test-rule", False),
                ("go", "go-check", True), ("c", "c-check", True),
                ("c", "nginx-check", True), ("c", "zstd-check", True),
                ("javascript", "js-check", True), ("python", "py-check", True),
                ("php", "wp-check", True), ("bash", "sh-check", True)):
            args = SimpleNamespace(id=rule_id, language=language, proposal=None,
                                   positive="bad(x)", near_miss="good(x)", claim="Check",
                                   category="security", matcher=None, severity="warning")
            with self.subTest(language=language, rule_id=rule_id):
                if valid:
                    self.assertEqual(SCAFFOLD.prepare_scaffold(args)[0].stem, rule_id)
                else:
                    with self.assertRaisesRegex(SystemExit, "prefixed"):
                        SCAFFOLD.prepare_scaffold(args)

    def test_scaffold_dry_run_write_and_overwrite_refusal(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            guard, argv = self.make_scaffold_case(root)
            with contextlib.redirect_stdout(io.StringIO()):
                with patch("sys.argv", [*argv, "--dry-run"]):
                    self.assertEqual(SCAFFOLD.main(), 0)
                self.assertFalse((root / "rules").exists())
                original_open = Path.open

                def fail_rule_write(path, mode="r", *values, **kwargs):
                    if path.name == "go-test-rule.yml" and mode in ("x", "w"):
                        raise OSError("injected output failure")
                    return original_open(path, mode, *values, **kwargs)

                with patch("sys.argv", argv), patch.object(Path, "open", fail_rule_write), \
                        self.assertRaisesRegex(OSError, "injected output failure"):
                    SCAFFOLD.main()
                self.assertEqual(guard.read_text().count(", 3)"), 2)

                def fail_fixture_write(path, mode="r", *values, **kwargs):
                    if path == root / "tests/go/security/go-test-rule.yml" and mode in ("x", "w"):
                        raise OSError("injected fixture failure")
                    return original_open(path, mode, *values, **kwargs)

                original_bump = SCAFFOLD.bump_count

                def fail_count_write(dry_run):
                    if not dry_run:
                        raise OSError("injected count failure")
                    return original_bump(dry_run)

                for failure in (patch.object(Path, "open", fail_fixture_write),
                                patch.object(SCAFFOLD, "bump_count", fail_count_write),
                                patch.object(Path, "replace", side_effect=OSError("count failure"))):
                    with patch("sys.argv", argv), failure, self.assertRaises(OSError):
                        SCAFFOLD.main()
                    self.assertFalse((root / "rules/go/security/go-test-rule.yml").exists())
                    self.assertFalse((root / "tests/go/security/go-test-rule.yml").exists())
                    self.assertFalse((root / "rules").exists())
                    self.assertFalse((root / "tests/go").exists())
                    self.assertEqual(guard.read_text().count(", 3)"), 2)

                def fail_fixture_encoding(path, *values, **kwargs):
                    mode = values[0] if values else kwargs.get("mode", "r")
                    if path == root / "tests/go/security/go-test-rule.yml" and mode == "x":
                        raise UnicodeEncodeError("ascii", "é", 0, 1, "injected encoding failure")
                    return original_open(path, *values, **kwargs)

                with patch("sys.argv", argv), patch.object(Path, "open", fail_fixture_encoding), \
                        self.assertRaisesRegex(UnicodeEncodeError, "injected encoding failure"):
                    SCAFFOLD.main()
                self.assertFalse((root / "rules/go/security/go-test-rule.yml").exists())
                self.assertFalse((root / "tests/go/security/go-test-rule.yml").exists())
                self.assertFalse((root / "rules").exists())
                self.assertFalse((root / "tests/go").exists())
                self.assertEqual(guard.read_text().count(", 3)"), 2)

                with patch("sys.argv", argv):
                    self.assertEqual(SCAFFOLD.main(), 0)
                with patch("sys.argv", argv), self.assertRaisesRegex(SystemExit, "refusing to overwrite"):
                    SCAFFOLD.main()
            rule = yaml.safe_load((root / "rules/go/security/go-test-rule.yml").read_text())
            fixture = yaml.safe_load((root / "tests/go/security/go-test-rule.yml").read_text())
            self.assertEqual(rule["rule"], {"pattern": "bad($X)"})
            self.assertEqual(fixture, {"id": "go-test-rule",
                                      "valid": ["good(x)", "// bad(x)",
                                                'var astgrepFixture = "bad(x)"'],
                                      "invalid": ["bad(x)"]})
            self.assertEqual(guard.read_text().count(", 4)"), 2)

    def test_scaffold_generates_required_lexical_controls_for_every_language(self):
        self.assertEqual(SCAFFOLD.lexical_controls("go", 'bad("x")', "good()"),
                         ["good()", '// bad("x")', 'var astgrepFixture = "bad(\\"x\\")"'])
        self.assertEqual(SCAFFOLD.lexical_controls("c", "bad();\nreturn 0;", "good();"),
                         ["good();", "// bad();\n// return 0;",
                          'const char *astgrep_fixture = "bad();\\nreturn 0;";'])
        cases = {
            "python": ("# bad()", 'astgrep_fixture = "bad()"'),
            "javascript": ("// bad()", 'const astgrepFixture = "bad()";'),
            "java": ("// bad()", 'class AstgrepFixture { String value = "bad()"; }'),
            "lua": ("-- bad()", 'local astgrep_fixture = "bad()"'),
            "bash": ("# bad()", "astgrep_fixture='bad()'"),
            "php": ("<?php\n// bad()", "<?php\n$astgrep_fixture = 'bad()';"),
        }
        for language, expected in cases.items():
            with self.subTest(language=language):
                self.assertEqual(SCAFFOLD.lexical_controls(language, "bad()", "good()"),
                                 ["good()", *expected])

    def test_php_comment_control_neutralizes_close_tags(self):
        positive = "<?php bad(); ?>\n<?php bad(); ?>"
        controls = SCAFFOLD.lexical_controls("php", positive, "<?php good(); ?>")
        self.assertEqual(controls[1],
                         "<?php\n// <?php bad(); ? >\n// <?php bad(); ? >")
        self.assertNotIn("?>", controls[1])

    def test_contrast_is_bounded_to_structural_token_delta(self):
        self.assertEqual(SCAFFOLD.distinct_tokens(
            "if i+1 > len(data) { return }", "if i+1 >= len(data) { return }"), [">"])
        self.assertEqual(SCAFFOLD.distinct_tokens(
            "call(a, a, 4, 5, 6, 7, 8, 9, 10)", "call(a)"),
            [",", "a", "4", "5", "6", "7", "8", "9"])
        rule = "language: go\n"
        fixture = "invalid: ['if x && y {}']\nvalid: ['if x || y {}']\n"
        with patch.object(SCAFFOLD, "pattern_roots", side_effect=("if_statement", "if_statement")):
            line = SCAFFOLD.contrast_line(rule, fixture)
        self.assertEqual(line, "CONTRAST roots positive=if_statement near=if_statement; "
                               'positive-only=["&&"]; near-only=["||"]')

    def test_seed_generalizes_local_identifiers_but_keeps_claim_vocabulary(self):
        pattern, bindings = SCAFFOLD.generalized_pattern(
            "c-read-eof", "while (remaining) { n = read(fd, p, remaining); break; }")
        self.assertEqual(bindings,
                         {"remaining": "$V0", "n": "$V1", "fd": "$V2", "p": "$V3"})
        self.assertEqual(pattern,
                         "while ($V0) { $V1 = read($V2, $V3, $V0); break; }")

    def test_seed_matcher_requires_generalization_and_oracle_pass(self):
        with patch.object(SCAFFOLD, "seed_oracle", return_value=True) as oracle:
            matcher = SCAFFOLD.seed_matcher(
                "go-range-and", "go", "if value < low && value > high {}", ["safe()"])
        self.assertEqual(matcher, {"pattern": "if $V0 < $V1 && $V0 > $V2 {}"})
        oracle.assert_called_once()
        with patch.object(SCAFFOLD, "seed_oracle", return_value=False):
            self.assertIsNone(SCAFFOLD.seed_matcher(
                "go-range-and", "go", "if value < low && value > high {}", ["safe()"]))
        with patch.object(SCAFFOLD, "seed_oracle") as oracle:
            self.assertIsNone(SCAFFOLD.seed_matcher(
                "go-panic", "go", 'panic("bad")', ["return nil"]))
        oracle.assert_not_called()

    def test_seed_oracle_batches_fixtures_and_rejects_bad_engine_output(self):
        rule = {"id": "go-test-rule", "language": "go", "severity": "warning",
                "message": "seed", "note": "provisional", "rule": {"pattern": "bad($V0)"}}

        def passing(command, **_kwargs):
            directory = Path(command[-1])
            self.assertNotEqual(directory, ROOT)
            self.assertNotIn(ROOT, directory.parents)
            finding = {"ruleId": "go-test-rule", "file": str(directory / "invalid-0.go")}
            return SimpleNamespace(returncode=1, stdout=json.dumps([finding]), stderr="")

        with patch.object(SCAFFOLD.subprocess, "run", side_effect=passing) as runner:
            self.assertTrue(SCAFFOLD.seed_oracle(rule, "bad(x)", ["good(x)", "// bad(x)"]))
        self.assertEqual(runner.call_count, 1)
        for result in (SimpleNamespace(returncode=2, stdout="", stderr="failed"),
                       SimpleNamespace(returncode=0, stdout="{}", stderr=""),
                       SimpleNamespace(returncode=1,
                                       stdout='[{"ruleId":"other","file":"x"}]', stderr="")):
            with self.subTest(result=result), \
                    patch.object(SCAFFOLD.subprocess, "run", return_value=result):
                self.assertFalse(SCAFFOLD.seed_oracle(rule, "bad(x)", ["good(x)"]))
        with patch.object(Path, "is_file", return_value=True), \
                patch.object(SCAFFOLD.subprocess, "run",
                             side_effect=subprocess.TimeoutExpired(["ast-grep"], 15)):
            self.assertFalse(SCAFFOLD.seed_oracle(rule, "bad(x)", ["good(x)"]))

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)), \
                self.assertRaisesRegex(SystemExit, "run npm ci"):
            SCAFFOLD.seed_oracle(rule, "bad(x)", ["good(x)"])
        self.assertEqual(set(SCAFFOLD.EXTENSIONS), set(SCAFFOLD.LANGUAGES))
        self.assertEqual(SCAFFOLD.EXTENSIONS, PROBE.EXTENSIONS)
        self.assertEqual(SCAFFOLD.ID_PREFIXES, PACKETS.ID_PREFIXES)
        self.assertEqual(HISTORY.SOURCE_LANGUAGES, PACKETS.LANGUAGE_SUFFIXES)
        unsupported = {**rule, "language": "powershell"}
        with self.assertRaisesRegex(SystemExit, "no fixture oracle"):
            SCAFFOLD.seed_oracle(unsupported, "bad(x)", ["good(x)"])

    def test_rendered_seed_is_provisional_and_falls_back_to_todo(self):
        args = SimpleNamespace(id="go-test-rule", matcher=None, seed=True, severity="warning")
        with patch.object(SCAFFOLD, "seed_matcher", return_value={"pattern": "bad($V0)"}):
            rule_text, _fixture = SCAFFOLD.render_scaffold(
                args, {}, "go", "bad(x)", "good(x)", "Check call")
        self.assertEqual(yaml.safe_load(rule_text)["rule"], {"pattern": "bad($V0)"})
        self.assertIn("review generality", SCAFFOLD.seed_line(rule_text))
        with patch.object(SCAFFOLD, "seed_matcher", return_value=None):
            rule_text, _fixture = SCAFFOLD.render_scaffold(
                args, {}, "go", "bad(x)", "good(x)", "Check call")
        self.assertIsInstance(yaml.safe_load(rule_text)["rule"], str)
        self.assertIn("SEED NONE", SCAFFOLD.seed_line(rule_text))

    def test_seed_cli_dry_run_is_bounded_and_does_not_write(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
                SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            guard = root / "tests/test_diagnostics.py"
            guard.parent.mkdir()
            guard.write_text("self.assertEqual(len(rules), 3)\nself.assertEqual(checked, 3)\n")
            argv = ["rule-scaffold", "--id", "go-test-rule", "--language", "go",
                    "--category", "correctness", "--positive", "bad(x)",
                    "--near-miss", "good(x)", "--claim", "Check call", "--seed",
                    "--contrast", "--dry-run"]
            with patch("sys.argv", argv), patch.object(
                    SCAFFOLD, "seed_matcher", return_value={"pattern": "bad($V0)"}), \
                    patch.object(SCAFFOLD, "pattern_roots", return_value="call_expression"), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(SCAFFOLD.main(), 0)
            self.assertIn("SEED PASS fixture oracle", output.getvalue())
            self.assertIn("CONTRAST roots positive=call_expression", output.getvalue())
            self.assertFalse((root / "rules").exists())
            self.assertEqual(guard.read_text().count(", 3)"), 2)

    def test_seed_and_explicit_matcher_are_refused(self):
        args = SimpleNamespace(id="go-test-rule", matcher=Path("matcher.yml"), seed=True,
                               severity="warning")
        with self.assertRaisesRegex(SystemExit, "mutually exclusive"):
            SCAFFOLD.render_scaffold(args, {}, "go", "bad(x)", "good(x)", "Check")

    def test_pattern_roots_handles_missing_engine_and_parser_failure(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            self.assertEqual(SCAFFOLD.pattern_roots("go", "bad()"), "engine-missing")
        with patch.object(Path, "is_file", return_value=True), \
                patch.object(SCAFFOLD.subprocess, "run",
                             side_effect=subprocess.TimeoutExpired(["ast-grep"], 15)):
            self.assertEqual(SCAFFOLD.pattern_roots("go", "bad()"), "unparsed")

    def test_lexical_controls_reject_unmapped_language_cleanly(self):
        with self.assertRaisesRegex(SystemExit, "no string-literal control"):
            SCAFFOLD.lexical_controls("rust", "bad()", "good()")

    def test_pattern_roots_discards_logs_and_bounds_top_level_kinds(self):
        parsed = SimpleNamespace(stderr="warning\nDebug AST:\nsource_file (0,0)-(0,1)\n"
                                 "  first (0,0)-(0,1)\n  second (0,0)-(0,1)\n"
                                 "  third (0,0)-(0,1)\n  fourth (0,0)-(0,1)\n"
                                 "  fifth (0,0)-(0,1)\nSTDIN:x\n", stdout="")
        with patch.object(SCAFFOLD.subprocess, "run", return_value=parsed):
            self.assertEqual(SCAFFOLD.pattern_roots("go", "x"),
                             "first,second,third,fourth")

    def test_directory_creation_failure_rolls_back_owned_directories(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            _, argv = self.make_scaffold_case(root)
            original_mkdir = Path.mkdir

            def fail_fixture_mkdir(path, *values, **kwargs):
                if path == root / "tests/go":
                    raise PermissionError("injected directory failure")
                return original_mkdir(path, *values, **kwargs)

            with patch("sys.argv", argv), patch.object(Path, "mkdir", fail_fixture_mkdir), \
                    self.assertRaisesRegex(PermissionError, "injected directory failure"):
                SCAFFOLD.main()
            self.assertFalse((root / "rules").exists())
            self.assertFalse((root / "tests/go").exists())

    def test_interrupt_rollback_depends_on_atomic_count_commit(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            guard, argv = self.make_scaffold_case(root)
            original_replace = Path.replace

            with patch("sys.argv", argv), \
                    patch.object(Path, "replace", side_effect=KeyboardInterrupt), \
                    self.assertRaises(KeyboardInterrupt):
                SCAFFOLD.main()
            self.assertFalse((root / "rules/go/security/go-test-rule.yml").exists())
            self.assertFalse((root / "tests/go/security/go-test-rule.yml").exists())
            self.assertEqual(guard.read_text(encoding="utf-8").count(", 3)"), 2)

            def replace_then_interrupt(source, target):
                original_replace(source, target)
                raise KeyboardInterrupt

            with patch("sys.argv", argv), patch.object(Path, "replace", replace_then_interrupt), \
                    contextlib.redirect_stderr(io.StringIO()) as stderr, \
                    self.assertRaises(KeyboardInterrupt):
                SCAFFOLD.main()
            self.assertTrue((root / "rules/go/security/go-test-rule.yml").exists())
            self.assertTrue((root / "tests/go/security/go-test-rule.yml").exists())
            self.assertEqual(guard.read_text(encoding="utf-8").count(", 4)"), 2)
            self.assertIn("outputs and count were committed before the interrupt",
                          stderr.getvalue())
            self.assertIn("rules/go/security/go-test-rule.yml", stderr.getvalue())
            self.assertIn("tests/go/security/go-test-rule.yml", stderr.getvalue())

    def test_interrupt_preserves_committed_outputs_when_count_reread_fails(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            guard, argv = self.make_scaffold_case(root)
            args = SimpleNamespace(
                id="go-test-rule", proposal=None, language="go", category="security",
                positive="bad(x)", near_miss="good(x)", claim="Check call",
                matcher=root / "matcher.yml", severity="warning", dry_run=False)
            rule_path, fixture_path, expected = SCAFFOLD.prepare_scaffold(args)
            original_bump = SCAFFOLD.bump_count
            committed = False

            def interrupt_then_hide_count(dry_run):
                nonlocal committed
                if dry_run and committed:
                    raise SystemExit("injected unreadable count")
                result = original_bump(dry_run)
                if not dry_run:
                    committed = True
                    raise KeyboardInterrupt
                return result

            with patch("sys.argv", argv), \
                    patch.object(SCAFFOLD, "bump_count", side_effect=interrupt_then_hide_count), \
                    contextlib.redirect_stderr(io.StringIO()) as stderr, \
                    self.assertRaises(KeyboardInterrupt):
                SCAFFOLD.main()
            self.assertEqual(rule_path.read_bytes(), expected[0].encode("utf-8"))
            self.assertEqual(fixture_path.read_bytes(), expected[1].encode("utf-8"))
            self.assertEqual(guard.read_text(encoding="utf-8").count(", 4)"), 2)
            self.assertIn("transaction state is unknown", stderr.getvalue())
            self.assertIn("verify the count and tree before deleting", stderr.getvalue())
            self.assertIn("rules/go/security/go-test-rule.yml", stderr.getvalue())
            self.assertIn("tests/go/security/go-test-rule.yml", stderr.getvalue())

    def test_repeated_interrupt_during_recovery_preserves_original(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            guard, argv = self.make_scaffold_case(root)
            original_bump = SCAFFOLD.bump_count
            failed = False

            def interrupt_twice(dry_run):
                nonlocal failed
                if failed:
                    raise KeyboardInterrupt("recovery interrupt")
                if dry_run:
                    return original_bump(dry_run)
                failed = True
                raise KeyboardInterrupt("original interrupt")

            with patch("sys.argv", argv), \
                    patch.object(SCAFFOLD, "bump_count", side_effect=interrupt_twice), \
                    contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaisesRegex(KeyboardInterrupt, "original interrupt"):
                SCAFFOLD.main()
            self.assertEqual(guard.read_text(encoding="utf-8").count(", 3)"), 2)
            self.assertTrue((root / "rules/go/security/go-test-rule.yml").exists())
            self.assertTrue((root / "tests/go/security/go-test-rule.yml").exists())

    def test_unexpected_recovery_error_does_not_mask_original(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            _, argv = self.make_scaffold_case(root)
            original_bump = SCAFFOLD.bump_count
            failed = False

            def fail_recovery(dry_run):
                nonlocal failed
                if failed:
                    raise ValueError("unexpected recovery failure")
                if dry_run:
                    return original_bump(dry_run)
                failed = True
                raise KeyboardInterrupt("original interrupt")

            with patch("sys.argv", argv), \
                    patch.object(SCAFFOLD, "bump_count", side_effect=fail_recovery), \
                    patch("builtins.print", side_effect=BrokenPipeError("closed stderr")), \
                    self.assertRaisesRegex(KeyboardInterrupt, "original interrupt"):
                SCAFFOLD.main()
            self.assertTrue((root / "rules/go/security/go-test-rule.yml").exists())
            self.assertTrue((root / "tests/go/security/go-test-rule.yml").exists())

    def test_cleanup_stops_retrying_repeated_interrupts(self):
        path = Path("inert")
        with patch.object(Path, "unlink", side_effect=KeyboardInterrupt) as unlink:
            SCAFFOLD.remove_created_path(path)
        self.assertEqual(unlink.call_count, SCAFFOLD.CLEANUP_INTERRUPT_RETRIES)

    def test_cleanup_retry_treats_already_removed_directory_as_success(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "created"
            path.mkdir()
            original_rmdir = Path.rmdir
            interrupted = False

            def remove_then_interrupt(target):
                nonlocal interrupted
                if not interrupted:
                    interrupted = True
                    original_rmdir(target)
                    raise KeyboardInterrupt
                return original_rmdir(target)

            with patch.object(Path, "rmdir", remove_then_interrupt):
                self.assertTrue(SCAFFOLD.remove_created_path(path, directory=True))
            self.assertFalse(path.exists())

    def test_interrupt_during_cleanup_is_retried_without_masking_original(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            guard, argv = self.make_scaffold_case(root)
            fixture = root / "tests/go/security/go-test-rule.yml"
            original_unlink = Path.unlink
            interrupted = False

            def interrupt_fixture_unlink(path, *args, **kwargs):
                nonlocal interrupted
                if path == fixture and not interrupted:
                    interrupted = True
                    raise KeyboardInterrupt("cleanup interrupt")
                return original_unlink(path, *args, **kwargs)

            with patch("sys.argv", argv), \
                    patch.object(Path, "replace",
                                 side_effect=KeyboardInterrupt("original interrupt")), \
                    patch.object(Path, "unlink", interrupt_fixture_unlink), \
                    self.assertRaisesRegex(KeyboardInterrupt, "original interrupt"):
                SCAFFOLD.main()
            self.assertTrue(interrupted)
            self.assertFalse((root / "rules/go/security/go-test-rule.yml").exists())
            self.assertFalse(fixture.exists())
            self.assertEqual(guard.read_text(encoding="utf-8").count(", 3)"), 2)

    def test_cleanup_permission_error_does_not_mask_original_or_stop_cleanup(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            guard, argv = self.make_scaffold_case(root)
            rule = root / "rules/go/security/go-test-rule.yml"
            fixture = root / "tests/go/security/go-test-rule.yml"
            original_unlink = Path.unlink

            def refuse_fixture_unlink(path, *args, **kwargs):
                if path == fixture:
                    raise PermissionError("injected cleanup refusal")
                return original_unlink(path, *args, **kwargs)

            with patch("sys.argv", argv), \
                    patch.object(Path, "replace",
                                 side_effect=KeyboardInterrupt("original interrupt")), \
                    patch.object(Path, "unlink", refuse_fixture_unlink), \
                    contextlib.redirect_stderr(io.StringIO()) as stderr, \
                    self.assertRaisesRegex(KeyboardInterrupt, "original interrupt"):
                SCAFFOLD.main()
            self.assertFalse(rule.exists())
            self.assertTrue(fixture.exists())
            self.assertEqual(guard.read_text(encoding="utf-8").count(", 3)"), 2)
            self.assertIn("rollback was incomplete", stderr.getvalue())
            self.assertIn("tests/go/security/go-test-rule.yml", stderr.getvalue())
            self.assertNotIn("tests/go/security,", stderr.getvalue())

    def test_retained_path_warning_falls_back_for_path_outside_root(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)), \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            outside = Path(directory).parent / "outside-rule.yml"
            SCAFFOLD.warn_retained_paths([Path(directory) / "inside-rule.yml", outside])
        warning = stderr.getvalue()
        self.assertIn("inside-rule.yml", warning)
        self.assertIn(str(outside), warning)

    def test_retained_path_warning_continues_after_unprintable_path(self):
        class UnprintablePath:
            def relative_to(self, _root):
                raise ValueError("outside root")

            def __str__(self):
                raise ValueError("cannot render")

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)), \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            valid = Path(directory) / "later-rule.yml"
            SCAFFOLD.warn_retained_paths([UnprintablePath(), valid])
        warning = stderr.getvalue()
        self.assertIn("<unprintable path>", warning)
        self.assertIn("later-rule.yml", warning)

    def test_unknown_count_warning_includes_created_directories_without_files(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            _, argv = self.make_scaffold_case(root)
            original_create = SCAFFOLD.create_parent_dirs
            original_bump = SCAFFOLD.bump_count
            failed = False

            def create_then_fail(directories, created_dirs):
                nonlocal failed
                original_create(directories, created_dirs)
                failed = True
                raise OSError("injected failure after directory creation")

            def hide_count_after_failure(dry_run):
                if failed:
                    raise SystemExit("injected unreadable count")
                return original_bump(dry_run)

            with patch("sys.argv", argv), \
                    patch.object(SCAFFOLD, "create_parent_dirs", side_effect=create_then_fail), \
                    patch.object(SCAFFOLD, "bump_count", side_effect=hide_count_after_failure), \
                    contextlib.redirect_stderr(io.StringIO()) as stderr, \
                    self.assertRaisesRegex(OSError, "directory creation"):
                SCAFFOLD.main()
            self.assertIn("rules/go/security", stderr.getvalue())
            self.assertIn("tests/go/security", stderr.getvalue())

    def test_unexpected_count_change_preserves_outputs_and_original_error(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            _, argv = self.make_scaffold_case(root)
            original_bump = SCAFFOLD.bump_count
            failed = False

            def fail_then_report_unexpected_count(dry_run):
                nonlocal failed
                if failed:
                    return 99, 100
                if not dry_run:
                    failed = True
                    raise OSError("original count failure")
                return original_bump(dry_run)

            with patch("sys.argv", argv), \
                    patch.object(SCAFFOLD, "bump_count",
                                 side_effect=fail_then_report_unexpected_count), \
                    contextlib.redirect_stderr(io.StringIO()) as stderr, \
                    self.assertRaisesRegex(OSError, "original count failure"):
                SCAFFOLD.main()
            self.assertTrue((root / "rules/go/security/go-test-rule.yml").exists())
            self.assertTrue((root / "tests/go/security/go-test-rule.yml").exists())
            self.assertIn("transaction state is unknown", stderr.getvalue())

    def test_concurrently_created_parent_is_not_removed(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            _, argv = self.make_scaffold_case(root)
            original_mkdir = Path.mkdir
            original_open = Path.open

            def race_rules_mkdir(path, *values, **kwargs):
                if path == root / "rules" and not path.exists():
                    original_mkdir(path)
                    raise FileExistsError("injected concurrent directory")
                return original_mkdir(path, *values, **kwargs)

            def fail_rule_write(path, *values, **kwargs):
                mode = values[0] if values else kwargs.get("mode", "r")
                if path.name == "go-test-rule.yml" and mode == "x":
                    raise OSError("injected output failure")
                return original_open(path, *values, **kwargs)

            with patch("sys.argv", argv), patch.object(Path, "mkdir", race_rules_mkdir), \
                    patch.object(Path, "open", fail_rule_write), self.assertRaises(OSError):
                SCAFFOLD.main()
            self.assertTrue((root / "rules").is_dir())
            self.assertFalse((root / "rules/go").exists())
            self.assertFalse((root / "tests/go").exists())

    def test_success_reports_written_count(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            guard, argv = self.make_scaffold_case(root)
            original_bump = SCAFFOLD.bump_count

            def change_count_after_preflight(dry_run):
                if not dry_run:
                    guard.write_text(guard.read_text().replace(", 3)", ", 7)"))
                return original_bump(dry_run)

            with patch("sys.argv", argv), \
                    patch.object(SCAFFOLD, "bump_count", change_count_after_preflight), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(SCAFFOLD.main(), 0)
            self.assertIn("rule count 7 -> 8", output.getvalue())

    def test_scaffold_writes_utf8_under_ascii_defaults(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            root = Path(directory)
            guard = root / "tests/test_diagnostics.py"
            guard.parent.mkdir()
            guard.write_text("self.assertEqual(len(rules), 3)\nself.assertEqual(checked, 3)\n",
                             encoding="utf-8")
            matcher = root / "matcher.yml"
            matcher.write_text("pattern: 'café($X)'\n", encoding="utf-8")
            argv = ["rule-scaffold", "--id", "go-unicode-test", "--language", "go",
                    "--category", "correctness", "--positive", 'fmt.Println("café 🧪")',
                    "--near-miss", 'fmt.Println("cafe")', "--claim", "Reject mojibaké",
                    "--matcher", str(matcher)]
            with patch("sys.argv", argv), ascii_text_defaults(), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(SCAFFOLD.main(), 0)
            rule_path = root / "rules/go/correctness/go-unicode-test.yml"
            fixture_path = root / "tests/go/correctness/go-unicode-test.yml"
            rule = rule_path.read_text(encoding="utf-8")
            fixture = fixture_path.read_text(encoding="utf-8")
            self.assertIn("mojibaké", rule)
            self.assertIn("café($X)", rule)
            self.assertIn("café 🧪", fixture)
            self.assertNotIn(b"\r\n", rule_path.read_bytes())
            self.assertNotIn(b"\r\n", fixture_path.read_bytes())
            self.assertEqual(guard.read_text(encoding="utf-8").count(", 4)"), 2)

    def test_missing_rule_count_guard_is_controlled_refusal(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            path = Path(directory) / "tests/test_diagnostics.py"
            path.parent.mkdir()
            with self.assertRaisesRegex(SystemExit, "cannot read rule-count guard"):
                SCAFFOLD.bump_count(False)

    def test_counts_update_together_and_dry_run_does_not_write(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(SCAFFOLD, "ROOT", Path(directory)):
            path = Path(directory) / "tests/test_diagnostics.py"
            path.parent.mkdir()
            original = "self.assertEqual(len(rules), 3)\nself.assertEqual(checked, 3)\n"
            path.write_text(original)
            self.assertEqual(SCAFFOLD.bump_count(True), (3, 4))
            self.assertEqual(path.read_text(), original)
            self.assertEqual(SCAFFOLD.bump_count(False), (3, 4))
            self.assertEqual(path.read_text(), original.replace(", 3)", ", 4)"))
            path.write_text(original.replace("checked, 3", "checked, 2"))
            with self.assertRaisesRegex(SystemExit, "disagree"):
                SCAFFOLD.bump_count(False)

    def test_missing_proposal_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proposals.jsonl"
            with self.assertRaisesRegex(SystemExit, "cannot read proposals"):
                SCAFFOLD.load_proposal(path, "go-index-check")
            path.write_text('{"id": "go-other-rule"}\n')
            with self.assertRaisesRegex(SystemExit, "no proposal"):
                SCAFFOLD.load_proposal(path, "go-index-check")
            for text in ("{", "{}", "[]"):
                path.write_text(text)
                with self.assertRaises(SystemExit):
                    SCAFFOLD.load_proposal(path, "go-index-check")
            proposal = {"id": "go-index-check", "claim": "Reject mojibaké"}
            path.write_text(json.dumps(proposal, ensure_ascii=False), encoding="utf-8")
            with ascii_text_defaults():
                self.assertEqual(SCAFFOLD.load_proposal(path, "go-index-check"), proposal)
            path.write_bytes(b'{"id":"go-index-check","claim":"\xff"}')
            with self.assertRaisesRegex(SystemExit, "cannot read proposals"):
                SCAFFOLD.load_proposal(path, "go-index-check")
