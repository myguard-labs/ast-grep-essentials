import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import yaml

from tests.mechanics_test_support import load_tool, minimal_plan

PLAN = load_tool("rule-plan")


class RulePlanPreflightTests(unittest.TestCase):
    def test_relation_only_mutants_are_not_counted_as_kills(self):
        matcher = {"all": [{"kind": "call"}, {"not": {"has": {"kind": "string"}}}]}
        plan = minimal_plan(rule=matcher)
        paths = [path for path, _rule in PLAN.compiled_mutations(plan, matcher)]
        self.assertNotIn("rule.all[0]-deleted", paths)

    def test_affirmative_relation_only_mutant_is_not_a_candidate(self):
        matcher = {"all": [{"kind": "call"}, {"has": {"kind": "identifier"}}]}
        plan = minimal_plan(rule=matcher)
        paths = [path for path, _rule in PLAN.compiled_mutations(plan, matcher)]
        self.assertNotIn("rule.all[0]-deleted", paths)

    def test_constraint_any_arm_deletions_are_mutation_candidates(self):
        matcher = {"pattern": "danger($ARG)"}
        plan = minimal_plan(
            rule=matcher,
            constraints={"ARG": {"not": {"any": [
                {"kind": "string_literal"}, {"kind": "concatenated_string"},
            ]}}},
        )
        paths = [path for path, _rule in PLAN.compiled_mutations(plan, matcher)]
        self.assertEqual(paths, [
            "constraints.ARG-deleted",
            "constraints.ARG.not.any[0]-deleted",
            "constraints.ARG.not.any[1]-deleted",
        ])

    def test_referenced_utilities_are_not_whole_deletion_candidates(self):
        matcher = {"matches": "danger-call"}
        plan = minimal_plan(
            rule=matcher,
            utils={"danger-call": {"pattern": "danger()"}},
        )
        paths = [path for path, _rule in PLAN.compiled_mutations(plan, matcher)]
        self.assertNotIn("utils.danger-call-deleted", paths)

    def test_preflight_calls_share_one_cumulative_deadline(self):
        plan = minimal_plan(rule={"all": [{"kind": "call"}, {"pattern": "danger()"}]})
        matcher, cases = PLAN.validate_plan(plan)
        deadlines = []

        def batch(_items, _cases, _rule_id, deadline, _telemetry):
            deadlines.append(deadline)
            return {"one": ("killed", "test-failure")}

        with patch.object(PLAN, "compiled_mutations", return_value=[("one", "rule")]), \
                patch.object(PLAN, "perf_counter", return_value=10.0), \
                patch.object(PLAN, "run_preflight", return_value=(True, "ok")) as run, \
                patch.object(PLAN, "_run_mutant_batch", side_effect=batch):
            PLAN.preflight(plan, matcher, cases)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.kwargs["deadline"], 10.0 + PLAN.MAX_PREFLIGHT_SECONDS)
        self.assertEqual(deadlines, [10.0 + PLAN.MAX_PREFLIGHT_SECONDS])

    def test_exhausted_preflight_budget_fails_before_engine_run(self):
        with patch.object(PLAN, "perf_counter", side_effect=[5.0, 6.0]), \
                patch.object(PLAN, "run_engine") as run:
            passed, detail = PLAN.run_preflight(
                "id: sample\n", {"invalid": ["x"], "valid": ["y"]}, "sample",
                deadline=5.5,
            )
        self.assertFalse(passed)
        self.assertEqual(detail, "engine-error=preflight budget exhausted")
        run.assert_not_called()

    def test_invalid_mutant_is_skipped(self):
        plan = minimal_plan(rule={"all": [{"kind": "call"}, {"pattern": "danger()"}]})
        matcher, cases = PLAN.validate_plan(plan)
        with patch.object(PLAN, "run_preflight", return_value=(True, "ok")), \
                patch.object(PLAN, "_run_mutant_batch", return_value={
                    path: ("invalid", "bad rule")
                    for path, _rule in PLAN.compiled_mutations(plan, matcher)
                }):
            PLAN.preflight(plan, matcher, cases)

    def test_mutants_share_one_engine_process_with_per_mutant_outcomes(self):
        output = "PASS sample-mutant-0  ..\nFAIL sample-mutant-1  NM\nError: test failed."
        result = SimpleNamespace(returncode=4, stdout=output, stderr="")
        telemetry = PLAN.PhaseTelemetry()
        rules = [
            ("survivor", yaml.safe_dump({"id": "sample", "language": "python",
                                         "message": "x", "severity": "warning",
                                         "rule": {"pattern": "$_"}})),
            ("killed", yaml.safe_dump({"id": "sample", "language": "python",
                                       "message": "x", "severity": "warning",
                                       "rule": {"pattern": "danger()"}})),
        ]
        with patch.object(PLAN, "run_engine", return_value=result) as run:
            # pylint: disable-next=protected-access
            outcomes = PLAN._run_mutant_batch(
                rules, {"invalid": ["danger()"], "valid": ["safe()"]},
                "sample", float("inf"), telemetry)
        self.assertEqual(outcomes["survivor"][0], "survived")
        self.assertEqual(outcomes["killed"][0], "killed")
        self.assertEqual(run.call_count, 1)
        self.assertEqual(telemetry.engine_processes, 1)

    def test_batch_runner_uses_one_process_for_two_valid_mutants(self):
        result = SimpleNamespace(returncode=0, stdout="", stderr="")
        rule = yaml.safe_dump({
            "id": "sample", "language": "python", "message": "x", "severity": "warning",
            "rule": {"pattern": "danger()"},
        })
        with patch.object(PLAN, "run_engine", return_value=result) as run:
            # pylint: disable-next=protected-access
            PLAN._run_mutant_batch(
                [("one", rule), ("two", rule)],
                {"invalid": ["danger()"], "valid": ["safe()"]},
                "sample", float("inf"), PLAN.PhaseTelemetry())
        self.assertEqual(run.call_count, 1)

    def test_unloadable_mutant_is_bisected_and_attributed(self):
        load_error = SimpleNamespace(
            returncode=2, stdout="", stderr="file is not a valid ast-grep rule")
        passed = SimpleNamespace(returncode=0, stdout="PASS sample-mutant-0 ..", stderr="")
        telemetry = PLAN.PhaseTelemetry()
        valid_rule = yaml.safe_dump({
            "id": "sample", "language": "python", "message": "x", "severity": "warning",
            "rule": {"pattern": "danger()"},
        })
        with patch.object(PLAN, "run_engine",
                          side_effect=[load_error, passed, load_error]):
            # pylint: disable-next=protected-access
            outcomes = PLAN._run_mutant_batch(
                [("valid", valid_rule), ("invalid", yaml.safe_dump({
                    "id": "sample", "language": "python", "message": "x",
                    "severity": "warning", "rule": {},
                }))],
                {"invalid": ["danger()"], "valid": ["safe()"]},
                "sample", float("inf"), telemetry)
        self.assertEqual(outcomes["valid"][0], "survived")
        self.assertEqual(outcomes["invalid"][0], "invalid")
        self.assertEqual(telemetry.engine_processes, 3)

    def test_telemetry_separates_deterministic_counts_from_wall_clock(self):
        telemetry = PLAN.PhaseTelemetry(
            engine_processes=2, plans=1, valid_cases=4, invalid_cases=3,
            exclusions=2, bytes=120, mutants=9, wall_ms=37)
        report = telemetry.report()
        self.assertEqual(report["counts"]["engine_processes"], 2)
        self.assertEqual(report["counts"]["mutants"], 9)
        self.assertEqual(report["counts"] | {}, {
            "engine_processes": 2, "plans": 1, "valid_cases": 4,
            "invalid_cases": 3, "exclusions": 2, "bytes": 120,
            "mutants": 9, "survived": 0, "invalid": 0, "errors": 0,
        })
        self.assertEqual(report["wall_clock_ms_informational"]["batched_engine"], 37)


class RulePlanSyntaxPreflightTests(unittest.TestCase):
    def test_metamorphic_parser_errors_fail_before_contrast_preflight(self):
        plan = minimal_plan(metamorphic=[
            {"source": "danger()", "transform": "parenthesized", "outcome": "equivalent"},
        ])
        matcher, cases = PLAN.validate_plan(plan)
        malformed = SimpleNamespace(returncode=0, stdout="(ERROR)", stderr="")
        finding = SimpleNamespace(returncode=0, stderr="", stdout=json.dumps([{
            "range": {"byteOffset": {"start": 0, "end": 8}},
        }]))
        target = SimpleNamespace(returncode=0, stderr="", stdout=finding.stdout)
        with patch.object(PLAN, "run_engine", side_effect=[finding, target, malformed]), \
                patch.object(PLAN, "run_preflight") as contrast, \
                self.assertRaisesRegex(RuntimeError, "METAMORPHIC_PARSE_ERROR"):
            PLAN.preflight(plan, matcher, cases)
        contrast.assert_not_called()

        failed_cst = SimpleNamespace(returncode=2, stdout="query failed", stderr="")
        with patch.object(PLAN, "run_engine",
                          side_effect=[finding, target, failed_cst]), \
                patch.object(PLAN, "run_preflight") as contrast, \
                self.assertRaisesRegex(RuntimeError, "METAMORPHIC_PARSE_ERROR"):
            PLAN.preflight(plan, matcher, cases)
        contrast.assert_not_called()

    def test_metamorphic_parser_checks_actual_derived_cst(self):
        good = minimal_plan(metamorphic=[
            {"source": "first = 1\ndanger()", "transform": "callee-parenthesized",
             "outcome": "equivalent"},
        ], cases={"invalid": ["first = 1\ndanger()"], "valid": ["safe()"]})
        _matcher, good_cases = PLAN.validate_plan(good)
        PLAN.validate_derived_syntax(
            good, good_cases, float("inf"), PLAN.PhaseTelemetry())

        bad = minimal_plan(
            cases={"invalid": ["first = 1\ndanger()\nif"], "valid": ["safe()"]},
            metamorphic=[
                {"source": "first = 1\ndanger()\nif",
                 "transform": "callee-parenthesized",
                 "outcome": "equivalent"},
            ],
        )
        _matcher, bad_cases = PLAN.validate_plan(bad)
        with self.assertRaisesRegex(RuntimeError, "METAMORPHIC_PARSE_ERROR"):
            PLAN.validate_derived_syntax(
                bad, bad_cases, float("inf"), PLAN.PhaseTelemetry())

    def test_full_source_parser_rejects_cpp_missing_node_recovery(self):
        source = "void f(){if () {} obj->field;}"
        plan = minimal_plan(
            language="cpp", cases={"invalid": [source], "valid": ["int value = 1;"]},
            metamorphic=[{
                "source": source, "transform": "member-access-spacing",
                "outcome": "equivalent",
            }],
        )
        _matcher, cases = PLAN.validate_plan(plan)
        with self.assertRaisesRegex(RuntimeError, "METAMORPHIC_PARSE_ERROR"):
            PLAN.validate_derived_syntax(
                plan, cases, float("inf"), PLAN.PhaseTelemetry())

    def test_full_source_parser_rejects_missing_only_recovery(self):
        # White-box call isolates the full-CST parser boundary from preflight.
        # pylint: disable-next=protected-access
        invoke = PLAN._syntax_run
        rows = (
            ("c", "void f(){ if () {} }", "c"),
            ("java", "class X { void f(){ if () {} } }", "java"),
            ("html", "<div", "html"),
        )
        for language, source, extension in rows:
            with self.subTest(language=language), self.assertRaisesRegex(
                    RuntimeError, "METAMORPHIC_PARSE_ERROR"):
                PLAN.SYNTAX.validate_full_source(
                    source, language, extension, float("inf"), invoke)
        PLAN.SYNTAX.validate_full_source(
            "<div>ok</div>", "html", "html", float("inf"), invoke)

    def test_compound_callees_and_optional_members_derive_parseable_syntax(self):
        rows = (
            ("python", 'value = "a" "b"', "literal-spacing", "safe()"),
            ("cpp", "void f(){ obj->danger(); }", "callee-parenthesized",
             "int value = 1;"),
            ("cpp", "void f(){ ns::danger(); }", "callee-parenthesized",
             "int value = 1;"),
            ("javascript", "obj.danger()", "callee-parenthesized", "safe();"),
            ("javascript", "obj?.field", "member-access-spacing", "safe();"),
            ("javascript", "function f(){ return /fake.name/; } obj.name;",
             "qualified-name-spacing", "safe();"),
            ("typescript", "if (x) /fake.name/; obj.name;",
             "qualified-name-spacing", "safe();"),
            ("python", "x = 1.2\nobj.name", "qualified-name-spacing", "safe()"),
            ("java", "class X { void f(){ double x=1.2; obj.name(); } }",
             "qualified-name-spacing", "class X {}"),
            ("php", "<?php $x = 1.2; $obj->name();",
             "qualified-name-spacing", "<?php safe();"),
            ("php", "$obj?->field;", "member-access-spacing", "$safe->field;"),
            ("javascript", "handlers[key]();", "callee-parenthesized", "safe();"),
            ("python", "handlers[0]()", "callee-parenthesized", "safe()"),
            ("python", "(handler)()", "callee-parenthesized", "safe()"),
        )
        for language, source, transform, valid in rows:
            with self.subTest(language=language, source=source):
                plan = minimal_plan(
                    language=language, cases={"invalid": [source], "valid": [valid]},
                    metamorphic=[{
                        "source": source, "transform": transform,
                        "outcome": "equivalent",
                    }],
                )
                _matcher, cases = PLAN.validate_plan(plan)
                PLAN.validate_derived_syntax(
                    plan, cases, float("inf"), PLAN.PhaseTelemetry())

    def test_c_callee_plan_is_schema_valid_and_passes_full_preflight(self):
        sources = [
            "void f(){ danger(); }",
            "int f(){ return danger(); }",
            "int f(){ int x = danger(); return x; }",
            "void f(){ if (danger()) {} }",
        ]
        plan = minimal_plan(
            language="c",
            rule={"any": [
                {"pattern": {"context": "danger();", "selector": "call_expression"}},
                {"pattern": {"context": "(danger)();", "selector": "call_expression"}},
            ]},
            cases={
                "invalid": sources, "valid": ["void f(){ safe(); }"],
            },
            metamorphic=[
                {"source": source, "transform": "callee-parenthesized",
                 "outcome": "equivalent"}
                for source in sources
            ],
        )
        matcher, cases = PLAN.validate_plan(plan)
        telemetry = PLAN.PhaseTelemetry()
        with patch.object(PLAN, "run_engine", wraps=PLAN.run_engine) as processes:
            PLAN.preflight(plan, matcher, cases, telemetry)
        self.assertEqual(processes.call_count, telemetry.engine_processes)
        self.assertEqual(processes.call_count, 14)

    def test_expired_deadline_stops_before_target_discovery_process(self):
        plan = minimal_plan(metamorphic=[{
            "source": "danger()", "transform": "callee-parenthesized",
            "outcome": "equivalent",
        }])
        matcher, cases = PLAN.validate_plan(plan)
        telemetry = PLAN.PhaseTelemetry()
        with patch.object(PLAN, "run_engine") as process, \
                self.assertRaisesRegex(RuntimeError, "budget exhausted"):
            PLAN.preflight(
                plan, matcher, cases, telemetry, deadline=PLAN.perf_counter() - 1)
        process.assert_not_called()
        self.assertEqual(telemetry.engine_processes, 0)

        telemetry = PLAN.PhaseTelemetry()
        with patch.object(PLAN, "run_engine") as process, \
                self.assertRaisesRegex(RuntimeError, "CONTRAST_PREFLIGHT_FAILED"):
            PLAN.preflight(minimal_plan(), {"pattern": "danger()"},
                           minimal_plan()["cases"], telemetry, deadline=0)
        process.assert_not_called()
        self.assertEqual(telemetry.engine_processes, 0)

        telemetry = PLAN.PhaseTelemetry()
        with patch.object(PLAN, "run_engine") as process:
            passed, detail = PLAN.run_preflight(
                "id: sample\n", {"invalid": ["x"], "valid": ["y"]}, "sample",
                deadline=PLAN.perf_counter() - 1, telemetry=telemetry)
        self.assertFalse(passed)
        self.assertIn("budget exhausted", detail)
        process.assert_not_called()
        self.assertEqual(telemetry.engine_processes, 0)

        plan = minimal_plan(match={
            "target": {"kind": "call"},
            "any": [{"name": "only", "rule": {"pattern": "danger()"},
                     "witness": "danger()"}],
        })
        with patch.object(PLAN, "run_engine") as process, \
                self.assertRaisesRegex(RuntimeError, "ANY_ARM_PREFLIGHT_ERROR"):
            # White-box call verifies named-arm accounting before engine launch.
            # pylint: disable-next=protected-access
            PLAN._preflight_named_branches(
                plan, plan["cases"], PLAN.perf_counter() - 1, telemetry)
        process.assert_not_called()
        self.assertEqual(telemetry.engine_processes, 0)

    def test_literal_concatenation_is_limited_to_adjacent_literal_grammars(self):
        for language in ("javascript", "typescript", "java"):
            with self.subTest(language=language), \
                    self.assertRaisesRegex(ValueError, f"does not support {language}"):
                PLAN.validate_plan(minimal_plan(language=language, metamorphic=[{
                    "source": "danger()", "transform": "literal-concatenation",
                    "outcome": "equivalent",
                }]))

    def test_engine_timeout_terminates_descendant_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            child_pid = Path(directory) / "child.pid"
            ready = Path(directory) / "ready"
            child_program = (
                "import pathlib,signal,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"pathlib.Path({str(ready)!r}).write_text('ready', encoding='utf-8'); "
                "time.sleep(60)"
            )
            program = (
                "import pathlib,subprocess,sys,time; "
                f"child=subprocess.Popen([sys.executable,'-c',{child_program!r}], "
                "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
                f"ready=pathlib.Path({str(ready)!r}); "
                "deadline=time.monotonic()+2; "
                "exec(\"while not ready.exists() and time.monotonic() < deadline:\\n"
                " time.sleep(0.01)\"); "
                f"pathlib.Path({str(child_pid)!r}).write_text(str(child.pid), encoding='utf-8'); "
                "time.sleep(60)"
            )
            with self.assertRaises(subprocess.TimeoutExpired):
                PLAN.run_engine([sys.executable, "-c", program], timeout=3)
            self.assertTrue(ready.is_file())
            pid = int(child_pid.read_text(encoding="utf-8"))
            status = Path(f"/proc/{pid}/status")
            for _attempt in range(100):
                if (not status.exists()
                        or "\nState:\tZ" in status.read_text(encoding="utf-8")):
                    break
                time.sleep(0.01)
            self.assertTrue(
                not status.exists()
                or "\nState:\tZ" in status.read_text(encoding="utf-8"))

    def test_engine_interrupt_kills_reaps_and_reraises(self):
        for failure in (KeyboardInterrupt(), RuntimeError("interrupted")):
            with self.subTest(failure=type(failure).__name__):
                process = MagicMock(pid=4242)
                process.__enter__.return_value = process
                process.communicate.side_effect = [failure, ("", "")]
                with patch.object(PLAN.subprocess, "Popen", return_value=process), \
                        patch.object(PLAN, "signal_process_group", return_value=True) as signal, \
                        self.assertRaises(type(failure)):
                    PLAN.run_engine(["engine"], timeout=1)
                signal.assert_called_once_with(4242, PLAN.signal.SIGKILL)
                self.assertEqual(process.communicate.call_count, 2)

    def test_two_named_branches_reach_both_witness_preflights(self):
        plan = minimal_plan(
            rule=None,
            match={
                "target": {"kind": "call"},
                "any": [
                    {"name": "first", "rule": {"pattern": "first()"},
                     "witness": "first()"},
                    {"name": "second", "rule": {"pattern": "second()"},
                     "witness": "second()"},
                ],
            },
            cases={"invalid": ["first()", "second()"], "valid": ["safe()"]},
        )
        del plan["rule"]
        matcher, cases = PLAN.validate_plan(plan)
        with patch.object(PLAN, "compiled_mutations", return_value=[]), \
                patch.object(PLAN, "run_preflight",
                          side_effect=[(True, "ok"), (False, "test-failure"),
                                       (False, "test-failure")]) as preflight:
            PLAN.preflight(plan, matcher, cases)
        self.assertEqual(preflight.call_count, 3)


class RulePlanBatchPrecedenceTests(unittest.TestCase):
    def test_batch_errors_precede_exclusion_semantics(self):
        plan = minimal_plan(
            rule={"all": [{"kind": "call"}, {"pattern": "danger()"}]},
            mutation_exclusions={
                "excluded": "the deliberately broad mutant survives its contrasts",
            },
        )
        matcher, cases = PLAN.validate_plan(plan)
        outcomes = {
            "excluded": ("killed", "test-failure"),
            "required": ("error", "engine-error=preflight budget exhausted"),
        }
        with patch.object(PLAN, "run_preflight", return_value=(True, "ok")), \
                patch.object(PLAN, "compiled_mutations", return_value=[
                    ("excluded", "rule"), ("required", "rule")]), \
                patch.object(PLAN, "_run_mutant_batch", return_value=outcomes), \
                self.assertRaisesRegex(
                    RuntimeError, "MUTATION_PREFLIGHT_ERROR: required:.*budget exhausted"):
            PLAN.preflight(plan, matcher, cases)


class RulePlanLiteralContractTests(unittest.TestCase):
    def test_literal_spacing_requires_supported_grammar_and_same_line(self):
        for language in ("javascript", "typescript"):
            with self.subTest(language=language), self.assertRaisesRegex(
                    ValueError, f"does not support {language}"):
                PLAN.validate_plan(minimal_plan(language=language, metamorphic=[{
                    "source": '"a"\n"b"', "transform": "literal-spacing",
                    "outcome": "equivalent",
                }], cases={"invalid": ['"a"\n"b"'], "valid": ["safe();"]}))
        for separator in ("\n", "\r", "\r\n"):
            source = f'"a"{separator}"b"'
            plan = minimal_plan(metamorphic=[{
                "source": source, "transform": "literal-spacing",
                "outcome": "equivalent",
            }], cases={"invalid": [source], "valid": ["safe()"]})
            _matcher, cases = PLAN.validate_plan(plan)
            with self.subTest(separator=repr(separator)), self.assertRaisesRegex(
                    ValueError, "not applicable"):
                PLAN.expanded_cases(plan, cases)
