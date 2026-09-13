import tempfile
import unittest
from pathlib import Path
from time import perf_counter
from unittest.mock import patch

import yaml

from tests.mechanics_test_support import ROOT, load_tool, minimal_plan

PLAN = load_tool("rule-plan")
PROBE = load_tool("rule-probe")


class RulePlanTests(unittest.TestCase):
    def test_plan_and_probe_cover_every_native_rule_language(self):
        configured = {
            path.name for path in (ROOT / "rules").iterdir()
            if path.is_dir() and path.name != "powershell"
        }
        self.assertEqual(set(PLAN.LANGUAGE_EXTENSIONS), configured)
        self.assertEqual(PROBE.EXTENSIONS, PLAN.LANGUAGE_EXTENSIONS)

    def test_repository_plan_compiles_and_passes_preflight(self):
        path = ROOT / "plans/python/security/py-tempfile-mktemp.yml"
        plan, matcher, rule, fixture = PLAN.compile_plan(path)
        self.assertEqual(plan["id"], "py-tempfile-mktemp")
        self.assertEqual(yaml.safe_load(rule)["rule"], matcher)
        self.assertEqual(yaml.safe_load(fixture)["id"], plan["id"])

    def test_closed_schema_rejects_unknown_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.yml"
            path.write_text(yaml.safe_dump({**minimal_plan(), "surprise": True}))
            with self.assertRaisesRegex(ValueError, "unknown keys: surprise"):
                PLAN.load_plan(path)

    def test_plan_id_is_safe_for_preflight_paths(self):
        for rule_id in ("../outside", "/outside", "py/sample", "UPPER"):
            with self.subTest(rule_id=rule_id), \
                    self.assertRaisesRegex(ValueError, "plan id must start"):
                PLAN.validate_plan(minimal_plan(id=rule_id))
        matcher, _cases = PLAN.validate_plan(
            minimal_plan(id="avoid_app_run_with_bad_host-python")
        )
        self.assertEqual(matcher, {"pattern": "danger()"})

    def test_provenance_comments_and_extensions_render_without_overrides(self):
        plan = minimal_plan(
            comments=["License: Example", "Source: https://example.test/rule"],
            extensions={"upstream-pack": True},
        )
        matcher, _cases = PLAN.validate_plan(plan)
        rendered = PLAN.render_rule(plan, matcher)
        self.assertTrue(rendered.startswith(
            "# License: Example\n# Source: https://example.test/rule\n"))
        self.assertTrue(yaml.safe_load(rendered)["upstream-pack"])
        with self.assertRaisesRegex(ValueError, "non-reserved"):
            PLAN.validate_plan(minimal_plan(extensions={"rule": {"pattern": "safe()"}}))
        with self.assertRaisesRegex(ValueError, "single-line"):
            PLAN.validate_plan(minimal_plan(comments=["trusted\rinjected: true"]))

    def test_mutation_limit_cannot_disable_or_truncate_mutations(self):
        with self.assertRaisesRegex(ValueError, "from 1"):
            PLAN.validate_plan(minimal_plan(mutation_limit=0))
        plan = minimal_plan(mutation_limit=1)
        matcher, cases = PLAN.validate_plan(plan)
        with patch.object(PLAN, "compiled_mutations",
                          return_value=[("one", "rule"), ("two", "rule")]), \
                patch.object(PLAN, "run_preflight", return_value=(True, "ok")), \
                self.assertRaisesRegex(RuntimeError, "MUTATION_BUDGET_EXCEEDED"):
            PLAN.preflight(plan, matcher, cases)

    def test_mutation_exclusions_must_exist_and_survive(self):
        matcher, cases = PLAN.validate_plan(minimal_plan())
        unknown = minimal_plan(mutation_exclusions={"missing": "reason"})
        with patch.object(PLAN, "compiled_mutations", return_value=[("one", "rule")]), \
                patch.object(PLAN, "run_preflight", return_value=(True, "ok")), \
                self.assertRaisesRegex(RuntimeError, "UNKNOWN_MUTATION_EXCLUSION"):
            PLAN.preflight(unknown, matcher, cases)
        killed = minimal_plan(mutation_exclusions={"one": "reason"})
        with patch.object(PLAN, "compiled_mutations", return_value=[("one", "rule")]), \
                patch.object(PLAN, "run_preflight", return_value=(True, "ok")), \
                patch.object(PLAN, "_run_mutant_batch",
                             return_value={"one": ("killed", "test-failure")}), \
                self.assertRaisesRegex(RuntimeError, "INVALID_MUTATION_EXCLUSION"):
            PLAN.preflight(killed, matcher, cases)

    def test_mutation_limit_counts_required_mutants_not_exclusions(self):
        plan = minimal_plan(
            mutation_limit=1,
            mutation_exclusions={"excluded-one": "redundant", "excluded-two": "redundant"},
        )
        matcher, cases = PLAN.validate_plan(plan)
        candidates = [("required", "rule"), ("excluded-one", "rule"),
                      ("excluded-two", "rule")]
        outcomes = {
            "required": ("killed", "test-failure"),
            "excluded-one": ("survived", "ok"),
            "excluded-two": ("survived", "ok"),
        }
        with patch.object(PLAN, "compiled_mutations", return_value=candidates), \
                patch.object(PLAN, "run_preflight", return_value=(True, "ok")), \
                patch.object(PLAN, "_run_mutant_batch", return_value=outcomes) as batch:
            PLAN.preflight(plan, matcher, cases)
        self.assertEqual(batch.call_args.args[0], candidates)

    def test_api_contracts_bind_arity_positions_and_exact_counts(self):
        first = "memcpy(NULL, src, 8);"
        second = "memcpy(dst, NULL, 8);"
        plan = minimal_plan(
            language="cpp",
            cases={"invalid": [first, second], "valid": ["memcpy(dst, src, 8);"]},
            oracles={first: {"count": 1}, second: {"count": 1}},
            api_contracts=[{
                "callee": "memcpy", "arity": 3,
                "positions": [1, 2], "witnesses": {1: first, 2: second},
            }],
        )
        PLAN.validate_plan(plan)
        with self.assertRaisesRegex(ValueError, "do not support python syntax"):
            PLAN.validate_plan({**plan, "language": "python"})

        invalid_contracts = (
            ({"callee": "memcpy", "arity": 2, "positions": [1, 3],
              "witnesses": {1: first, 3: second}}, "cannot exceed arity"),
            ({"callee": "memcpy", "arity": 3, "positions": [1],
              "witnesses": {1: "missing"}}, "must be invalid cases"),
            ({"callee": "memcpy", "arity": 3, "positions": [1, 2],
              "witnesses": {1: first}}, "must exactly cover positions"),
        )
        for contract, message in invalid_contracts:
            with self.subTest(contract=contract), self.assertRaisesRegex(ValueError, message):
                PLAN.validate_plan({**plan, "api_contracts": [contract]})
        with self.assertRaisesRegex(ValueError, "unique callee and arity"):
            PLAN.validate_plan({**plan, "api_contracts": plan["api_contracts"] * 2})

        without_count = {**plan, "oracles": {second: {"count": 1}}}
        with self.assertRaisesRegex(ValueError, "exact count oracle"):
            PLAN.validate_plan(without_count)

    def test_api_contract_reused_witness_requires_matching_count(self):
        source = "memcpy(NULL, NULL, 8);"
        base = minimal_plan(
            language="cpp", cases={"invalid": [source], "valid": ["safe();"]},
            api_contracts=[{
                "callee": "memcpy", "arity": 3,
                "positions": [1, 2], "witnesses": {1: source, 2: source},
            }],
        )
        with self.assertRaisesRegex(ValueError, "expected 2"):
            PLAN.validate_plan({**base, "oracles": {source: {"count": 1}}})
        PLAN.validate_plan({**base, "oracles": {source: {"count": 2}}})

    def test_api_contract_preflight_proves_exact_call_and_position(self):
        source = "void f(){ memcpy(NULL, src, 8); }"
        plan = minimal_plan(
            language="cpp", rule={"pattern": "NULL"},
            cases={"invalid": [source], "valid": ["void f(){ safe(); }"]},
            oracles={source: {"count": 1}},
            api_contracts=[{
                "callee": "memcpy", "arity": 3,
                "positions": [1], "witnesses": {1: source},
            }],
        )
        matcher, _cases = PLAN.validate_plan(plan)
        PLAN.validate_api_contract_syntax(
            plan, matcher, perf_counter() + 20, PLAN.PhaseTelemetry())
        c_plan = {**plan, "language": "c"}
        PLAN.validate_api_contract_syntax(
            c_plan, matcher, perf_counter() + 20, PLAN.PhaseTelemetry())

        shared = "void f(){ memcpy(NULL, NULL, 8); }"
        shared_plan = {
            **plan,
            "cases": {"invalid": [shared], "valid": plan["cases"]["valid"]},
            "oracles": {shared: {"count": 2}},
            "api_contracts": [{
                "callee": "memcpy", "arity": 3, "positions": [1, 2],
                "witnesses": {1: shared, 2: shared},
            }],
        }
        with patch.object(
                PLAN.SYNTAX, "api_call_arguments",
                wraps=PLAN.SYNTAX.api_call_arguments) as query:
            PLAN.validate_api_contract_syntax(
                shared_plan, matcher, perf_counter() + 20,
                PLAN.PhaseTelemetry())
        self.assertEqual(query.call_count, 1)

        wrong_position = {**plan, "api_contracts": [{
            "callee": "memcpy", "arity": 3,
            "positions": [2], "witnesses": {2: source},
        }]}
        with self.assertRaisesRegex(RuntimeError, "POSITION_UNMATCHED"):
            PLAN.validate_api_contract_syntax(
                wrong_position, matcher, perf_counter() + 20, PLAN.PhaseTelemetry())

        whole_call = {**plan, "rule": {"pattern": "memcpy($$$ARGS)"}}
        with self.assertRaisesRegex(RuntimeError, "POSITION_UNMATCHED"):
            PLAN.validate_api_contract_syntax(
                whole_call, whole_call["rule"], perf_counter() + 20,
                PLAN.PhaseTelemetry())

        wrong_arity = {**plan, "api_contracts": [{
            "callee": "memcpy", "arity": 2,
            "positions": [1], "witnesses": {1: source},
        }]}
        with self.assertRaisesRegex(RuntimeError, "CALL_MISMATCH"):
            PLAN.validate_api_contract_syntax(
                wrong_arity, matcher, perf_counter() + 20, PLAN.PhaseTelemetry())

        repeated = "void f(){ memcpy(NULL, src, 8); memcpy(NULL, src, 8); }"
        repeated_plan = {
            **plan,
            "cases": {"invalid": [repeated], "valid": plan["cases"]["valid"]},
            "oracles": {repeated: {"count": 1}},
            "api_contracts": [{
                "callee": "memcpy", "arity": 3,
                "positions": [1], "witnesses": {1: repeated},
            }],
        }
        with self.assertRaisesRegex(RuntimeError, "needs one exact call, got 2"):
            PLAN.validate_api_contract_syntax(
                repeated_plan, matcher, perf_counter() + 20,
                PLAN.PhaseTelemetry())

        for malformed in (
                "void f(){ memcpy(NULL, src, 8);",
                "void f(){ memcpy(NULL, src, 8) }"):
            malformed_plan = {
                **plan,
                "cases": {"invalid": [malformed], "valid": plan["cases"]["valid"]},
                "oracles": {malformed: {"count": 1}},
                "api_contracts": [{
                    "callee": "memcpy", "arity": 3,
                    "positions": [1], "witnesses": {1: malformed},
                }],
            }
            with self.subTest(malformed=malformed), self.assertRaisesRegex(
                    RuntimeError, "API_CONTRACT_PARSE_ERROR"):
                PLAN.validate_api_contract_syntax(
                    malformed_plan, matcher, perf_counter() + 20,
                    PLAN.PhaseTelemetry())

    def test_preflight_invokes_api_contract_syntax_gate(self):
        plan = minimal_plan(language="cpp")
        matcher, cases = PLAN.validate_plan(plan)
        with patch.object(PLAN, "expanded_cases", return_value=cases), \
                patch.object(PLAN, "validate_derived_syntax"), \
                patch.object(PLAN, "validate_api_contract_syntax",
                             side_effect=RuntimeError("api gate reached")) as gate, \
                self.assertRaisesRegex(RuntimeError, "api gate reached"):
            PLAN.preflight(plan, matcher, cases)
        gate.assert_called_once()

    def test_utility_graph_rejects_undefined_cycle_and_unreachable(self):
        cases = [
            ({"rule": {"matches": "missing"}}, "undefined local utilities"),
            ({"rule": {"matches": "a"}, "utils": {
                "a": {"matches": "b"}, "b": {"matches": "a"}}}, "cycle"),
            ({"utils": {"unused": {"pattern": "safe()"}}}, "unreachable"),
        ]
        for update, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                PLAN.validate_plan(minimal_plan(**update))

    def test_constraint_referenced_utility_is_reachable(self):
        plan = minimal_plan(
            rule={"pattern": "danger($ARG)"},
            constraints={"ARG": {"matches": "safe-arg"}},
            utils={"safe-arg": {"kind": "identifier"}},
        )
        matcher, _cases = PLAN.validate_plan(plan)
        self.assertEqual(matcher, plan["rule"])

    def test_surviving_weakening_is_rejected(self):
        plan = minimal_plan(rule={"all": [{"kind": "call"}, {"pattern": "danger()"}]})
        matcher, cases = PLAN.validate_plan(plan)
        with patch.object(PLAN, "run_preflight", return_value=(True, "ok")), \
                self.assertRaisesRegex(RuntimeError, "MUTATION_SURVIVED"):
            PLAN.preflight(plan, matcher, cases)

    def test_qualified_call_patterns_mutate_receiver_and_member(self):
        mutations = dict(PLAN.mutation_candidates(
            {"pattern": "tempfile.mktemp($$$ARGS)"}))
        self.assertEqual(
            set(mutations),
            {"rule.pattern-receiver", "rule.pattern-member"},
        )
        self.assertEqual(mutations["rule.pattern-receiver"]["pattern"],
                         "$_.mktemp($$$ARGS)")


class RuleRegexMutationTests(unittest.TestCase):
    def test_regex_alternatives_are_independently_mutated(self):
        mutations = dict(PLAN.mutation_candidates({"regex": "^open$|^read$|^write$"}))
        self.assertEqual(
            mutations["rule.regex-alternative[1]-deleted"]["regex"],
            "^open$|^write$",
        )

    def test_top_level_alternatives_preserve_leading_global_flags(self):
        mutations = dict(PLAN.mutation_candidates({"regex": "(?i)a|b"}))
        self.assertEqual(
            mutations["rule.regex-alternative[0]-deleted"]["regex"], "(?i)b")
        self.assertEqual(
            mutations["rule.regex-alternative[1]-deleted"]["regex"], "(?i)a")

    def test_leading_global_verbose_flag_applies_while_splitting(self):
        mutations = dict(PLAN.mutation_candidates(
            {"regex": "(?x)a # ignored | fake\n|b"}))
        self.assertEqual(
            mutations["rule.regex-alternative[0]-deleted"]["regex"], "(?x)b")
        self.assertEqual(
            mutations["rule.regex-alternative[1]-deleted"]["regex"],
            "(?x)a # ignored | fake\n",
        )

    def test_regex_split_ignores_escaped_group_and_class_bars(self):
        # pylint: disable-next=protected-access
        self.assertEqual(PLAN._regex_alternatives(r"^(a|b)[|]c\|d$|^e$"),
                         [r"^(a|b)[|]c\|d$", "^e$"])

    def test_regex_split_ignores_advanced_bracket_class_bars(self):
        cases = {
            r"[]|]value|outer": [r"[]|]value", "outer"],
            r"[[:alpha:]|]+|outer": [r"[[:alpha:]|]+", "outer"],
            r"[[.ch.]|]+|outer": [r"[[.ch.]|]+", "outer"],
            r"[[=a=]|]+|outer": [r"[[=a=]|]+", "outer"],
            r"[a&&[b|c]]+|outer": [r"[a&&[b|c]]+", "outer"],
            r"[a--[b|c]]+|outer": [r"[a--[b|c]]+", "outer"],
            r"[a--[b|c]|d]|outer": [r"[a--[b|c]|d]", "outer"],
        }
        for pattern, expected in cases.items():
            with self.subTest(pattern=pattern):
                # pylint: disable-next=protected-access
                self.assertEqual(PLAN._regex_alternatives(pattern), expected)

    def test_grouped_regex_alternatives_preserve_anchors_and_wrapper(self):
        cases = {
            "^(?:open|read|write)$": ("^(?:read|write)$", 3),
            "^(?i:open|read)+$": ("^(?i:read)+$", 2),
            "(open|read){2}": ("(read){2}", 2),
            "(open|read){2,4}?": ("(read){2,4}?", 2),
            "(?x:open # ignored | bar\n|read)": ("(?x:read)", 2),
        }
        for pattern, (expected, expected_count) in cases.items():
            with self.subTest(pattern=pattern):
                mutations = dict(PLAN.mutation_candidates({"regex": pattern}))
                self.assertEqual(
                    mutations["rule.regex-alternative[0]-deleted"]["regex"], expected)
                alternative_keys = [key for key in mutations if "regex-alternative" in key]
                self.assertEqual(len(alternative_keys), expected_count)

    def test_top_level_and_concatenated_groups_all_produce_stable_mutants(self):
        mutations = dict(PLAN.mutation_candidates({"regex": "pre(a|b)post|outer(c|d)"}))
        regexes = {key: value["regex"] for key, value in mutations.items()
                  if "regex-alternative" in key}
        self.assertIn("pre(a|b)post", regexes.values())
        self.assertIn("outer(c|d)", regexes.values())
        self.assertIn("pre(b)post|outer(c|d)", regexes.values())
        self.assertIn("pre(a|b)post|outer(d)", regexes.values())

    def test_nested_regex_mutations_ignore_nonstructural_parentheses(self):
        cases = {
            r"\(a|b\)": {r"\(a", r"b\)"},
            r"[(a|b)]": set(),
            "(?x:(a # ignored | fake\n|b))": {"(?x:(b))", "(?x:(a # ignored | fake\n))"},
            "^(?:pre(a|b)post)$": {"^(?:pre(b)post)$", "^(?:pre(a)post)$"},
        }
        for pattern, expected in cases.items():
            with self.subTest(pattern=pattern):
                mutations = {
                    value["regex"] for key, value in
                    PLAN.mutation_candidates({"regex": pattern})
                    if "regex-alternative" in key
                }
                self.assertEqual(mutations, expected)

    def test_nested_alternatives_inside_grouped_alternatives_are_mutated(self):
        mutations = {
            value["regex"] for key, value in
            PLAN.mutation_candidates({"regex": "^(?:(a|b)|c)$"})
            if "regex-alternative" in key
        }
        self.assertEqual(
            mutations,
            {"^(?:c)$", "^(?:(a|b))$", "^(?:(b)|c)$", "^(?:(a)|c)$"},
        )

    def test_nested_group_reparse_uses_mode_at_group_open(self):
        pattern = "(?x:(a # ignored | fake\n(?-x)b|c))"
        mutations = {
            value["regex"] for key, value in
            PLAN.mutation_candidates({"regex": pattern})
            if "regex-alternative" in key
        }
        self.assertEqual(
            mutations,
            {"(?x:(c))", "(?x:(a # ignored | fake\n(?-x)b))"},
        )

    def test_scoped_verbose_group_does_not_mask_outer_alternative(self):
        pattern = "^foo#bar$|^(?x:a|b)$"
        mutations = dict(PLAN.mutation_candidates({"regex": pattern}))
        self.assertEqual(
            mutations["rule.regex-alternative[0]-deleted"]["regex"],
            "^(?x:a|b)$",
        )
        self.assertEqual(
            mutations["rule.regex-alternative[1]-deleted"]["regex"],
            "^foo#bar$",
        )

    def test_scoped_verbose_comment_keeps_group_structure(self):
        pattern = "^foo$|(?x:a # ) | fake\n|b)$"
        mutations = dict(PLAN.mutation_candidates({"regex": pattern}))
        expected = ("(?x:a # ) | fake\n|b)$", "^foo$")
        keys = [key for key in mutations if "regex-alternative" in key]
        self.assertEqual(len(keys), 4)
        self.assertEqual(
            {mutations[key]["regex"] for key in keys},
            {"(?x:a # ) | fake\n|b)$", "^foo$",
             "^foo$|(?x:b)$", "^foo$|(?x:a # ) | fake\n)$"},
        )
        for index, regex in enumerate(expected):
            self.assertEqual(
                mutations[f"rule.regex-alternative[{index}]-deleted"]["regex"], regex)
            rule = yaml.safe_dump({
                "id": f"scoped-{index}", "language": "python", "message": "x",
                "severity": "warning", "rule": {"kind": "identifier", "regex": regex},
            })
            passed, detail = PLAN.run_preflight(
                rule, {"invalid": ["b" if index == 0 else "foo"], "valid": ["closed"]},
                f"scoped-{index}")
            self.assertTrue(passed, detail)

    def test_anchored_scoped_verbose_group_has_two_valid_mutants(self):
        pattern = "^(?x:open # ignored | fake\n|read)$"
        mutations = dict(PLAN.mutation_candidates({"regex": pattern}))
        expected = ("^(?x:read)$", "^(?x:open # ignored | fake\n)$")
        keys = [key for key in mutations if "regex-alternative" in key]
        self.assertEqual(len(keys), 2)
        for index, regex in enumerate(expected):
            self.assertEqual(
                mutations[f"rule.regex-alternative[{index}]-deleted"]["regex"], regex)
            rule = yaml.safe_dump({
                "id": f"anchored-{index}", "language": "python", "message": "x",
                "severity": "warning", "rule": {"kind": "identifier", "regex": regex},
            })
            passed, detail = PLAN.run_preflight(
                rule, {"invalid": ["read" if index == 0 else "open"],
                       "valid": ["closed"]}, f"anchored-{index}")
            self.assertTrue(passed, detail)

    def test_uppercase_inline_flags_preserve_scoped_verbose_comments(self):
        pattern = "^foo$|(?Ux:a # ) | fake\n|b)$"
        mutations = dict(PLAN.mutation_candidates({"regex": pattern}))
        expected = ("(?Ux:a # ) | fake\n|b)$", "^foo$")
        keys = [key for key in mutations if "regex-alternative" in key]
        self.assertEqual(len(keys), 4)
        self.assertEqual(
            {mutations[key]["regex"] for key in keys},
            {"(?Ux:a # ) | fake\n|b)$", "^foo$",
             "^foo$|(?Ux:b)$", "^foo$|(?Ux:a # ) | fake\n)$"},
        )
        for index, regex in enumerate(expected):
            self.assertEqual(
                mutations[f"rule.regex-alternative[{index}]-deleted"]["regex"], regex)
            rule = yaml.safe_dump({
                "id": f"uppercase-{index}", "language": "python", "message": "x",
                "severity": "warning", "rule": {"kind": "identifier", "regex": regex},
            })
            passed, detail = PLAN.run_preflight(
                rule, {"invalid": ["b" if index == 0 else "foo"], "valid": ["closed"]},
                f"uppercase-{index}")
            self.assertTrue(passed, detail)

    def test_grouped_disabled_verbose_flags_keep_hash_literal(self):
        for prefix in ("?-x", "?i-x"):
            pattern = f"^({prefix}:a#literal|b)$"
            with self.subTest(pattern=pattern):
                mutations = dict(PLAN.mutation_candidates({"regex": pattern}))
                expected = (f"^({prefix}:b)$", f"^({prefix}:a#literal)$")
                keys = [key for key in mutations if "regex-alternative" in key]
                self.assertEqual(len(keys), 2)
                for index, regex in enumerate(expected):
                    self.assertEqual(
                        mutations[f"rule.regex-alternative[{index}]-deleted"]["regex"],
                        regex)
                    rule = yaml.safe_dump({
                        "id": f"disabled-{index}", "language": "python",
                        "message": "x", "severity": "warning",
                        "rule": {"kind": "string_content", "regex": regex},
                    })
                    witness = '"b"' if index == 0 else '"a#literal"'
                    passed, detail = PLAN.run_preflight(
                        rule, {"invalid": [witness], "valid": ['"closed"']},
                        f"disabled-{index}")
                    self.assertTrue(passed, detail)

    def test_grouped_regex_mutants_are_engine_valid_with_exact_text(self):
        mutations = dict(PLAN.mutation_candidates({"regex": "^(?:open|read|write)$"}))
        rows = (("^(?:read|write)$", "read"), ("^(?:open|write)$", "open"),
                ("^(?:open|read)$", "open"))
        for index, (expected, witness) in enumerate(rows):
            regex = mutations[f"rule.regex-alternative[{index}]-deleted"]["regex"]
            self.assertEqual(regex, expected)
            rule = yaml.safe_dump({
                "id": f"regex-{index}", "language": "python", "message": "x",
                "severity": "warning", "rule": {"kind": "identifier", "regex": regex},
            })
            passed, detail = PLAN.run_preflight(
                rule, {"invalid": [witness], "valid": ["closed"]}, f"regex-{index}")
            self.assertTrue(passed, detail)
