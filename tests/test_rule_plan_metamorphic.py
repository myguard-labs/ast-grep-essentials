import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from tests.mechanics_test_support import ROOT, load_tool, minimal_plan

PLAN = load_tool("rule-plan")


class RulePlanMetamorphicTests(unittest.TestCase):
    def test_claim_matrix_requires_each_pairwise_combination(self):
        plan = minimal_plan(
            cases={"invalid": ["a()", "b()"], "valid": ["safe()"]},
            claims={
                "api": {"a": ["a()"], "b": ["b()"]},
                "operator": {"call": ["a()", "b()"]},
            },
        )
        PLAN.validate_plan(plan)
        plan["claims"]["operator"]["call"] = ["a()"]
        with self.assertRaisesRegex(ValueError, "CLAIM_PAIR_UNCOVERED.*api.b"):
            PLAN.validate_plan(plan)

    def test_claim_matrix_rejects_semantic_dimensions_and_valid_witnesses(self):
        with self.assertRaisesRegex(ValueError, "syntax-only"):
            PLAN.validate_plan(minimal_plan(claims={"runtime-type": {"file": ["danger()"]}}))
        with self.assertRaisesRegex(ValueError, "non-invalid witnesses"):
            PLAN.validate_plan(minimal_plan(claims={"api": {"safe": ["safe()"]}}))
        with self.assertRaisesRegex(ValueError, "dimension names must be strings"):
            PLAN.validate_plan(minimal_plan(claims={1: {"api": ["danger()"]}}))
        for name in (" ", " padded", "padded ", "line\nbreak", "tab\tname"):
            with self.subTest(name=repr(name)), self.assertRaisesRegex(
                    ValueError, "must map names"):
                PLAN.validate_plan(minimal_plan(claims={"api": {name: ["danger()"]}}))

    def test_declared_metamorphic_cases_preserve_or_change_outcome(self):
        plan = minimal_plan(metamorphic=[
            {"source": "safe(); danger()", "transform": "callee-parenthesized",
             "outcome": "equivalent"},
        ], cases={"invalid": ["safe(); danger()"], "valid": ["safe()"]})
        matcher, cases = PLAN.validate_plan(plan)
        self.assertEqual(matcher, {"pattern": "danger()"})
        expanded = PLAN.expanded_cases(plan, cases)
        self.assertIn("safe(); (danger)()", expanded["invalid"])

        unmatched = minimal_plan(metamorphic=[{
            "source": "safe()", "transform": "callee-parenthesized",
            "outcome": "different",
        }])
        _matcher, cases = PLAN.validate_plan(unmatched)
        self.assertIn("(safe)()", PLAN.expanded_cases(unmatched, cases)["invalid"])
        with self.assertRaisesRegex(RuntimeError, "CONTRAST_PREFLIGHT_FAILED"):
            PLAN.preflight(unmatched, _matcher, cases)

        for language, source, expected in (
            ("c", "int x='%s'; log(\"%s\", value);",
             "int x='%s'; log(\"%20s\", value);"),
            ("go", "fake := `%s`; log(\"%s\", value)",
             "fake := `%s`; log(\"%20s\", value)"),
        ):
            with self.subTest(language=language):
                plan = minimal_plan(
                    language=language, rule={"pattern": 'log("%s", value)'},
                    cases={"invalid": [source], "valid": ["safe()"]},
                    metamorphic=[{"source": source, "transform": "format-width",
                                  "outcome": "equivalent"}],
                )
                _matcher, cases = PLAN.validate_plan(plan)
                self.assertIn(expected, PLAN.expanded_cases(plan, cases)["invalid"])

    def test_metamorphic_rejects_unknown_or_inapplicable_transforms(self):
        with self.assertRaisesRegex(ValueError, "invalid metamorphic"):
            PLAN.validate_plan(minimal_plan(metamorphic=[
                {"source": "danger()", "transform": "rename-symbol",
                 "outcome": "equivalent"},
            ]))
        plan = minimal_plan(language="c", metamorphic=[
            {"source": "danger()", "transform": "format-width", "outcome": "equivalent"},
        ])
        _matcher, cases = PLAN.validate_plan(plan)
        with self.assertRaisesRegex(ValueError, "not applicable"):
            PLAN.expanded_cases(plan, cases)
        with self.assertRaisesRegex(ValueError, "must be strings"):
            PLAN.validate_plan(minimal_plan(metamorphic=[{
                "source": ["danger()"], "transform": "parenthesized",
                "outcome": "equivalent",
            }]))
        with self.assertRaisesRegex(ValueError, "does not support bash"):
            PLAN.validate_plan(minimal_plan(language="bash", metamorphic=[
                {"source": "danger()", "transform": "member-access-swap",
                 "outcome": "equivalent"},
            ]))
        with self.assertRaisesRegex(ValueError, "does not support c"):
            PLAN.validate_plan(minimal_plan(language="c", metamorphic=[{
                "source": "ns::call()", "transform": "qualified-name",
                "outcome": "equivalent",
            }], cases={"invalid": ["ns::call()"], "valid": ["safe();"]}))

    def test_metamorphic_derives_required_syntax_families(self):
        cases = {
            ("obj->field", "member-access-swap"): "obj.field",
            ("ns::call()", "qualified-name"): "::ns::call()",
            ('log("value")', "literal-concatenation"): 'log("value" "")',
            ('log("%s", value)', "format-width"): 'log("%20s", value)',
            ('log("%s", value)', "format-precision"): 'log("%.3s", value)',
            ('value = "a" "b"', "literal-spacing"): 'value = "a"   "b"',
            ("danger()", "parenthesized"): "(danger())",
        }
        for (source, transform), expected in cases.items():
            with self.subTest(transform=transform):
                language = ("python" if transform in {"parenthesized", "literal-spacing"}
                            else "cpp" if transform == "qualified-name" else "c")
                self.assertEqual(
                    PLAN._metamorphic_source(  # pylint: disable=protected-access
                        source, transform, language), expected)

    def test_metamorphic_transforms_skip_lexical_lookalikes(self):
        cases = {
            ('["fake()", danger()]', "callee-parenthesized", "python"):
                '["fake()", (danger)()]',
            ('"obj.field"; obj.field', "member-access-spacing", "javascript"):
                '"obj.field"; obj . field',
            ('# fake()\ndanger()', "callee-parenthesized", "python"):
                '# fake()\n(danger)()',
            ('// "fake"\nlog("real")', "literal-concatenation", "c"):
                '// "fake"\nlog("real" "")',
            ('// %s\nlog("%s", value)', "format-width", "c"):
                '// %s\nlog("%20s", value)',
            ('[/obj.field/, obj.field]', "member-access-spacing", "javascript"):
                '[/obj.field/, obj . field]',
            ('x // y; danger()', "callee-parenthesized", "python"):
                'x // y; (danger)()',
            ('function f(){ return /obj.field/; } obj.field;',
             "member-access-spacing", "javascript"):
                'function f(){ return /obj.field/; } obj . field;',
            ('function f(){ return /fake.name/; } obj.name;',
             "qualified-name-spacing", "javascript"):
                'function f(){ return /fake.name/; } obj . name;',
            ('if (x) /fake.name/; obj.name;',
             "qualified-name-spacing", "javascript"):
                'if (x) /fake.name/; obj . name;',
            ('x = 1.2\nobj.name', "qualified-name-spacing", "python"):
                'x = 1.2\nobj . name',
            ('class X { void f(){ double x=1.2; obj.name(); } }',
             "qualified-name-spacing", "java"):
                'class X { void f(){ double x=1.2; obj . name(); } }',
            ('<?php $x = 1.2; $obj->name();', "qualified-name-spacing", "php"):
                '<?php $x = 1.2; $obj -> name();',
            ('# $fake->field\n$obj->field;', "member-access-spacing", "php"):
                '# $fake->field\n$obj -> field;',
            ('f"{obj.field}"', "qualified-name-spacing", "python"):
                'f"{obj . field}"',
            ('`${obj.field}`', "member-access-spacing", "javascript"):
                '`${obj . field}`',
            ('void f() { danger(); }', "callee-parenthesized", "cpp"):
                'void f() { (danger)(); }',
            ('obj->danger()', "callee-parenthesized", "cpp"):
                '(obj->danger)()',
            ('ns::danger()', "callee-parenthesized", "cpp"):
                '(ns::danger)()',
            ('obj.danger()', "callee-parenthesized", "javascript"):
                '(obj.danger)()',
            ('obj?.field', "member-access-spacing", "javascript"):
                'obj ?. field',
            ('$obj?->field', "member-access-spacing", "php"):
                '$obj ?-> field',
            ('handlers[key]()', "callee-parenthesized", "javascript"):
                '(handlers[key])()',
            ('handlers[0]()', "callee-parenthesized", "python"):
                '(handlers[0])()',
            ('(handler)()', "callee-parenthesized", "python"):
                '((handler))()',
            ('void f(){ danger(); }', "callee-parenthesized", "c"):
                'void f(){ (danger)(); }',
            ('int f(){ return danger(); }', "callee-parenthesized", "c"):
                'int f(){ return (danger)(); }',
            ('int f(){ int x = danger(); return x; }', "callee-parenthesized", "c"):
                'int f(){ int x = (danger)(); return x; }',
            ('void f(){ if (danger()) {} }', "callee-parenthesized", "c"):
                'void f(){ if ((danger)()) {} }',
        }
        for (source, transform, language), expected in cases.items():
            with self.subTest(transform=transform):
                self.assertEqual(
                    PLAN._metamorphic_source(  # pylint: disable=protected-access
                        source, transform, language), expected)

    def test_literal_spacing_requires_adjacent_literal_nodes_on_one_line(self):
        self.assertEqual(
            PLAN._metamorphic_source(  # pylint: disable=protected-access
                'value = "a"\t"b"', "literal-spacing", "python"),
            'value = "a"   "b"')
        for language in ("c", "cpp"):
            with self.subTest(transform="literal-spacing", language=language):
                self.assertEqual(
                    PLAN._metamorphic_source(  # pylint: disable=protected-access
                        'const char *x = "a" "b";', "literal-spacing", language),
                    'const char *x = "a"   "b";')
        for source, language in (('danger(" ")', "python"),
                                 ('danger(" ");', "c"),
                                 ('"a"\n"b"', "python"),
                                 ('"a"\r"b"', "python"),
                                 ('"a"\r\n"b"', "python")):
            with self.subTest(source=source), self.assertRaisesRegex(
                    ValueError, "not applicable"):
                PLAN._metamorphic_source(  # pylint: disable=protected-access
                    source, "literal-spacing", language)

    def test_format_transforms_skip_escaped_percent_and_existing_fields(self):
        transformed = [
            ('log("%% literal: %s", value)', "format-width",
             'log("%% literal: %20s", value)'),
            ('log("%%%s", value)', "format-precision", 'log("%%%.3s", value)'),
            ('log("%20s %s", first, second)', "format-width",
             'log("%20s %20s", first, second)'),
            ('log("%.2s %s", first, second)', "format-precision",
             'log("%.2s %.3s", first, second)'),
        ]
        for source, transform, expected in transformed:
            with self.subTest(source=source, transform=transform):
                # pylint: disable-next=protected-access
                self.assertEqual(PLAN._metamorphic_source(source, transform, "c"), expected)
        unchanged = [("%20s", "format-width"), ("%*s", "format-width"),
                     ("%.2s", "format-precision"), ("%.*s", "format-precision"),
                     ("%%", "format-width")]
        for source, transform in unchanged:
            with self.subTest(source=source, transform=transform), \
                    self.assertRaisesRegex(ValueError, "not applicable"):
                # pylint: disable-next=protected-access
                PLAN._metamorphic_source(source, transform, "c")

    def test_targeted_transforms_stay_within_structural_and_finding_spans(self):
        rows = (
            ("c", "void f(){ int x='%s'; log(\"%s\", x); }", "format-width",
             "void f(){ int x='%s'; log(\"%20s\", x); }"),
            ("go", "package p\nfunc f(){ _ = '%s'; log(`%s`, x) }", "format-width",
             "package p\nfunc f(){ _ = '%s'; log(`%20s`, x) }"),
            ("php", "<?php $x=1.2; $obj->name();", "member-access-spacing",
             "<?php $x=1.2; $obj -> name();"),
        )
        for language, source, transform, expected in rows:
            with self.subTest(language=language, transform=transform):
                # pylint: disable-next=protected-access
                self.assertEqual(PLAN._metamorphic_source(source, transform, language), expected)

        plan = minimal_plan(
            language="cpp", rule={"pattern": "ns::call()"},
            cases={"invalid": ["safe::call(); ns::call();"], "valid": ["safe();"]},
            metamorphic=[{
                "source": "safe::call(); ns::call();", "transform": "qualified-name",
                "outcome": "equivalent",
            }],
        )
        _matcher, cases = PLAN.validate_plan(plan)
        self.assertIn("safe::call(); ::ns::call();",
                      PLAN.expanded_cases(plan, cases)["invalid"])

        no_target = minimal_plan(
            language="php", rule={"pattern": "$X"},
            cases={"invalid": ["<?php $x=1.2;"], "valid": ["<?php safe();"]},
            metamorphic=[{
                "source": "<?php $x=1.2;", "transform": "member-access-spacing",
                "outcome": "equivalent",
            }],
        )
        _matcher, cases = PLAN.validate_plan(no_target)
        with patch.object(PLAN.SYNTAX, "rule_spans", return_value=[(0, 13)]), \
                patch.object(PLAN.SYNTAX, "syntax_spans", return_value=[]), \
                self.assertRaisesRegex(ValueError, "not applicable"):
            PLAN.expanded_cases(no_target, cases)

    def test_literal_concatenation_preserves_legal_literal_forms(self):
        rows = (
            ("python", "'value'", "'value' ''"),
            ("python", "''", "'' ''"),
            ("python", r"'a\'b'", r"'a\'b' ''"),
            ("python", "'''value'''", "'''value''' ''''''"),
            ("python", "b'value'", "b'value' b''"),
            ("cpp", 'R"tag(value)tag"', 'R"tag(value)tag" ""'),
        )
        for language, source, expected in rows:
            with self.subTest(language=language, source=source):
                # pylint: disable-next=protected-access
                actual = PLAN._metamorphic_source(
                    source, "literal-concatenation", language)
                self.assertEqual(actual, expected)

        for source, expected in (("value = 'a' 'b'", "value = 'a'   'b'"),
                                 ('value = b"a" b"b"', 'value = b"a"   b"b"'),
                                 ('R"(a)" R"(b)"', 'R"(a)"   R"(b)"')):
            with self.subTest(source=source):
                language = "cpp" if source.startswith("R") else "python"
                # pylint: disable-next=protected-access
                actual = PLAN._metamorphic_source(source, "literal-spacing", language)
                self.assertEqual(actual, expected)

        # pylint: disable-next=protected-access
        self.assertEqual(PLAN._metamorphic_source(
            'log(R"tag(%s)tag", value)', "format-width", "cpp"),
            'log(R"tag(%20s)tag", value)')

        raw = 'log(R"tag(quoted \" text \\\\ %s)tag", value)'
        # pylint: disable-next=protected-access
        self.assertEqual(PLAN._metamorphic_source(raw, "format-precision", "cpp"),
                         raw.replace("%s", "%.3s"))

    def test_bound_transforms_require_one_attributable_target(self):
        ambiguous = minimal_plan(
            language="c", rule={"pattern": {
                "context": 'sink("safe", "danger");', "selector": "call_expression",
            }},
            cases={"invalid": ['sink("safe", "danger");'], "valid": ["safe();"]},
            metamorphic=[{
                "source": 'sink("safe", "danger");',
                "transform": "literal-concatenation", "outcome": "equivalent",
            }],
        )
        _matcher, cases = PLAN.validate_plan(ambiguous)
        with self.assertRaisesRegex(ValueError, "one unambiguous target"):
            PLAN.expanded_cases(ambiguous, cases)

        different = minimal_plan(
            language="c", rule={"pattern": 'log("%20s", value)'},
            cases={"invalid": ['log("%20s", value)'],
                   "valid": ['log("%s", value)']},
            metamorphic=[{
                "source": 'log("%s", value)', "transform": "format-width",
                "outcome": "different",
            }],
        )
        _matcher, cases = PLAN.validate_plan(different)
        expanded = PLAN.expanded_cases(different, cases)
        self.assertIn('log("%20s", value)', expanded["invalid"])
        passed, _detail = PLAN.run_preflight(
            PLAN.render_rule(different, _matcher), expanded, different["id"])
        self.assertTrue(passed)

        multiple = minimal_plan(
            language="c", rule={"pattern": 'log("%s %s", a, b)'},
            cases={"invalid": ['log("%s %s", a, b)'], "valid": ["safe();"]},
            metamorphic=[{
                "source": 'log("%s %s", a, b)', "transform": "format-width",
                "outcome": "equivalent",
            }],
        )
        _matcher, cases = PLAN.validate_plan(multiple)
        with self.assertRaisesRegex(ValueError, "not applicable"):
            PLAN.expanded_cases(multiple, cases)

    def test_all_source_category_and_outcome_transitions(self):
        rows = (
            ("invalid", "equivalent", {"pattern": "log($FMT, value)"}, "invalid"),
            ("invalid", "different", {"pattern": 'log("%s", value)'}, "valid"),
            ("valid", "different", {"pattern": 'log("%20s", value)'}, "invalid"),
            ("valid", "equivalent", {"pattern": "danger()"}, "valid"),
        )
        source, transformed = 'log("%s", value)', 'log("%20s", value)'
        for category, outcome, rule, destination in rows:
            cases = {"invalid": ["danger()"], "valid": ["safe()"]}
            cases[category] = [source]
            if category == "valid" and outcome == "different":
                cases["invalid"] = [transformed]
            plan = minimal_plan(
                language="c", rule=rule, cases=cases,
                metamorphic=[{"source": source, "transform": "format-width",
                              "outcome": outcome}],
            )
            matcher, validated = PLAN.validate_plan(plan)
            expanded = PLAN.expanded_cases(plan, validated)
            with self.subTest(category=category, outcome=outcome):
                self.assertIn(transformed, expanded[destination])
                passed, _detail = PLAN.run_preflight(
                    PLAN.render_rule(plan, matcher), expanded, plan["id"])
                self.assertTrue(passed)

        wrong = {"invalid": [source], "valid": [transformed]}
        passed, _detail = PLAN.run_preflight(
            PLAN.render_rule(plan, matcher), wrong, plan["id"])
        self.assertFalse(passed)

    def test_compiled_plan_ir_matches_compatibility_artifacts(self):
        path = ROOT / "plans/python/security/py-tempfile-mktemp.yml"
        ir = PLAN.compile_plan_ir(path, run_checks=False)
        legacy = PLAN.compile_plan(path, run_checks=False)
        self.assertEqual(legacy, (PLAN.thaw(ir.plan), PLAN.thaw(ir.matcher),
                                  ir.rule_text, ir.fixture_text))

    def test_compiled_plan_ir_is_recursively_immutable(self):
        path = ROOT / "plans/python/security/py-tempfile-mktemp.yml"
        ir = PLAN.compile_plan_ir(path, run_checks=False)
        with self.assertRaises(TypeError):
            ir.plan["cases"]["invalid"][0] = "changed()"
        with self.assertRaises(TypeError):
            ir.matcher["kind"] = "identifier"

    def test_compiled_plan_ir_freezes_yaml_sets_and_thaws_compatibly(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.yml"
            path.write_text(yaml.safe_dump(minimal_plan(
                extensions={"tags": {"one", "two"}})), encoding="utf-8")
            ir = PLAN.compile_plan_ir(path, run_checks=False)
        self.assertIsInstance(ir.plan["extensions"]["tags"], frozenset)
        self.assertEqual(PLAN.thaw(ir.plan)["extensions"]["tags"], {"one", "two"})
