"""Syntax-aware source transforms and regex mutation helpers for rule plans."""

import re
from dataclasses import dataclass, field

METAMORPHIC_LANGUAGES = {
    "parenthesized": {"python"},
    "callee-parenthesized": {"c", "cpp", "javascript", "typescript", "python"},
    "qualified-name-spacing": {"python", "javascript", "typescript", "java", "php"},
    "member-access-spacing": {"c", "cpp", "javascript", "typescript", "java", "go", "php"},
    "literal-spacing": {"c", "cpp", "python"},
    "format-width": {"c", "cpp", "go"}, "format-precision": {"c", "cpp", "go"},
    "qualified-name": {"cpp"}, "member-access-swap": {"c", "cpp"},
    "literal-concatenation": {"c", "cpp", "python"},
}

FORMAT_CONVERSION = re.compile(
    r"%(?!%)(?P<flags>[-+ #0]*)(?P<width>\d+|\*)?"
    r"(?P<precision>\.(?:\d+|\*))?(?P<length>hh|ll|[hljztL])?"
    r"(?P<conversion>[diuoxXfFeEgGaAcspn])")


def _lexical_kinds(source: str, language: str) -> list[str]:
    """Classify source characters conservatively as code, string, or comment."""
    kinds = ["code"] * len(source)
    index = 0
    while index < len(source):
        end = _comment_end(source, index, language)
        if end is not None:
            kinds[index:end] = ["comment"] * (end - index)
            index = end
        elif language == "cpp" and source.startswith('R"', index):
            end = _cpp_raw_end(source, index)
            kinds[index:end] = ["string"] * (end - index)
            index = end
        elif source[index] in "'\"`":
            end = _quoted_end(source, index)
            kinds[index:end] = ["string"] * (end - index)
            index = end
        elif language in {"javascript", "typescript"} and source[index] == "/":
            end = _javascript_regex_end(source, index)
            if end is not None:
                kinds[index:end] = ["string"] * (end - index)
                index = end
                continue
            index += 1
        else:
            index += 1
    return kinds


def _comment_end(source: str, index: int, language: str) -> int | None:
    slash_comments = language not in {"python", "bash", "ruby"}
    hash_comments = language in {"python", "bash", "ruby"}
    if ((slash_comments and source.startswith("//", index))
            or (hash_comments and source[index] == "#")):
        newline = source.find("\n", index)
        return len(source) if newline < 0 else newline
    if slash_comments and source.startswith("/*", index):
        close = source.find("*/", index + 2)
        return len(source) if close < 0 else close + 2
    return None


def _quoted_end(source: str, index: int) -> int:
    quote = source[index]
    delimiter = quote * 3 if source.startswith(quote * 3, index) else quote
    end = index + len(delimiter)
    while end < len(source) and not source.startswith(delimiter, end):
        end += 2 if source[end] == "\\" else 1
    return min(len(source), end + len(delimiter))


def _cpp_raw_end(source: str, index: int) -> int:
    opening = source.find("(", index + 2)
    if opening < 0 or opening - index > 18:
        return index + 1
    delimiter = source[index + 2:opening]
    close = source.find(")" + delimiter + '"', opening + 1)
    return len(source) if close < 0 else close + len(delimiter) + 2


def _javascript_regex_end(source: str, index: int) -> int | None:
    previous = next((character for character in reversed(source[:index])
                     if not character.isspace()), "")
    if previous and previous not in "([=,:;!&|?{}":
        return None
    end, escaped, in_class = index + 1, False, False
    while end < len(source):
        character = source[end]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "[":
            in_class = True
        elif character == "]":
            in_class = False
        elif character == "/" and not in_class:
            end += 1
            while end < len(source) and source[end].isalpha():
                end += 1
            return end
        end += 1
    return None


def _replace_first(source: str, expression: re.Pattern, replacement,
                   language: str, target) -> tuple[str, int]:
    allowed, syntax_spans = target
    kinds = _lexical_kinds(source, language) if syntax_spans is None else None
    eligible = []
    for match in expression.finditer(source):
        in_syntax = syntax_spans is None or any(
            start <= match.start() and match.end() <= end for start, end in syntax_spans)
        lexical_match = kinds is None or set(kinds[match.start():match.end()]) <= allowed
        if in_syntax and (syntax_spans is not None or lexical_match):
            eligible.append(match)
    if len(eligible) != 1:
        return source, len(eligible)
    match = eligible[0]
    value = replacement(match) if callable(replacement) else match.expand(replacement)
    return source[:match.start()] + value + source[match.end():], 1


def _parenthesize_callee(source: str,
                         syntax_spans: list[tuple[int, int]] | None) -> tuple[str, int]:
    if not syntax_spans:
        return source, 0
    start, end = syntax_spans[0]
    return source[:start] + f"({source[start:end]})" + source[end:], 1


def metamorphic_source(source: str, transform: str, language: str,
                       syntax_spans: list[tuple[int, int]] | None = None) -> str:
    """Apply one transform only to a token of the intended lexical class."""
    if transform in {"parenthesized", "callee-parenthesized"}:
        changed, count = _parenthesize_callee(source, syntax_spans)
    elif transform in {"qualified-name-spacing", "member-access-spacing"}:
        changed, count = _replace_first(
            source, re.compile(r"\s*(\?->|\?\.|->|\.)\s*"), r" \1 ", language,
            ({"code"}, syntax_spans))
    elif transform == "qualified-name":
        changed, count = _replace_first(
            source, re.compile(r"(?<!:)\b([A-Za-z_]\w*::)"), r"::\1", language,
            ({"code"}, syntax_spans))
    elif transform == "member-access-swap":
        changed, count = _replace_first(
            source, re.compile(r"->|\."),
            lambda match: "." if match[0] == "->" else "->", language,
            ({"code"}, syntax_spans))
    elif transform == "literal-concatenation":
        changed, count = _concatenate_literal(source, language, syntax_spans)
    elif transform == "literal-spacing":
        changed, count = _space_literal_gap(source, syntax_spans)
    elif transform == "format-width":
        changed, count = _transform_format_conversion(
            source, language, precision=False, syntax_spans=syntax_spans)
    elif transform == "format-precision":
        changed, count = _transform_format_conversion(
            source, language, precision=True, syntax_spans=syntax_spans)
    else:
        raise ValueError(f"unsupported metamorphic transform: {transform}")
    if count != 1 or changed == source:
        raise ValueError(f"metamorphic transform {transform} is not applicable")
    return changed


def _space_literal_gap(source: str,
                       syntax_spans: list[tuple[int, int]] | None) -> tuple[str, int]:
    if not syntax_spans:
        return source, 0
    start, end = syntax_spans[0]
    return source[:start] + "   " + source[end:], 1


def _concatenate_literal(source: str, language: str,
                         syntax_spans: list[tuple[int, int]] | None) -> tuple[str, int]:
    if not syntax_spans:
        return source, 0
    _start, end = syntax_spans[0]
    literal = source[syntax_spans[0][0]:end]
    if language == "python":
        opening = re.match(r"(?i)([rubf]*)(\"\"\"|'''|\"|')", literal)
        if not opening:
            return source, 0
        prefix, delimiter = opening.groups()
        empty = prefix + delimiter * 2
    else:
        empty = '""'
    return source[:end] + " " + empty + source[end:], 1


def _transform_format_conversion(source: str, language: str,
                                 *, precision: bool,
                                 syntax_spans=None) -> tuple[str, int]:
    kinds = _lexical_kinds(source, language) if syntax_spans is None else None
    matches = [candidate for candidate in FORMAT_CONVERSION.finditer(source)
                  if (kinds is None or set(kinds[candidate.start():candidate.end()]) == {"string"})
                  and _preceding_percent_count(source, candidate.start()) % 2 == 0
                  and not candidate.group("precision" if precision else "width")
                  and (syntax_spans is None or any(
                      start <= candidate.start() and candidate.end() <= end
                      for start, end in syntax_spans))]
    if len(matches) != 1:
        return source, len(matches)
    match = matches[0]
    parts = match.groupdict(default="")
    if precision:
        parts["precision"] = ".3"
    else:
        parts["width"] = "20"
    replacement = (f"%{parts['flags']}{parts['width']}{parts['precision']}"
                   f"{parts['length']}{parts['conversion']}")
    return source[:match.start()] + replacement + source[match.end():], 1


def _preceding_percent_count(source: str, offset: int) -> int:
    count = 0
    while offset > count and source[offset - count - 1] == "%":
        count += 1
    return count


def regex_alternatives(pattern: str, *, verbose: bool = False) -> list[str]:
    """Split real top-level alternatives while preserving original regex bytes."""
    parts, start = [], 0
    for index in _top_level_bars(pattern, verbose):
        parts.append(pattern[start:index])
        start = index + 1
    parts.append(pattern[start:])
    return parts if len(parts) > 1 and all(parts) else []


def nested_regex_alternative_mutations(pattern: str):
    """Yield byte-preserving deletions from every structural regex group."""
    state = _RegexState([False])
    index = 0
    while index < len(pattern):
        index = state.advance(pattern, index)
    for start, end, verbose in state.groups:
        alternatives = regex_alternatives(pattern[start:end], verbose=verbose)
        for index in range(len(alternatives)):
            remaining = "|".join(part for part_index, part in enumerate(alternatives)
                                 if part_index != index)
            yield f"group@{start}.{index}", pattern[:start] + remaining + pattern[end:]


INLINE_FLAGS = re.compile(r"\(\?([aiLmsuxUR]*)(?:-([aiLmsuxUR]*))?([:)])")


def inline_verbose(fragment: str, inherited: bool = False) -> bool:
    """Apply supported inline enable/disable flags to inherited verbose mode."""
    flags = INLINE_FLAGS.match(fragment)
    if not flags:
        return inherited
    enabled, disabled, _terminator = flags.groups()
    return (inherited or "x" in enabled) and "x" not in (disabled or "")


@dataclass
class _RegexState:
    modes: list[bool]
    escaped: bool = False
    in_comment: bool = False
    bars: list[int] = field(default_factory=list)
    group_starts: list[tuple[int, bool]] = field(default_factory=list)
    groups: list[tuple[int, int, bool]] = field(default_factory=list)

    def advance(self, pattern: str, index: int) -> int:
        character = pattern[index]
        if self.in_comment:
            self.in_comment = character != "\n"
        elif self.escaped:
            self.escaped = False
        elif character == "\\":
            self.escaped = True
        elif character == "[":
            return _class_end(pattern, index)
        elif self.modes[-1] and character == "#":
            self.in_comment = True
        elif character == "(":
            index = self._open_group(pattern, index)
        elif character == ")" and len(self.modes) > 1:
            start, opening_mode = self.group_starts.pop()
            self.groups.append((start, index, opening_mode))
            self.modes.pop()
        elif character == "|" and len(self.modes) == 1:
            self.bars.append(index)
        return index + 1

    def _open_group(self, pattern: str, index: int) -> int:
        flags = INLINE_FLAGS.match(pattern, index)
        if not flags:
            self.modes.append(self.modes[-1])
            self.group_starts.append((index + 1, self.modes[-1]))
            return index
        _enabled, _disabled, terminator = flags.groups()
        mode = inline_verbose(pattern[index:], self.modes[-1])
        if terminator == ":":
            self.modes.append(mode)
            self.group_starts.append((flags.end(), mode))
        else:
            self.modes[-1] = mode
        return flags.end() - 1


def _class_end(pattern: str, index: int) -> int:
    """Skip one bracket class, including leading `]` and POSIX bracket syntax."""
    cursor = index + 1
    if cursor < len(pattern) and pattern[cursor] == "^":
        cursor += 1
    if cursor < len(pattern) and pattern[cursor] == "]":
        cursor += 1
    depth = 1
    while cursor < len(pattern):
        if pattern[cursor] == "\\":
            cursor += 2
            continue
        if pattern.startswith(("[:", "[.", "[="), cursor):
            marker = pattern[cursor + 1]
            close = pattern.find(marker + "]", cursor + 2)
            cursor = len(pattern) if close < 0 else close + 2
            continue
        if pattern[cursor] == "[":
            depth += 1
        if pattern[cursor] == "]":
            depth -= 1
            if depth == 0:
                return cursor + 1
        cursor += 1
    return cursor


def _top_level_bars(pattern: str, verbose: bool) -> list[int]:
    """Track escape, class, nesting, scoped flags, and verbose-comment state.

    Escapes and character classes suppress structural punctuation. Each group
    inherits its parent's verbose mode unless scoped flags change it. A `#`
    starts a comment only while that active scope is verbose; parentheses and
    bars inside the comment remain inert until the newline.
    """
    state = _RegexState([verbose])
    index = 0
    while index < len(pattern):
        index = state.advance(pattern, index)
    return state.bars
