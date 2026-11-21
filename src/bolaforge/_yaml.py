"""Small, allocation-bounded, security-first YAML subset reader.

The reader supports the subset of YAML that OpenAPI documents actually use:
block mappings, block sequences (including inline ``- key: value`` items),
flow collections, quoted and plain scalars, comments, document markers and
literal/folded block scalars. Aliases, anchors, custom tags and multiple
documents are rejected because they enable entity-expansion and code-execution
surprises in unrelated YAML libraries.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

MAX_LINES = 200_000
MAX_DEPTH = 200

_INT_RE = re.compile(r"^[+-]?(?:0|[1-9][0-9]*)$")
_FLOAT_RE = re.compile(r"^[+-]?(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$")


class YamlSubsetError(ValueError):
    """Raised when a document falls outside the supported safe YAML subset."""


def _is_escaped(text: str, index: int) -> bool:
    count = 0
    position = index - 1
    while position >= 0 and text[position] == "\\":
        count += 1
        position -= 1
    return count % 2 == 1


@dataclass(frozen=True, slots=True)
class _Line:
    indent: int
    content: str
    number: int


def _strip_comment(text: str) -> str:
    quote = ""
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if quote == '"' and char == "\\":
            escaped = True
            continue
        if char in "\"'":
            if quote == "":
                quote = char
            elif quote == char:
                quote = ""
            continue
        if char == "#" and quote == "" and (index == 0 or text[index - 1].isspace()):
            return text[:index].rstrip()
    return text.rstrip()


def _reject_unsafe(text: str, number: int) -> None:
    quote = ""
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if quote == '"' and char == "\\":
            escaped = True
            index += 1
            continue
        if char in "\"'":
            if quote == "":
                quote = char
            elif quote == char:
                quote = ""
            index += 1
            continue
        if quote == "":
            if char == "!" and text.startswith("!!", index):
                raise YamlSubsetError(f"line {number}: custom tags are not allowed")
            if char in "&*" and index + 1 < len(text):
                following = text[index + 1]
                if following.isalpha() or following == "_":
                    raise YamlSubsetError(f"line {number}: anchors and aliases are not allowed")
        index += 1


def _split_key(text: str, number: int) -> tuple[str, str]:
    quote = ""
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if quote == '"' and char == "\\":
            escaped = True
            continue
        if char in "\"'":
            if quote == "":
                quote = char
            elif quote == char:
                quote = ""
            continue
        if char == ":" and quote == "" and (index + 1 == len(text) or text[index + 1].isspace()):
            key = text[:index].strip()
            if not key:
                raise YamlSubsetError(f"line {number}: empty mapping key")
            return _parse_scalar(key, number), text[index + 1 :].strip()
    raise YamlSubsetError(f"line {number}: expected 'key: value' mapping entry")


def _is_sequence_item(text: str) -> bool:
    return text == "-" or text.startswith("- ")


def _parse_flow(text: str, number: int) -> Any:
    index = 0

    def skip_space() -> None:
        nonlocal index
        while index < len(text) and text[index].isspace():
            index += 1

    def parse_key() -> str:
        nonlocal index
        skip_space()
        if index < len(text) and text[index] in "\"'":
            value = parse_value()
            if not isinstance(value, str):
                raise YamlSubsetError(f"line {number}: flow mapping keys must be strings")
            return value
        start = index
        quote = ""
        depth = 0
        while index < len(text):
            char = text[index]
            if quote:
                if char == quote and (quote == "'" or not _is_escaped(text, index)):
                    quote = ""
            elif char in "\"'":
                quote = char
            elif char in "[{":
                depth += 1
            elif char in "]}":
                depth -= 1
            elif char == ":" and depth == 0:
                key = _parse_scalar(text[start:index].strip(), number)
                index += 1
                if not isinstance(key, str):
                    raise YamlSubsetError(f"line {number}: flow mapping keys must be strings")
                return key
            index += 1
        raise YamlSubsetError(f"line {number}: unterminated flow mapping key")

    def parse_value() -> Any:
        nonlocal index
        skip_space()
        if index >= len(text):
            raise YamlSubsetError(f"line {number}: unterminated flow collection")
        char = text[index]
        if char == "[":
            index += 1
            values: list[Any] = []
            skip_space()
            if index < len(text) and text[index] == "]":
                index += 1
                return values
            while True:
                values.append(parse_value())
                skip_space()
                if index >= len(text):
                    raise YamlSubsetError(f"line {number}: unterminated flow sequence")
                if text[index] == ",":
                    index += 1
                    continue
                if text[index] == "]":
                    index += 1
                    return values
                raise YamlSubsetError(f"line {number}: invalid flow sequence separator")
        if char == "{":
            index += 1
            values_map: dict[str, Any] = {}
            skip_space()
            if index < len(text) and text[index] == "}":
                index += 1
                return values_map
            while True:
                key_value = parse_key()
                values_map[key_value] = parse_value()
                skip_space()
                if index >= len(text):
                    raise YamlSubsetError(f"line {number}: unterminated flow mapping")
                if text[index] == ",":
                    index += 1
                    continue
                if text[index] == "}":
                    index += 1
                    return values_map
                raise YamlSubsetError(f"line {number}: invalid flow mapping separator")
        if char in "\"'":
            quote = char
            start = index
            index += 1
            escaped = False
            while index < len(text):
                current = text[index]
                if escaped:
                    escaped = False
                elif quote == '"' and current == "\\":
                    escaped = True
                elif current == quote:
                    if quote == "'" and index + 1 < len(text) and text[index + 1] == "'":
                        index += 2
                        continue
                    index += 1
                    return _parse_scalar(text[start:index], number)
                index += 1
            raise YamlSubsetError(f"line {number}: unterminated quoted scalar")
        start = index
        while index < len(text) and text[index] not in ",]}":
            index += 1
        return _parse_scalar(text[start:index].strip(), number)

    result = parse_value()
    skip_space()
    if index != len(text):
        raise YamlSubsetError(f"line {number}: trailing data in flow collection")
    return result


def _parse_scalar(raw: str, number: int) -> Any:
    text = raw.strip()
    if not text:
        return None
    if text[0] == "'":
        if len(text) < 2 or not text.endswith("'"):
            raise YamlSubsetError(f"line {number}: unterminated single-quoted scalar")
        return text[1:-1].replace("''", "'")
    if text[0] == '"':
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise YamlSubsetError(
                f"line {number}: invalid double-quoted scalar: {exc.msg}"
            ) from exc
        if not isinstance(value, str):
            raise YamlSubsetError(f"line {number}: expected a string scalar")
        return value
    if text[0] in "[{":
        return _parse_flow(text, number)
    if text in {"null", "Null", "NULL", "~"}:
        return None
    if text in {"true", "True", "TRUE"}:
        return True
    if text in {"false", "False", "FALSE"}:
        return False
    if _INT_RE.match(text):
        return int(text)
    if _FLOAT_RE.match(text):
        return float(text)
    return text


def _tokenize(source: str) -> list[_Line]:
    if source.startswith("\ufeff"):
        source = source[1:]
    lines = source.splitlines()
    if len(lines) > MAX_LINES:
        raise YamlSubsetError(f"document exceeds {MAX_LINES} lines")
    raw_lines: list[_Line] = []
    document_started = False
    for number, original in enumerate(lines, start=1):
        if not original.strip() or original.lstrip().startswith("#"):
            continue
        if original.lstrip().startswith("%"):
            raise YamlSubsetError(f"line {number}: YAML directives are not allowed")
        prefix = len(original) - len(original.lstrip(" "))
        if prefix < len(original) and original[prefix] == "\t":
            raise YamlSubsetError(f"line {number}: tabs are not allowed for indentation")
        content = _strip_comment(original[prefix:])
        if not content:
            continue
        _reject_unsafe(content, number)
        if content == "---":
            if document_started:
                raise YamlSubsetError(f"line {number}: multiple YAML documents are not allowed")
            document_started = True
            continue
        if content == "...":
            continue
        document_started = True
        if prefix > MAX_DEPTH:
            raise YamlSubsetError(f"line {number}: indentation depth exceeds {MAX_DEPTH}")
        raw_lines.append(_Line(prefix, content, number))

    expanded: list[_Line] = []
    for line in raw_lines:
        if _is_sequence_item(line.content) and line.content != "-":
            remainder = line.content[1:].strip()
            try:
                _split_key(remainder, line.number)
            except YamlSubsetError:
                expanded.append(line)
            else:
                expanded.append(_Line(line.indent, "-", line.number))
                expanded.append(_Line(line.indent + 2, remainder, line.number))
        else:
            expanded.append(line)
    return expanded


def loads(source: str) -> Any:
    """Parse a safe YAML subset document into plain Python containers."""

    lines = _tokenize(source)
    if not lines:
        return None
    value, position = _parse_node(lines, 0, 0)
    if position != len(lines):
        raise YamlSubsetError(f"line {lines[position].number}: unexpected indentation")
    return value


def _parse_node(lines: list[_Line], position: int, indent: int) -> tuple[Any, int]:
    if position >= len(lines):
        return None, position
    if lines[position].indent != indent:
        raise YamlSubsetError(f"line {lines[position].number}: unexpected indentation")
    if _is_sequence_item(lines[position].content):
        return _parse_sequence(lines, position, indent)
    return _parse_mapping(lines, position, indent)


def _parse_sequence(lines: list[_Line], position: int, indent: int) -> tuple[list[Any], int]:
    items: list[Any] = []
    while position < len(lines) and lines[position].indent == indent:
        line = lines[position]
        if not _is_sequence_item(line.content):
            break
        remainder = line.content[1:].strip()
        position += 1
        if remainder:
            items.append(_parse_scalar(remainder, line.number))
            continue
        if position < len(lines) and lines[position].indent > indent:
            value, position = _parse_node(lines, position, lines[position].indent)
            items.append(value)
        else:
            items.append(None)
    return items, position


def _parse_mapping(lines: list[_Line], position: int, indent: int) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    while position < len(lines) and lines[position].indent == indent:
        line = lines[position]
        if _is_sequence_item(line.content):
            break
        key, raw = _split_key(line.content, line.number)
        if key in result:
            raise YamlSubsetError(f"line {line.number}: duplicate mapping key {key!r}")
        position += 1
        if raw in {"|", "|-", ">", ">-"}:
            result[key], position = _parse_block_scalar(lines, position, indent, raw)
        elif raw:
            result[key] = _parse_scalar(raw, line.number)
        elif position < len(lines) and lines[position].indent > indent:
            result[key], position = _parse_node(lines, position, lines[position].indent)
        else:
            result[key] = None
    return result, position


def _parse_block_scalar(
    lines: list[_Line], position: int, indent: int, style: str
) -> tuple[str, int]:
    collected: list[str] = []
    while position < len(lines) and lines[position].indent > indent:
        collected.append(lines[position].content)
        position += 1
    separator = "\n" if style.startswith("|") else " "
    text = separator.join(collected)
    if not style.endswith("-"):
        text += "\n"
    return text, position
