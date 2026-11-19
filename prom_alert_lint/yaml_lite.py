"""Lightweight pure-Python stdlib YAML parser for Prometheus & Alertmanager configs.

Supports:
- Mappings (key: value)
- Sequences (- item, - key: value)
- Inline sequences ([a, b, c]) and inline mappings ({k: v})
- Block scalars (| and >)
- Single-quoted and double-quoted strings, booleans, ints, floats, null
- Comments (# ...)
"""

from __future__ import annotations

import re
from typing import Any, List, Tuple


class YamlParseError(ValueError):
    """Raised when YAML input cannot be parsed."""


def _strip_comment(line: str) -> str:
    """Strip trailing # comment outside of single/double quotes."""
    in_single = False
    in_double = False
    escaped = False
    for idx, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_double:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if idx == 0 or line[idx - 1].isspace():
                return line[:idx].rstrip()
    return line.rstrip()


def _parse_scalar(raw: str) -> Any:
    val = raw.strip()
    if val == "" or val in ("null", "Null", "NULL", "~"):
        return None
    if val in ("true", "True", "TRUE"):
        return True
    if val in ("false", "False", "FALSE"):
        return False
    if (val.startswith('"') and val.endswith('"') and len(val) >= 2) or (
        val.startswith("'") and val.endswith("'") and len(val) >= 2
    ):
        inner = val[1:-1]
        if val.startswith('"'):
            inner = inner.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")
        else:
            inner = inner.replace("''", "'")
        return inner
    if val.startswith("[") and val.endswith("]"):
        inner = val[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part) for part in _split_inline(inner)]
    if val.startswith("{") and val.endswith("}"):
        inner = val[1:-1].strip()
        if not inner:
            return {}
        result = {}
        for part in _split_inline(inner):
            if ":" in part:
                k, v = part.split(":", 1)
                result[_parse_scalar(k)] = _parse_scalar(v)
        return result
    if re.fullmatch(r"-?\d+", val):
        return int(val)
    if re.fullmatch(r"-?\d+\.\d+", val):
        return float(val)
    return val


def _split_inline(text: str) -> List[str]:
    parts: List[str] = []
    buf: List[str] = []
    in_single = False
    in_double = False
    depth = 0
    for ch in text:
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            if ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
            elif ch == "," and depth == 0:
                parts.append("".join(buf).strip())
                buf = []
                continue
        buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())
    return parts


def _split_key_value(content: str) -> Tuple[str, str]:
    in_single = False
    in_double = False
    for idx, ch in enumerate(content):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == ":" and not in_single and not in_double:
            if idx + 1 == len(content) or content[idx + 1].isspace():
                return content[:idx].strip(), content[idx + 1 :].strip()
    raise YamlParseError(f"Expected key: value in {content!r}")


def parse_yaml(text: str) -> Any:
    """Parse a YAML string into Python dicts, lists, and scalars."""
    raw_lines = text.splitlines()
    lines: List[Tuple[int, int, str]] = []
    for lineno, raw in enumerate(raw_lines, start=1):
        if raw.strip() in ("---", "..."):
            continue
        cleaned = _strip_comment(raw)
        if not cleaned.strip():
            continue
        indent = len(cleaned) - len(cleaned.lstrip(" "))
        lines.append((lineno, indent, cleaned.strip()))

    if not lines:
        return {}

    val, _ = _parse_node(lines, 0, lines[0][1])
    return val


def _parse_block_scalar(
    lines: List[Tuple[int, int, str]], idx: int, parent_indent: int, folded: bool
) -> Tuple[str, int]:
    collected: List[str] = []
    block_indent = None
    while idx < len(lines):
        _, indent, content = lines[idx]
        if indent <= parent_indent:
            break
        if block_indent is None:
            block_indent = indent
        collected.append(content)
        idx += 1
    joiner = " " if folded else "\n"
    return joiner.join(collected), idx


def _parse_node(
    lines: List[Tuple[int, int, str]], idx: int, base_indent: int
) -> Tuple[Any, int]:
    _, indent, content = lines[idx]
    if content.startswith("- ") or content == "-":
        return _parse_sequence(lines, idx, indent)
    return _parse_mapping(lines, idx, indent)


def _parse_sequence(
    lines: List[Tuple[int, int, str]], idx: int, seq_indent: int
) -> Tuple[List[Any], int]:
    items: List[Any] = []
    while idx < len(lines):
        _, indent, content = lines[idx]
        if indent < seq_indent:
            break
        if indent > seq_indent:
            break
        if not (content.startswith("- ") or content == "-"):
            break

        rest = content[1:].strip() if len(content) > 1 else ""
        idx += 1

        if not rest:
            if idx < len(lines) and lines[idx][1] > seq_indent:
                child, idx = _parse_node(lines, idx, lines[idx][1])
                items.append(child)
            else:
                items.append(None)
            continue

        # Check if "- key: value"
        try:
            key, val_str = _split_key_value(rest)
        except YamlParseError:
            items.append(_parse_scalar(rest))
            continue

        item_dict: dict[str, Any] = {}
        key_parsed = str(_parse_scalar(key))
        item_indent = seq_indent + 2

        if val_str in ("|", "|-", ">", ">-"):
            folded = val_str.startswith(">")
            block_val, idx = _parse_block_scalar(lines, idx, seq_indent, folded)
            item_dict[key_parsed] = block_val
        elif val_str == "":
            if idx < len(lines) and lines[idx][1] > seq_indent:
                child, idx = _parse_node(lines, idx, lines[idx][1])
                item_dict[key_parsed] = child
            else:
                item_dict[key_parsed] = None
        else:
            item_dict[key_parsed] = _parse_scalar(val_str)

        # Parse remaining keys of this dict item at indent > seq_indent
        if idx < len(lines) and lines[idx][1] > seq_indent and not (
            lines[idx][2].startswith("- ") or lines[idx][2] == "-"
        ):
            more_dict, idx = _parse_mapping(lines, idx, lines[idx][1])
            item_dict.update(more_dict)

        items.append(item_dict)

    return items, idx


def _parse_mapping(
    lines: List[Tuple[int, int, str]], idx: int, map_indent: int
) -> Tuple[dict[str, Any], int]:
    mapping: dict[str, Any] = {}
    while idx < len(lines):
        _, indent, content = lines[idx]
        if indent < map_indent:
            break
        if indent > map_indent:
            break
        if content.startswith("- ") or content == "-":
            break

        key, val_str = _split_key_value(content)
        key_parsed = str(_parse_scalar(key))
        idx += 1

        if val_str in ("|", "|-", ">", ">-"):
            folded = val_str.startswith(">")
            block_val, idx = _parse_block_scalar(lines, idx, indent, folded)
            mapping[key_parsed] = block_val
        elif val_str == "":
            if idx < len(lines) and lines[idx][1] > indent:
                child, idx = _parse_node(lines, idx, lines[idx][1])
                mapping[key_parsed] = child
            else:
                mapping[key_parsed] = None
        else:
            mapping[key_parsed] = _parse_scalar(val_str)

    return mapping, idx
