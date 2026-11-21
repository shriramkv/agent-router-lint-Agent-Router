"""Zero-dependency loader for the block-YAML subset used by Kubernetes manifests.

Supports: multi-document streams (``---``), nested mappings and sequences
(including the compact ``key:\\n- item`` style), ``- key: value`` sequence
items, quoted and plain scalars, ints/floats/bools/null, simple flow
collections (``[a, b]`` / ``{a: 1}``), literal (``|``) and folded (``>``)
block scalars, and comments.

If PyYAML is installed, :func:`load_all` uses it instead (``safe_load_all``)
unless ``force_builtin=True``. Both paths are covered by the test suite.
"""
from __future__ import annotations

import re
from typing import Any, List, Tuple

__all__ = ["load_all", "YamlError"]


class YamlError(ValueError):
    pass


_INT = re.compile(r"^[-+]?\d+$")
_FLOAT = re.compile(r"^[-+]?(\d+\.\d*|\.\d+|\d+)([eE][-+]?\d+)?$")


def _strip_comment(line: str) -> str:
    out, quote = [], None
    for i, ch in enumerate(line):
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


def _split_flow(body: str) -> List[str]:
    parts, depth, cur, quote = [], 0, [], None
    for ch in body:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return parts


def _scalar(text: str) -> Any:
    t = text.strip()
    if t == "":
        return None
    if t[0] == '"' and t.endswith('"') and len(t) >= 2:
        return bytes(t[1:-1], "utf-8").decode("unicode_escape")
    if t[0] == "'" and t.endswith("'") and len(t) >= 2:
        return t[1:-1].replace("''", "'")
    if t.startswith("[") and t.endswith("]"):
        return [_scalar(p) for p in _split_flow(t[1:-1])]
    if t.startswith("{") and t.endswith("}"):
        d = {}
        for p in _split_flow(t[1:-1]):
            k, _, v = p.partition(":")
            d[_scalar(k)] = _scalar(v)
        return d
    low = t.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~"):
        return None
    if _INT.match(t):
        return int(t)
    if _FLOAT.match(t):
        return float(t)
    return t


def _split_key(text: str) -> Tuple[str, str] | None:
    """Split ``key: value`` respecting quotes. Returns None if not a mapping line."""
    quote = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch == ":" and (i + 1 == len(text) or text[i + 1] in " \t"):
            key = text[:i].strip()
            if key.startswith(("[", "{")):
                return None
            return _scalar(key) if key[:1] in "'\"" else key, text[i + 1:].strip()
    return None


class _Parser:
    def __init__(self, lines: List[Tuple[int, str, int]], raw: List[str]):
        self.lines = lines  # (indent, content, raw_index)
        self.raw = raw
        self.i = 0

    def peek(self):
        return self.lines[self.i] if self.i < len(self.lines) else None

    def parse_block(self, indent: int) -> Any:
        ln = self.peek()
        if ln is None or ln[0] < indent:
            return None
        if ln[1].startswith("- ") or ln[1] == "-":
            return self.parse_seq(ln[0])
        return self.parse_map(ln[0])

    def _value_after(self, rest: str, parent_indent: int, raw_idx: int) -> Any:
        if rest in ("|", "|-", "|+", ">", ">-", ">+"):
            return self.block_scalar(rest, parent_indent, raw_idx)
        if rest:
            return _scalar(rest)
        nxt = self.peek()
        if nxt is None:
            return None
        if nxt[0] > parent_indent and nxt[1][:1] in "[{":
            # multi-line flow collection: join until brackets balance
            buf, depth = [], 0
            while self.i < len(self.lines):
                piece = self.lines[self.i][1]
                self.i += 1
                buf.append(piece)
                depth += sum(piece.count(c) for c in "[{") - sum(piece.count(c) for c in "]}")
                if depth <= 0:
                    break
            return _scalar(" ".join(buf))
        if nxt[0] > parent_indent:
            return self.parse_block(nxt[0])
        # compact sequence: "key:\n- item" at same indent
        if nxt[0] == parent_indent and (nxt[1].startswith("- ") or nxt[1] == "-"):
            return self.parse_seq(parent_indent)
        return None

    def block_scalar(self, style: str, parent_indent: int, raw_idx: int) -> str:
        # consume raw lines until dedent to <= parent_indent
        collected = []
        j = raw_idx + 1
        block_indent = None
        while j < len(self.raw):
            line = self.raw[j]
            if line.strip() == "":
                collected.append("")
                j += 1
                continue
            ind = len(line) - len(line.lstrip(" "))
            if ind <= parent_indent:
                break
            if block_indent is None:
                block_indent = ind
            collected.append(line[block_indent:])
            j += 1
        # skip parsed lines covered by the block
        while self.i < len(self.lines) and self.lines[self.i][2] < j:
            self.i += 1
        while collected and collected[-1] == "":
            collected.pop()
        if style.startswith(">"):
            text = " ".join(c for c in collected if c)
        else:
            text = "\n".join(collected)
        if not style.endswith("-"):
            text += "\n"
        return text

    def parse_map(self, indent: int) -> dict:
        out: dict = {}
        while True:
            ln = self.peek()
            if ln is None or ln[0] < indent:
                return out
            if ln[0] > indent:
                raise YamlError(f"line {ln[2] + 1}: unexpected indentation")
            if ln[1].startswith("- ") or ln[1] == "-":
                return out
            kv = _split_key(ln[1])
            if kv is None:
                raise YamlError(f"line {ln[2] + 1}: expected 'key: value', got {ln[1]!r}")
            self.i += 1
            out[kv[0]] = self._value_after(kv[1], indent, ln[2])

    def parse_seq(self, indent: int) -> list:
        out: list = []
        while True:
            ln = self.peek()
            if ln is None or ln[0] != indent or not (ln[1].startswith("- ") or ln[1] == "-"):
                return out
            body = ln[1][1:].lstrip(" ")
            item_indent = indent + (len(ln[1]) - len(body))
            self.i += 1
            if body == "":
                out.append(self.parse_block(indent + 1))
                continue
            if body.startswith("- "):
                # nested inline sequence "- - a"
                self.lines.insert(self.i, (item_indent, body, ln[2]))
                out.append(self.parse_seq(item_indent))
                continue
            kv = _split_key(body)
            if kv is None or body.startswith(("'", '"', "[", "{")) and kv is None:
                out.append(_scalar(body))
                continue
            # mapping item: first key inline, siblings at item_indent
            self.lines.insert(self.i, (item_indent, body, ln[2]))
            out.append(self.parse_map(item_indent))


def _builtin_load_all(text: str) -> List[Any]:
    docs: List[List[str]] = [[]]
    for line in text.splitlines():
        if line.rstrip() == "---" or line.startswith("--- "):
            docs.append([])
            continue
        if line.rstrip() == "...":
            continue
        docs[-1].append(line.replace("\t", "    "))
    result = []
    for raw in docs:
        lines = []
        for idx, line in enumerate(raw):
            stripped = _strip_comment(line)
            if not stripped.strip():
                continue
            ind = len(stripped) - len(stripped.lstrip(" "))
            lines.append((ind, stripped.strip(), idx))
        if not lines:
            continue
        p = _Parser(lines, raw)
        result.append(p.parse_block(lines[0][0]))
        if p.i < len(p.lines):
            bad = p.lines[p.i]
            raise YamlError(f"line {bad[2] + 1}: could not parse {bad[1]!r}")
    return result


def load_all(text: str, force_builtin: bool = False) -> List[Any]:
    """Parse a (multi-document) YAML string into a list of Python objects."""
    if not force_builtin:
        try:
            import yaml  # type: ignore
        except ImportError:
            pass
        else:
            try:
                return [d for d in yaml.safe_load_all(text) if d is not None]
            except yaml.YAMLError as exc:  # pragma: no cover - passthrough
                raise YamlError(str(exc)) from exc
    return [d for d in _builtin_load_all(text) if d is not None]
