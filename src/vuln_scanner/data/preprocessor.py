"""
data/preprocessor.py
---------------------
Utilities for preparing source code before analysis:
  1. Language detection from filename extension or code content.
  2. Code chunking for large files (LLMs have context-window limits).
  3. Function/block extraction to give the LLM focused context.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import List, Optional

from loguru import logger

from ..models import Language


# ─────────────────────────────────────────────────────────────────────────────
# Language detection
# ─────────────────────────────────────────────────────────────────────────────

_EXT_MAP = {
    ".py":   Language.PYTHON,
    ".pyw":  Language.PYTHON,
    ".c":    Language.C,
    ".h":    Language.C,
    ".cpp":  Language.CPP,
    ".cxx":  Language.CPP,
    ".cc":   Language.CPP,
    ".hpp":  Language.CPP,
    ".java": Language.JAVA,
    ".js":   Language.JAVASCRIPT,
    ".mjs":  Language.JAVASCRIPT,
    ".ts":   Language.JAVASCRIPT,   # treat TypeScript like JS
    ".php":  Language.PHP,
    ".php3": Language.PHP,
    ".php4": Language.PHP,
    ".php5": Language.PHP,
}

_SHEBANG_MAP = {
    "python": Language.PYTHON,
    "php":    Language.PHP,
    "node":   Language.JAVASCRIPT,
}

# Heuristic patterns to detect language from code content
_CONTENT_PATTERNS = [
    (Language.PYTHON,     re.compile(r"^(import |from .+ import |def |class |\s*#!.*python)", re.MULTILINE)),
    (Language.PHP,        re.compile(r"<\?php|<\?=",              re.IGNORECASE)),
    (Language.JAVA,       re.compile(r"\bpublic\s+class\b|\bimport\s+java\.")),
    (Language.CPP,        re.compile(r"#include\s*<(iostream|vector|string|memory|cstdio)>")),
    (Language.C,          re.compile(r"#include\s*<(stdio\.h|stdlib\.h|string\.h|unistd\.h)>")),
    (Language.JAVASCRIPT, re.compile(r"\bconst\s+\w+\s*=\s*require\(|function\s+\w+\s*\(|\barrow\s*=>")),
]


def detect_language(code: str, filename: str = "") -> str:
    """
    Detect the programming language of *code*.

    Priority: filename extension → shebang → content heuristics → 'unknown'.

    Returns
    -------
    str : lowercase language tag (e.g. 'python', 'c').
    """
    # 1. Filename extension
    if filename:
        ext = Path(filename).suffix.lower()
        if ext in _EXT_MAP:
            return _EXT_MAP[ext].value

    # 2. Shebang (#! /usr/bin/env python3)
    first_line = code.split("\n", 1)[0].strip()
    if first_line.startswith("#!"):
        for keyword, lang in _SHEBANG_MAP.items():
            if keyword in first_line.lower():
                return lang.value

    # 3. Content heuristics
    for lang, pattern in _CONTENT_PATTERNS:
        if pattern.search(code):
            return lang.value

    return Language.UNKNOWN.value


# ─────────────────────────────────────────────────────────────────────────────
# Chunking
# ─────────────────────────────────────────────────────────────────────────────

def chunk_code(
    code: str,
    max_chars: int = 2000,
    overlap: int = 200,
) -> List[str]:
    """
    Split *code* into chunks of at most *max_chars* characters.

    Tries to split on blank lines first (preserves logical blocks);
    falls back to hard character splits with *overlap*.

    Parameters
    ----------
    code      : Source code string.
    max_chars : Maximum characters per chunk.
    overlap   : Characters of overlap between consecutive chunks
                (so vulnerabilities spanning a boundary aren't missed).

    Returns
    -------
    List[str] : One or more code chunks.
    """
    if len(code) <= max_chars:
        return [code]

    chunks: List[str] = []
    lines  = code.splitlines(keepends=True)

    current: List[str] = []
    current_len = 0

    for line in lines:
        if current_len + len(line) > max_chars and current:
            chunks.append("".join(current))
            # overlap: keep last few lines
            overlap_lines: List[str] = []
            kept = 0
            for l in reversed(current):
                if kept + len(l) > overlap:
                    break
                overlap_lines.insert(0, l)
                kept += len(l)
            current     = overlap_lines
            current_len = sum(len(l) for l in current)

        current.append(line)
        current_len += len(line)

    if current:
        chunks.append("".join(current))

    logger.debug(f"Chunked {len(code)} chars into {len(chunks)} chunks (max={max_chars})")
    return chunks


# ─────────────────────────────────────────────────────────────────────────────
# Function extraction (Python only)
# ─────────────────────────────────────────────────────────────────────────────

def extract_python_functions(code: str) -> List[str]:
    """
    Extract individual function/method bodies from Python source.
    Returns a list of source snippets, one per function.
    Falls back to returning the whole code on parse errors.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return [code]

    lines  = code.splitlines()
    result: List[str] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno - 1
            end   = node.end_lineno or (start + 1)
            snippet = "\n".join(lines[start:end])
            result.append(snippet)

    return result if result else [code]


# ─────────────────────────────────────────────────────────────────────────────
# C/C++ function extraction (regex-based)
# ─────────────────────────────────────────────────────────────────────────────

_C_FUNC_PATTERN = re.compile(
    r"(?:^|\n)"                     # start of line
    r"(?:[\w\*\s]+?)\s+"           # return type
    r"(\w+)\s*\([^)]*\)\s*\{"     # function name + params + opening brace
    , re.MULTILINE
)


def extract_c_functions(code: str) -> List[str]:
    """
    Rough C/C++ function body extractor using brace counting.
    Finds the '{' for each function signature and collects
    lines until the matching '}'.
    """
    functions: List[str] = []
    lines = code.splitlines()

    for match in _C_FUNC_PATTERN.finditer(code):
        start_char = match.start()
        # Find the line number of the match
        start_line = code[:start_char].count("\n")
        depth  = 0
        body   = []
        in_body = False

        for i, line in enumerate(lines[start_line:], start=start_line):
            body.append(line)
            for ch in line:
                if ch == "{":
                    depth += 1
                    in_body = True
                elif ch == "}":
                    depth -= 1
            if in_body and depth == 0:
                functions.append("\n".join(body))
                break

    return functions if functions else [code]


# ─────────────────────────────────────────────────────────────────────────────
# Public CodePreprocessor wrapper
# ─────────────────────────────────────────────────────────────────────────────

class CodePreprocessor:
    """
    Facade providing all preprocessing operations.

    Usage::

        pp = CodePreprocessor()
        lang = pp.detect_language(code, "app.py")
        chunks = pp.chunk(code, max_chars=2000)
        functions = pp.extract_functions(code, lang)
    """

    @staticmethod
    def detect_language(code: str, filename: str = "") -> str:
        return detect_language(code, filename)

    @staticmethod
    def chunk(code: str, max_chars: int = 2000, overlap: int = 200) -> List[str]:
        return chunk_code(code, max_chars=max_chars, overlap=overlap)

    @staticmethod
    def extract_functions(code: str, language: str) -> List[str]:
        lang = language.lower()
        if lang == "python":
            return extract_python_functions(code)
        if lang in ("c", "cpp"):
            return extract_c_functions(code)
        # For other languages: return the whole code as one block
        return [code]

    @staticmethod
    def line_count(code: str) -> int:
        return len(code.splitlines())
