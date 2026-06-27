"""
static_analysis/ast_parser.py
------------------------------
Uses Python's built-in `ast` module to extract structural metadata
from Python source code.

Output is NOT a list of vulnerabilities — it is supplementary context
that helps the LLM prompt be more specific:
  • Names of all imported modules (spot dangerous imports instantly)
  • Names and line ranges of all functions/methods
  • Calls to known dangerous built-ins (eval, exec, __import__, compile)
  • Variable names that suggest secrets (password, token, key …)
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import List, Optional, Set

from loguru import logger


# ─────────────────────────────────────────────────────────────────────────────
# Result model (plain dataclass — not Pydantic, kept internal)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ASTResult:
    imports: List[str]                      = field(default_factory=list)
    dangerous_imports: List[str]            = field(default_factory=list)
    function_names: List[str]               = field(default_factory=list)
    dangerous_calls: List[str]              = field(default_factory=list)   # "eval()" at L12
    hardcoded_secret_vars: List[str]        = field(default_factory=list)   # "password = '…' at L5"
    parse_error: Optional[str]              = None

    def summary(self) -> str:
        parts = []
        if self.dangerous_imports:
            parts.append(f"Dangerous imports: {', '.join(self.dangerous_imports)}")
        if self.dangerous_calls:
            parts.append(f"Dangerous calls: {'; '.join(self.dangerous_calls[:8])}")
        if self.hardcoded_secret_vars:
            parts.append(f"Possible hardcoded secrets: {'; '.join(self.hardcoded_secret_vars[:5])}")
        return " | ".join(parts) if parts else "No structural red flags detected."


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_DANGEROUS_MODULES: Set[str] = {
    "pickle", "marshal", "shelve", "subprocess", "os", "sys",
    "ctypes", "importlib", "tempfile", "shutil",
    "xml.etree.ElementTree",  # XXE if not configured
    "yaml",                   # unsafe load
    "cryptography",           # not dangerous itself, but worth noting
}

_DANGEROUS_BUILTINS: Set[str] = {"eval", "exec", "compile", "__import__", "input"}

_SECRET_KEYWORDS: Set[str] = {
    "password", "passwd", "secret", "api_key", "apikey",
    "access_token", "auth_token", "private_key", "credentials",
    "aws_secret", "db_password",
}


# ─────────────────────────────────────────────────────────────────────────────
# Parser
# ─────────────────────────────────────────────────────────────────────────────

class ASTParser:
    """
    Lightweight Python AST analyser.

    Only works on Python code — the scanner skips this for other languages.
    All errors are caught so a bad file never crashes the pipeline.

    Usage::

        parser = ASTParser()
        result = parser.parse(python_source)
        print(result.summary())
    """

    def parse(self, code: str) -> ASTResult:
        result = ASTResult()
        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            result.parse_error = f"SyntaxError: {exc}"
            logger.debug(f"AST parse failed: {exc}")
            return result

        visitor = _ASTVisitor()
        visitor.visit(tree)

        result.imports              = visitor.imports
        result.dangerous_imports    = [
            m for m in visitor.imports if m.split(".")[0] in _DANGEROUS_MODULES
        ]
        result.function_names       = visitor.function_names
        result.dangerous_calls      = visitor.dangerous_calls
        result.hardcoded_secret_vars = visitor.hardcoded_secret_vars
        return result


class _ASTVisitor(ast.NodeVisitor):
    """Internal AST walker — collect everything interesting in one pass."""

    def __init__(self) -> None:
        self.imports:               List[str] = []
        self.function_names:        List[str] = []
        self.dangerous_calls:       List[str] = []
        self.hardcoded_secret_vars: List[str] = []

    # ── Import statements ─────────────────────────────────────────────────────

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            self.imports.append(f"{module}.{alias.name}")
        self.generic_visit(node)

    # ── Function definitions ──────────────────────────────────────────────────

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.function_names.append(f"{node.name}() L{node.lineno}")
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    # ── Call expressions ──────────────────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._get_call_name(node)
        if func_name and func_name.split(".")[-1] in _DANGEROUS_BUILTINS:
            self.dangerous_calls.append(f"{func_name}() L{node.lineno}")
        self.generic_visit(node)

    # ── Assignments that look like secrets ────────────────────────────────────

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            name = self._get_name(target)
            if name and any(kw in name.lower() for kw in _SECRET_KEYWORDS):
                # Only flag if the value is a non-empty string literal
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val_preview = node.value.value[:6] + "…" if len(node.value.value) > 6 else node.value.value
                    self.hardcoded_secret_vars.append(
                        f"{name}='[{val_preview}]' L{node.lineno}"
                    )
        self.generic_visit(node)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _get_call_name(node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            obj = node.func
            while isinstance(obj, ast.Attribute):
                parts.append(obj.attr)
                obj = obj.value  # type: ignore[assignment]
            if isinstance(obj, ast.Name):
                parts.append(obj.id)
            return ".".join(reversed(parts))
        return None

    @staticmethod
    def _get_name(node: ast.expr) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None
