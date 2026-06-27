"""
tests/conftest.py
------------------
Shared pytest fixtures available to all test files.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# ── Point the scanner at test-specific dirs so tests don't touch real data ─────
os.environ.setdefault("CHROMA_PERSIST_DIR", "/tmp/vuln_scanner_test_chroma")
os.environ.setdefault("REPORT_OUTPUT_DIR",  "/tmp/vuln_scanner_test_reports")
os.environ.setdefault("LOG_FILE",           "/tmp/vuln_scanner_test.log")
os.environ.setdefault("SKIP_LLM",           "true")   # unit tests never call Ollama


FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ─────────────────────────────────────────────────────────────────────────────
# Code fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def sql_injection_code() -> str:
    return (FIXTURES_DIR / "vulnerable_code" / "sql_injection.py").read_text()


@pytest.fixture
def insecure_deser_code() -> str:
    return (FIXTURES_DIR / "vulnerable_code" / "insecure_deser.py").read_text()


@pytest.fixture
def safe_code() -> str:
    return (FIXTURES_DIR / "safe_code" / "safe_query.py").read_text()


@pytest.fixture
def buffer_overflow_c_code() -> str:
    return (FIXTURES_DIR / "vulnerable_code" / "buffer_overflow.c").read_text()


# ─────────────────────────────────────────────────────────────────────────────
# Component fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def pattern_matcher():
    from vuln_scanner.static_analysis.pattern_matcher import PatternMatcher
    return PatternMatcher()


@pytest.fixture
def bandit_analyzer():
    from vuln_scanner.static_analysis.bandit_wrapper import BanditAnalyzer
    return BanditAnalyzer()


@pytest.fixture
def ast_parser():
    from vuln_scanner.static_analysis.ast_parser import ASTParser
    return ASTParser()


@pytest.fixture
def preprocessor():
    from vuln_scanner.data.preprocessor import CodePreprocessor
    return CodePreprocessor()


@pytest.fixture
def scanner():
    """Returns a scanner with SKIP_LLM=true so tests run offline."""
    from vuln_scanner.core.scanner import VulnerabilityScanner
    return VulnerabilityScanner()
