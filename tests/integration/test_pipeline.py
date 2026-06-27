"""
tests/integration/test_pipeline.py
------------------------------------
End-to-end integration tests.

These tests require:
  • Ollama running locally  (ollama serve)
  • codellama:7b pulled     (ollama pull codellama:7b)
  • ChromaDB populated      (python scripts/setup_db.py)

Run with:
  pytest tests/integration/ -m integration -v

They are deliberately excluded from the default test run (no marker in pytest.ini_options).
"""

from __future__ import annotations

import os
import pytest

# Skip all tests in this module if Ollama isn't reachable
pytestmark = pytest.mark.integration


def _ollama_available() -> bool:
    try:
        from vuln_scanner.llm.ollama_client import OllamaClient
        return OllamaClient().health_check()
    except Exception:
        return False


@pytest.fixture(autouse=True)
def require_ollama():
    if not _ollama_available():
        pytest.skip("Ollama server not reachable — skipping integration test.")
    # Unset SKIP_LLM for integration tests
    original = os.environ.pop("SKIP_LLM", None)
    yield
    if original is not None:
        os.environ["SKIP_LLM"] = original


@pytest.fixture
def live_scanner():
    from vuln_scanner.core.scanner import VulnerabilityScanner
    return VulnerabilityScanner()


class TestFullPipeline:

    def test_sql_injection_detected_end_to_end(self, live_scanner, sql_injection_code):
        result = live_scanner.scan(sql_injection_code, language="python", filename="test_sqli.py")
        vuln_types = {v.type.lower() for v in result.vulnerabilities}
        # LLM should flag SQL injection in this obviously vulnerable code
        assert any("sql" in t for t in vuln_types), (
            f"Expected SQL Injection but got: {vuln_types}"
        )

    def test_deserialization_detected_end_to_end(self, live_scanner, insecure_deser_code):
        result = live_scanner.scan(insecure_deser_code, language="python", filename="test_deser.py")
        vuln_types = {v.type.lower() for v in result.vulnerabilities}
        assert any("deserializ" in t or "pickle" in t for t in vuln_types), (
            f"Expected deserialization vuln but got: {vuln_types}"
        )

    def test_safe_code_has_low_critical_count(self, live_scanner, safe_code):
        result = live_scanner.scan(safe_code, language="python", filename="safe.py")
        # Safe code should have no CRITICAL vulnerabilities
        assert result.critical_count == 0, (
            f"False positive CRITICAL findings in safe code: "
            f"{[v.type for v in result.vulnerabilities if v.severity.value == 'CRITICAL']}"
        )

    def test_scan_result_has_model_name(self, live_scanner, sql_injection_code):
        result = live_scanner.scan(sql_injection_code, language="python")
        assert result.model_used != ""
        assert "codellama" in result.model_used.lower() or len(result.model_used) > 3

    def test_overall_risk_reflects_findings(self, live_scanner, insecure_deser_code):
        from vuln_scanner.models import Severity
        result = live_scanner.scan(insecure_deser_code, language="python")
        # Code has multiple HIGH/CRITICAL patterns — overall_risk should not be INFO
        assert result.overall_risk != Severity.INFO
