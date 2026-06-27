"""
core/analyzer.py
-----------------
Orchestrates the LLM-based vulnerability analysis step.

Given a code snippet + retrieved CVE/CWE context + static hints,
this module:
  1. Builds the analysis prompt.
  2. Calls Ollama via OllamaClient.
  3. Parses the JSON response into Vulnerability objects.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from loguru import logger

from ..config import settings
from ..llm.ollama_client import OllamaClient, OllamaError
from ..llm.prompt_templates import SYSTEM_PROMPT, build_analysis_prompt
from ..llm.response_parser import parse_vulnerabilities
from ..models import CVEEntry, CWEEntry, PatternMatch, Severity, StaticFinding, Vulnerability


class CodeAnalyzer:
    """
    Performs LLM-based vulnerability analysis.

    Usage::

        analyzer = CodeAnalyzer()
        vulns, summary, risk = analyzer.analyze(
            code=source_code,
            language="python",
            filename="app.py",
            cve_context=cve_list,
            cwe_context=cwe_list,
            static_findings=bandit_findings,
            pattern_matches=pattern_hits,
        )
    """

    def __init__(self, client: Optional[OllamaClient] = None) -> None:
        self._client = client or OllamaClient()

    def analyze(
        self,
        code: str,
        language: str,
        filename: str = "source",
        cve_context: Optional[List[CVEEntry]] = None,
        cwe_context: Optional[List[CWEEntry]] = None,
        static_findings: Optional[List[StaticFinding]] = None,
        pattern_matches: Optional[List[PatternMatch]] = None,
    ) -> Tuple[List[Vulnerability], str, Severity]:
        """
        Run the LLM analysis.

        Returns
        -------
        (vulnerabilities, summary_text, overall_risk_severity)
        """
        if settings.SKIP_LLM:
            logger.info("SKIP_LLM=true — skipping LLM analysis.")
            return [], "LLM analysis skipped (SKIP_LLM=true).", Severity.INFO

        # ── Pre-flight check ──────────────────────────────────────────────────
        if not self._client.health_check():
            logger.error(
                "Ollama is not reachable at %s. "
                "Start it with: ollama serve",
                settings.OLLAMA_BASE_URL,
            )
            return (
                [],
                "LLM analysis skipped — Ollama server not reachable.",
                Severity.INFO,
            )

        if not self._client.model_is_available():
            logger.error(
                "Model '%s' is not pulled locally. "
                "Run: ollama pull %s",
                settings.OLLAMA_MODEL,
                settings.OLLAMA_MODEL,
            )
            return (
                [],
                f"LLM analysis skipped — model '{settings.OLLAMA_MODEL}' not found.",
                Severity.INFO,
            )

        # ── Build prompt ──────────────────────────────────────────────────────
        prompt = build_analysis_prompt(
            code=code,
            language=language,
            filename=filename,
            cve_context=cve_context or [],
            cwe_context=cwe_context or [],
            static_findings=static_findings or [],
            pattern_matches=pattern_matches or [],
        )

        logger.info(
            f"Sending {len(code)} chars of {language} code to "
            f"Ollama ({settings.OLLAMA_MODEL}) …"
        )

        # ── LLM call ──────────────────────────────────────────────────────────
        try:
            raw_response = self._client.generate(
                prompt=prompt,
                system=SYSTEM_PROMPT,
                temperature=0.05,   # deterministic output for security analysis
            )
        except OllamaError as exc:
            logger.error(f"LLM call failed: {exc}")
            return [], f"LLM call failed: {exc}", Severity.INFO

        if not raw_response.strip():
            logger.warning("LLM returned an empty response.")
            return [], "LLM returned no content.", Severity.INFO

        logger.debug(f"LLM raw response ({len(raw_response)} chars):\n{raw_response[:400]}…")

        # ── Parse response ────────────────────────────────────────────────────
        vulns, summary, overall_risk = parse_vulnerabilities(raw_response)

        # Filter by confidence threshold
        before = len(vulns)
        vulns  = [v for v in vulns if v.confidence >= settings.CONFIDENCE_THRESHOLD]
        if before != len(vulns):
            logger.info(
                f"Confidence filter ({settings.CONFIDENCE_THRESHOLD:.0%}): "
                f"{before} → {len(vulns)} vulnerabilities"
            )

        logger.info(
            f"LLM analysis complete: {len(vulns)} vulnerabilities "
            f"(overall_risk={overall_risk.value})"
        )
        return vulns, summary, overall_risk

    def get_fix(self, vulnerability_type: str, language: str, code_snippet: str) -> str:
        """
        Ask the LLM for a corrected version of a specific vulnerable snippet.
        Used by the 'Show Fix' button in the Streamlit UI.
        """
        from ..llm.prompt_templates import build_remediation_prompt

        if not self._client.health_check():
            return "// Ollama not reachable — cannot generate fix."

        prompt = build_remediation_prompt(vulnerability_type, language, code_snippet)
        try:
            return self._client.generate(prompt, temperature=0.1)
        except OllamaError as exc:
            return f"// Fix generation failed: {exc}"
