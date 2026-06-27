"""
core/scanner.py
---------------
VulnerabilityScanner — the single public entry point for the pipeline.

Pipeline order:
  1. Preprocess  : detect language, split into chunks
  2. Static      : Bandit (Python) + AST analysis
  3. Patterns    : Regex-based pattern matching
  4. RAG         : Retrieve similar CVEs/CWEs from ChromaDB
  5. LLM         : Analyse code with Ollama + retrieved context
  6. Deduplicate : Merge LLM + pattern findings, remove duplicates
  7. Return      : ScanResult with all findings

Every stage is fail-safe — an exception in one stage does not abort the
remaining stages.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import List, Optional

from loguru import logger

from ..config import settings
from ..data.preprocessor import CodePreprocessor
from ..models import (
    PatternMatch, ScanResult, Severity, StaticFinding, Vulnerability,
)
from ..rag.retriever import CVERetriever
from ..static_analysis.ast_parser import ASTParser
from ..static_analysis.bandit_wrapper import BanditAnalyzer
from ..static_analysis.pattern_matcher import PatternMatcher
from .analyzer import CodeAnalyzer


class VulnerabilityScanner:
    """
    Full pipeline for vulnerability scanning.

    Usage::

        scanner = VulnerabilityScanner()
        result  = scanner.scan(code, language="python", filename="app.py")
        print(result.total_vulnerabilities)
    """

    def __init__(self) -> None:
        self._preprocessor = CodePreprocessor()
        self._pattern      = PatternMatcher()
        self._bandit       = BanditAnalyzer()
        self._ast          = ASTParser()
        self._retriever    = CVERetriever()
        self._analyzer     = CodeAnalyzer()
        logger.info("VulnerabilityScanner initialised.")

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(
        self,
        code: str,
        language: str = "auto",
        filename: str = "source_code",
    ) -> ScanResult:
        """
        Run the full vulnerability scan on *code*.

        Parameters
        ----------
        code     : Source code to scan.
        language : Language tag (e.g. 'python'). Use 'auto' to detect.
        filename : Original filename (used for language detection & reporting).

        Returns
        -------
        ScanResult : Typed result object containing all findings.
        """
        t_start = time.perf_counter()
        logger.info(f"=== Scan started: {filename} ({len(code)} chars) ===")

        # ── 0. Sanitise input ─────────────────────────────────────────────────
        code = code.strip()
        if not code:
            return self._empty_result(filename, "unknown", "Input code is empty.")

        # ── 1. Language detection ─────────────────────────────────────────────
        if language in ("auto", "", Language_UNKNOWN := "unknown"):
            language = self._preprocessor.detect_language(code, filename)
            logger.info(f"Auto-detected language: {language}")

        code_hash = hashlib.sha256(code.encode()).hexdigest()

        # ── 2. Static analysis (Bandit + AST) ────────────────────────────────
        static_findings: List[StaticFinding] = []
        try:
            if language == "python":
                static_findings = self._bandit.analyze(code)
                ast_result = self._ast.parse(code)
                logger.debug(f"AST summary: {ast_result.summary()}")
        except Exception as exc:
            logger.error(f"Static analysis error (non-fatal): {exc}")

        # ── 3. Pattern matching ───────────────────────────────────────────────
        pattern_matches: List[PatternMatch] = []
        try:
            pattern_matches = self._pattern.match(code, language)
        except Exception as exc:
            logger.error(f"Pattern matching error (non-fatal): {exc}")

        # ── 4. Code chunking for large files ─────────────────────────────────
        chunks = self._preprocessor.chunk(code, max_chars=settings.MAX_CODE_CHUNK_SIZE)
        logger.info(f"Code split into {len(chunks)} chunk(s) for LLM analysis.")

        # ── 5. RAG + LLM (one call per chunk, merged) ─────────────────────────
        all_vulnerabilities: List[Vulnerability] = []
        overall_summary = ""
        overall_risk    = Severity.INFO

        for i, chunk in enumerate(chunks):
            logger.info(f"Processing chunk {i + 1}/{len(chunks)} …")

            # RAG retrieval
            cve_ctx, cwe_ctx = [], []
            try:
                if self._retriever.is_ready:
                    cve_ctx, cwe_ctx = self._retriever.retrieve(
                        chunk, language=language
                    )
                else:
                    logger.warning(
                        "Knowledge base is empty — RAG context skipped. "
                        "Run python scripts/setup_db.py first."
                    )
            except Exception as exc:
                logger.error(f"RAG retrieval error (non-fatal): {exc}")

            # LLM analysis
            try:
                chunk_num = f"{filename} [chunk {i + 1}/{len(chunks)}]"
                vulns, summary, risk = self._analyzer.analyze(
                    code=chunk,
                    language=language,
                    filename=chunk_num,
                    cve_context=cve_ctx,
                    cwe_context=cwe_ctx,
                    static_findings=static_findings if i == 0 else [],
                    pattern_matches=pattern_matches if i == 0 else [],
                )
                all_vulnerabilities.extend(vulns)
                if i == 0:
                    overall_summary = summary
                # Upgrade overall risk if this chunk is worse
                if _sev_rank(risk) > _sev_rank(overall_risk):
                    overall_risk = risk
            except Exception as exc:
                logger.error(f"LLM analysis error on chunk {i + 1} (non-fatal): {exc}")

        # ── 6. Merge pattern-matcher findings as Vulnerability objects ─────────
        pattern_vulns = _pattern_to_vulns(pattern_matches)
        merged_vulns  = _deduplicate_vulns(all_vulnerabilities + pattern_vulns)

        # ── 7. Build result ───────────────────────────────────────────────────
        elapsed = time.perf_counter() - t_start
        result  = ScanResult(
            filename=filename,
            language=language,
            code_hash=code_hash,
            code=code,
            vulnerabilities=merged_vulns,
            static_findings=static_findings,
            pattern_matches=pattern_matches,
            scan_time=elapsed,
            model_used=settings.OLLAMA_MODEL,
        )

        logger.info(
            f"=== Scan complete in {elapsed:.1f}s: "
            f"{result.total_vulnerabilities} vulnerabilities "
            f"(overall_risk={result.overall_risk.value}) ==="
        )
        return result

    def scan_file(self, path: str | Path) -> ScanResult:
        """Convenience method to scan a file on disk."""
        p = Path(path)
        try:
            code = p.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            return self._empty_result(str(p), "unknown", f"Could not read file: {exc}")
        return self.scan(code, filename=p.name)

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _empty_result(filename: str, language: str, error: str) -> ScanResult:
        return ScanResult(
            filename=filename,
            language=language,
            code_hash="",
            code="",
            scan_time=0.0,
            model_used=settings.OLLAMA_MODEL,
            error=error,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Module-level helpers (no class needed)
# ─────────────────────────────────────────────────────────────────────────────

_SEV_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH:     3,
    Severity.MEDIUM:   2,
    Severity.LOW:      1,
    Severity.INFO:     0,
    Severity.UNKNOWN:  0,
}


def _sev_rank(s: Severity) -> int:
    return _SEV_ORDER.get(s, 0)


def _pattern_to_vulns(matches: List[PatternMatch]) -> List[Vulnerability]:
    """Convert PatternMatch hits into Vulnerability objects (source='pattern')."""
    result: List[Vulnerability] = []
    for m in matches:
        result.append(Vulnerability(
            type=m.vulnerability_type,
            cwe_id=m.cwe_id,
            severity=m.severity,
            line_numbers=m.line_numbers,
            description=m.description,
            code_snippet=m.code_snippet,
            remediation=_pattern_remediation(m.cwe_id),
            confidence=m.confidence,
            source="pattern",
        ))
    return result


def _pattern_remediation(cwe_id: str) -> str:
    _REMED = {
        "CWE-89":  "Use parameterised queries / prepared statements.",
        "CWE-78":  "Avoid shell=True; use subprocess with a list of args.",
        "CWE-120": "Replace with bounds-checked alternatives (snprintf, strlcpy).",
        "CWE-22":  "Canonicalise and whitelist paths; use os.path.abspath + startswith.",
        "CWE-79":  "Escape output with html.escape() or a templating engine.",
        "CWE-502": "Use json/safe_load instead of pickle/yaml.load.",
        "CWE-798": "Move secrets to environment variables or a vault.",
        "CWE-190": "Use checked arithmetic or a big-integer library.",
        "CWE-416": "Set pointer to NULL immediately after free().",
        "CWE-362": "Protect shared state with threading.Lock or a mutex.",
        "CWE-611": "Disable external entity processing in your XML parser.",
    }
    return _REMED.get(cwe_id, "Review the code and apply the principle of least privilege.")


def _deduplicate_vulns(vulns: List[Vulnerability]) -> List[Vulnerability]:
    """
    Remove near-duplicate findings: if an LLM finding and a pattern finding
    share the same CWE and at least one line number, keep the LLM one
    (it has richer detail).
    """
    seen: dict = {}  # (cwe_id, first_line) → Vulnerability
    for v in vulns:
        key = (v.cwe_id or v.type, v.line_numbers[0] if v.line_numbers else -1)
        existing = seen.get(key)
        if existing is None:
            seen[key] = v
        elif v.source == "llm" and existing.source == "pattern":
            seen[key] = v  # prefer richer LLM finding

    return sorted(
        seen.values(),
        key=lambda v: (_sev_rank(v.severity) * -1, v.line_numbers[0] if v.line_numbers else 0),
    )
