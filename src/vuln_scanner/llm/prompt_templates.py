"""
llm/prompt_templates.py
-----------------------
All prompt strings are kept here — never hard-coded in business logic.

Keeping prompts separate makes them easy to iterate on without touching
the rest of the codebase, which is especially important for LLM projects
where prompt quality directly drives output quality.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import yaml

from ..models import CVEEntry, CWEEntry, PatternMatch, StaticFinding


# ── Load system prompt from configs/model_config.yaml ─────────────────────────
_CONFIG_PATH = Path(__file__).resolve().parents[3] / "configs" / "model_config.yaml"

def _load_system_prompt() -> str:
    try:
        with open(_CONFIG_PATH, "r") as f:
            cfg = yaml.safe_load(f)
        return cfg.get("system_prompt", _DEFAULT_SYSTEM_PROMPT)
    except Exception:
        return _DEFAULT_SYSTEM_PROMPT


_DEFAULT_SYSTEM_PROMPT = (
    "You are an expert cybersecurity engineer specialising in static code analysis "
    "and vulnerability research. You have deep knowledge of the OWASP Top 10, "
    "CWE/SANS Top 25, and the CVE database. You always cite exact line numbers, "
    "never hallucinate CVE IDs, and respond ONLY with the JSON format requested."
)


SYSTEM_PROMPT: str = _load_system_prompt()


# ─────────────────────────────────────────────────────────────────────────────
# Main analysis prompt
# ─────────────────────────────────────────────────────────────────────────────

def build_analysis_prompt(
    code: str,
    language: str,
    filename: str,
    cve_context: List[CVEEntry],
    cwe_context: List[CWEEntry],
    static_findings: List[StaticFinding],
    pattern_matches: List[PatternMatch],
) -> str:
    """
    Build the full user prompt sent to the LLM for vulnerability analysis.

    The prompt is structured in clearly delimited sections so the model can
    focus on each information source independently before synthesising.
    """

    # ── Section 1: CVE context from RAG ──────────────────────────────────────
    cve_block = ""
    if cve_context:
        lines = []
        for c in cve_context:
            cwes = ", ".join(c.cwe_ids) if c.cwe_ids else "N/A"
            lines.append(
                f"  • {c.id} [{c.severity.value}, CVSS {c.cvss_score:.1f}] "
                f"CWEs: {cwes}\n    {c.description[:300]}"
            )
        cve_block = "RELEVANT CVEs FROM KNOWLEDGE BASE:\n" + "\n".join(lines)
    else:
        cve_block = "RELEVANT CVEs FROM KNOWLEDGE BASE:\n  (none retrieved)"

    # ── Section 2: CWE context from RAG ──────────────────────────────────────
    cwe_block = ""
    if cwe_context:
        lines = []
        for w in cwe_context:
            lines.append(
                f"  • {w.id}: {w.name}\n"
                f"    {w.description[:250]}"
            )
        cwe_block = "RELEVANT CWEs FROM KNOWLEDGE BASE:\n" + "\n".join(lines)
    else:
        cwe_block = "RELEVANT CWEs FROM KNOWLEDGE BASE:\n  (none retrieved)"

    # ── Section 3: Static analysis hints ──────────────────────────────────────
    static_block = ""
    if static_findings:
        lines = [
            f"  • Line {f.line_number}: [{f.severity}] {f.test_name} — {f.issue_text}"
            for f in static_findings
        ]
        static_block = "STATIC ANALYSIS PRE-SCAN HINTS:\n" + "\n".join(lines)
    else:
        static_block = "STATIC ANALYSIS PRE-SCAN HINTS:\n  (none)"

    # ── Section 4: Pattern-matcher hits ───────────────────────────────────────
    pattern_block = ""
    if pattern_matches:
        lines = [
            f"  • Lines {p.line_numbers}: [{p.severity.value}] "
            f"{p.vulnerability_type} ({p.cwe_id}) — confidence {p.confidence:.0%}"
            for p in pattern_matches
        ]
        pattern_block = "PATTERN MATCHER HITS:\n" + "\n".join(lines)
    else:
        pattern_block = "PATTERN MATCHER HITS:\n  (none)"

    # ── Section 5: The code itself ────────────────────────────────────────────
    code_block = f"SOURCE CODE TO ANALYSE  [{language.upper()}]  file: {filename}\n```{language}\n{code}\n```"

    # ── JSON schema instruction ────────────────────────────────────────────────
    schema = """\
INSTRUCTIONS:
Analyse the code above for ALL security vulnerabilities.
Consider:
  1. The retrieved CVE/CWE knowledge for patterns similar to this code.
  2. The static analysis hints and pattern hits as leads — verify them.
  3. Your own expert knowledge of common vulnerabilities in this language.

For EVERY real vulnerability found, populate one entry in the JSON below.
Do NOT invent CVE IDs. If you reference a CVE, it must appear in the list above.
Be precise about line numbers — count from line 1 at the top of the snippet.
Severity: CRITICAL | HIGH | MEDIUM | LOW | INFO

Respond with ONLY this JSON object (no markdown fences, no explanation):
{
  "vulnerabilities": [
    {
      "type": "<vulnerability name>",
      "cwe_id": "<CWE-NNN or null>",
      "cve_references": ["<CVE-YYYY-NNNNN>"],
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>",
      "line_numbers": [<int>, ...],
      "description": "<concise explanation of why this line is vulnerable>",
      "code_snippet": "<the exact vulnerable line(s)>",
      "remediation": "<concrete fix>",
      "confidence": <0.0–1.0>
    }
  ],
  "overall_risk": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>",
  "summary": "<2–3 sentence executive summary of findings>"
}

If NO vulnerabilities exist, return: {"vulnerabilities": [], "overall_risk": "INFO", "summary": "No vulnerabilities detected."}"""

    return "\n\n".join([
        cve_block,
        cwe_block,
        static_block,
        pattern_block,
        code_block,
        schema,
    ])


# ─────────────────────────────────────────────────────────────────────────────
# Remediation deep-dive prompt  (optional second call)
# ─────────────────────────────────────────────────────────────────────────────

def build_remediation_prompt(
    vulnerability_type: str,
    language: str,
    code_snippet: str,
) -> str:
    """
    Ask the LLM for a complete, drop-in fixed version of a vulnerable snippet.
    Used when the user clicks "Show Fix" in the UI.
    """
    return (
        f"The following {language} code contains a {vulnerability_type} vulnerability.\n\n"
        f"```{language}\n{code_snippet}\n```\n\n"
        "Provide the corrected version of this code with inline comments explaining "
        "each change. Output ONLY the fixed code block, no surrounding explanation."
    )


# ─────────────────────────────────────────────────────────────────────────────
# RAG embedding query prompt
# ─────────────────────────────────────────────────────────────────────────────

def build_rag_query(code_chunk: str, language: str) -> str:
    """
    Construct the query text used to search ChromaDB.
    Enriching the raw code with language context improves embedding similarity.
    """
    return (
        f"Security vulnerability in {language} code:\n{code_chunk[:800]}"
    )
