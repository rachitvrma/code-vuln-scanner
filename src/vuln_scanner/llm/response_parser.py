"""
llm/response_parser.py
----------------------
Parse the LLM's text output into strongly-typed Vulnerability objects.

LLMs occasionally:
  • Wrap JSON in markdown fences (```json ... ```)
  • Emit trailing commas or comments
  • Return truncated JSON when the context window is full
  • Return plain text instead of JSON

This module handles all of those cases with multiple fallback strategies.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

from ..models import Severity, Vulnerability


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

class LLMParseError(Exception):
    """Raised when the LLM response cannot be parsed into vulnerabilities."""


def parse_vulnerabilities(raw: str) -> Tuple[List[Vulnerability], str, Severity]:
    """
    Parse the LLM's raw text response.

    Returns
    -------
    (vulnerabilities, summary, overall_risk)
    """
    raw = raw.strip()

    # Strategy 1 — direct JSON parse
    data = _try_direct_json(raw)

    # Strategy 2 — extract JSON from markdown fence
    if data is None:
        data = _try_extract_from_fence(raw)

    # Strategy 3 — find the first '{' ... last '}' block
    if data is None:
        data = _try_brace_extraction(raw)

    # Strategy 4 — return empty result rather than crashing
    if data is None:
        logger.warning("Could not parse LLM response as JSON. Returning empty result.")
        logger.debug(f"Unparseable response:\n{raw[:500]}")
        return [], "LLM response could not be parsed.", Severity.INFO

    vulns     = _extract_vulnerabilities(data)
    summary   = data.get("summary", "Analysis complete.")
    risk_raw  = data.get("overall_risk", "UNKNOWN").upper()
    overall   = _to_severity(risk_raw)

    logger.info(f"Parsed {len(vulns)} vulnerabilities from LLM response (overall_risk={overall})")
    return vulns, summary, overall


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _try_direct_json(text: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _try_extract_from_fence(text: str) -> Optional[Dict[str, Any]]:
    """Strip ```json ... ``` or ``` ... ``` wrappers and try again."""
    pattern = r"```(?:json)?\s*(\{.*?\})\s*```"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return _try_direct_json(match.group(1))
    return None


def _try_brace_extraction(text: str) -> Optional[Dict[str, Any]]:
    """
    Find the outermost JSON object by scanning for the first '{' and
    the last '}', then progressively strip trailing characters until
    the fragment is valid JSON (handles truncation).
    """
    start = text.find("{")
    end   = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None

    fragment = text[start : end + 1]

    # Try as-is first
    result = _try_direct_json(fragment)
    if result:
        return result

    # Try removing trailing incomplete entries (truncation repair)
    # Strategy: strip from the last complete array element
    for cutoff in [fragment.rfind("},"), fragment.rfind("]")]:
        if cutoff > 0:
            candidate = fragment[:cutoff + 1]
            # Close any open structures
            candidate = _close_json(candidate)
            result = _try_direct_json(candidate)
            if result:
                logger.warning("Repaired truncated JSON from LLM response.")
                return result

    return None


def _close_json(fragment: str) -> str:
    """
    Attempt to close an unclosed JSON object/array by counting braces.
    Very naive — handles the most common truncation case.
    """
    depth_obj   = fragment.count("{") - fragment.count("}")
    depth_arr   = fragment.count("[") - fragment.count("]")
    closing = "]" * max(depth_arr, 0) + "}" * max(depth_obj, 0)
    return fragment + closing


def _extract_vulnerabilities(data: Dict[str, Any]) -> List[Vulnerability]:
    """Convert the parsed JSON dict into Vulnerability model instances."""
    raw_list = data.get("vulnerabilities", [])
    if not isinstance(raw_list, list):
        logger.warning(f"'vulnerabilities' field is not a list: {type(raw_list)}")
        return []

    vulns: List[Vulnerability] = []
    for i, item in enumerate(raw_list):
        if not isinstance(item, dict):
            continue
        try:
            vuln = Vulnerability(
                type=item.get("type", "Unknown"),
                cwe_id=item.get("cwe_id") or None,
                cve_references=_safe_list(item.get("cve_references")),
                severity=_to_severity(item.get("severity", "UNKNOWN")),
                line_numbers=_safe_int_list(item.get("line_numbers")),
                description=item.get("description", ""),
                code_snippet=item.get("code_snippet") or None,
                remediation=item.get("remediation", ""),
                confidence=float(item.get("confidence", 0.8)),
                source="llm",
            )
            vulns.append(vuln)
        except Exception as exc:
            logger.warning(f"Skipping malformed vulnerability entry #{i}: {exc}")

    return vulns


def _to_severity(raw: str) -> Severity:
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH":     Severity.HIGH,
        "MEDIUM":   Severity.MEDIUM,
        "MODERATE": Severity.MEDIUM,
        "LOW":      Severity.LOW,
        "INFO":     Severity.INFO,
        "INFORMATIONAL": Severity.INFO,
    }
    return mapping.get(raw.strip().upper(), Severity.UNKNOWN)


def _safe_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(v) for v in value if v]
    if isinstance(value, str) and value:
        return [value]
    return []


def _safe_int_list(value: Any) -> List[int]:
    if isinstance(value, list):
        result = []
        for v in value:
            try:
                result.append(int(v))
            except (ValueError, TypeError):
                pass
        return result
    if isinstance(value, (int, float)):
        return [int(value)]
    return []
