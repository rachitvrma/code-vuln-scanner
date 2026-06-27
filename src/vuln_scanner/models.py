"""
models.py
---------
Pydantic v2 data models for the entire scanner pipeline.

Every cross-module data structure lives here so imports stay unambiguous.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, computed_field


# ─── Enumerations ─────────────────────────────────────────────────────────────

class Severity(str, Enum):
    """CVSS-aligned severity levels."""
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"
    UNKNOWN  = "UNKNOWN"


class Language(str, Enum):
    """Source-code languages the scanner supports."""
    PYTHON     = "python"
    C          = "c"
    CPP        = "cpp"
    JAVA       = "java"
    JAVASCRIPT = "javascript"
    PHP        = "php"
    UNKNOWN    = "unknown"


# ─── Knowledge-Base Models ────────────────────────────────────────────────────

class CVEEntry(BaseModel):
    """A single CVE record as stored in ChromaDB."""
    id: str                          = Field(...,  description="CVE identifier, e.g. CVE-2021-44228")
    description: str                 = Field(...,  description="English vulnerability description")
    severity: Severity               = Field(default=Severity.UNKNOWN)
    cvss_score: float                = Field(default=0.0, ge=0.0, le=10.0)
    cwe_ids: List[str]               = Field(default_factory=list)
    references: List[str]            = Field(default_factory=list)
    published: Optional[str]         = Field(default=None)
    language_tags: List[str]         = Field(default_factory=list)


class CWEEntry(BaseModel):
    """A single CWE entry from the MITRE database."""
    id: str                          = Field(..., description="e.g. CWE-89")
    name: str
    description: str
    extended_description: Optional[str] = Field(default=None)
    examples: List[str]              = Field(default_factory=list)
    mitigations: List[str]           = Field(default_factory=list)
    related_weaknesses: List[str]    = Field(default_factory=list)


# ─── Detection Models ─────────────────────────────────────────────────────────

class Vulnerability(BaseModel):
    """A vulnerability detected by the LLM analysis stage."""

    id: str = Field(
        default_factory=lambda: "VULN-" + hashlib.md5(
            str(datetime.now().timestamp()).encode()
        ).hexdigest()[:8].upper()
    )
    type: str
    cwe_id: Optional[str]            = Field(default=None)
    cve_references: List[str]        = Field(default_factory=list)
    severity: Severity
    line_numbers: List[int]          = Field(default_factory=list)
    description: str
    code_snippet: Optional[str]      = Field(default=None)
    remediation: str
    confidence: float                = Field(default=0.8, ge=0.0, le=1.0)
    source: str                      = Field(default="llm",
                                             description="Detection source: llm | static | pattern")


class StaticFinding(BaseModel):
    """Output of a static analysis tool (e.g., Bandit)."""
    tool: str
    severity: str
    confidence: str                  = Field(default="HIGH")
    line_number: int
    col_offset: int                  = Field(default=0)
    test_id: str
    test_name: str
    issue_text: str
    code: str                        = Field(default="")
    cwe: Optional[str]               = Field(default=None)


class PatternMatch(BaseModel):
    """A hit from the regex-based pattern matcher."""
    pattern_name: str
    vulnerability_type: str
    cwe_id: str
    line_numbers: List[int]
    code_snippet: str
    description: str
    confidence: float                = Field(ge=0.0, le=1.0)
    severity: Severity


# ─── Scan Result ──────────────────────────────────────────────────────────────

class ScanResult(BaseModel):
    """Aggregated output of a complete vulnerability scan."""
    filename: str
    language: str
    code_hash: str
    code: str
    vulnerabilities: List[Vulnerability]  = Field(default_factory=list)
    static_findings: List[StaticFinding]  = Field(default_factory=list)
    pattern_matches: List[PatternMatch]   = Field(default_factory=list)
    scan_time: float
    model_used: str
    timestamp: datetime              = Field(default_factory=datetime.now)
    error: Optional[str]            = Field(default=None)

    # ── Derived counts (computed at access time, not stored) ───────────────

    @computed_field  # type: ignore[misc]
    @property
    def total_vulnerabilities(self) -> int:
        return len(self.vulnerabilities)

    @computed_field  # type: ignore[misc]
    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @computed_field  # type: ignore[misc]
    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    @computed_field  # type: ignore[misc]
    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM)

    @computed_field  # type: ignore[misc]
    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW)

    @computed_field  # type: ignore[misc]
    @property
    def overall_risk(self) -> Severity:
        if self.critical_count > 0:
            return Severity.CRITICAL
        if self.high_count > 0:
            return Severity.HIGH
        if self.medium_count > 0:
            return Severity.MEDIUM
        if self.low_count > 0:
            return Severity.LOW
        return Severity.INFO

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict (for JSON export)."""
        return self.model_dump(mode="json")


class ScanReport(BaseModel):
    """Final formatted report wrapping a ScanResult."""
    scan_result: ScanResult
    generated_at: datetime          = Field(default_factory=datetime.now)
    scanner_version: str            = Field(default="0.1.0")
