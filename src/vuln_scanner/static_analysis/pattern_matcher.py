"""
static_analysis/pattern_matcher.py
-----------------------------------
Regex-based detection of common vulnerability patterns.

This is the *fast* detection layer — no LLM, no network.  It runs first
and its findings are fed as hints to the LLM prompt to improve precision.

Each pattern is a dict with:
  name           : Human-readable rule name
  regex          : Compiled regular expression
  vuln_type      : Vulnerability category name
  cwe_id         : Associated CWE
  severity       : Severity enum value
  languages      : Languages this pattern applies to (empty = all)
  description    : Why this match is suspicious
  confidence     : Base confidence score (0–1)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern as RePattern

from loguru import logger

from ..models import Language, PatternMatch, Severity


# ─────────────────────────────────────────────────────────────────────────────
# Pattern definitions
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _Rule:
    name: str
    pattern: str
    vuln_type: str
    cwe_id: str
    severity: Severity
    languages: List[str]   # empty → applies to all languages
    description: str
    confidence: float
    # Compiled regex (populated in __post_init__)
    _compiled: Optional[RePattern] = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._compiled = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)

    def findall(self, code: str) -> List[int]:
        """Return 1-based line numbers where this pattern matches."""
        lines = code.splitlines()
        hits: List[int] = []
        for lineno, line in enumerate(lines, start=1):
            if self._compiled.search(line):  # type: ignore[union-attr]
                hits.append(lineno)
        return hits


# ── All rules ─────────────────────────────────────────────────────────────────
_RULES: List[_Rule] = [

    # ── SQL Injection (CWE-89) ────────────────────────────────────────────────
    _Rule(
        name="sqli_fstring_python",
        pattern=r'(execute|executemany)\s*\(\s*f["\'].*?SELECT|INSERT|UPDATE|DELETE|DROP',
        vuln_type="SQL Injection",
        cwe_id="CWE-89",
        severity=Severity.HIGH,
        languages=["python"],
        description="f-string interpolation inside an SQL execute() call — user data can reach the query.",
        confidence=0.90,
    ),
    _Rule(
        name="sqli_format_python",
        pattern=r'(execute|executemany)\s*\(.*?%\s*[(\w]|\.format\s*\(.*?(SELECT|INSERT|UPDATE|DELETE)',
        vuln_type="SQL Injection",
        cwe_id="CWE-89",
        severity=Severity.HIGH,
        languages=["python"],
        description="String formatting/% operator used to build SQL inside execute().",
        confidence=0.85,
    ),
    _Rule(
        name="sqli_concat_java",
        pattern=r'"(SELECT|INSERT|UPDATE|DELETE|DROP)[^"]*"\s*\+',
        vuln_type="SQL Injection",
        cwe_id="CWE-89",
        severity=Severity.HIGH,
        languages=["java"],
        description="String concatenation used to build SQL query.",
        confidence=0.85,
    ),
    _Rule(
        name="sqli_php_query",
        pattern=r'(mysql_query|mysqli_query|pg_query)\s*\(\s*[^,)]*\$_(GET|POST|REQUEST|COOKIE)',
        vuln_type="SQL Injection",
        cwe_id="CWE-89",
        severity=Severity.CRITICAL,
        languages=["php"],
        description="Unsanitised superglobal used directly in a database query.",
        confidence=0.95,
    ),

    # ── Command Injection (CWE-78) ────────────────────────────────────────────
    _Rule(
        name="cmdi_os_system",
        pattern=r'\bos\.system\s*\(',
        vuln_type="Command Injection",
        cwe_id="CWE-78",
        severity=Severity.HIGH,
        languages=["python"],
        description="os.system() executes a shell command; attacker-controlled input can inject arbitrary commands.",
        confidence=0.80,
    ),
    _Rule(
        name="cmdi_subprocess_shell",
        pattern=r'\bsubprocess\.(call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True',
        vuln_type="Command Injection",
        cwe_id="CWE-78",
        severity=Severity.HIGH,
        languages=["python"],
        description="subprocess with shell=True passes the command through /bin/sh.",
        confidence=0.90,
    ),
    _Rule(
        name="cmdi_eval_python",
        pattern=r'\beval\s*\(',
        vuln_type="Command Injection",
        cwe_id="CWE-78",
        severity=Severity.HIGH,
        languages=["python", "javascript"],
        description="eval() executes arbitrary code from a string.",
        confidence=0.85,
    ),
    _Rule(
        name="cmdi_exec_python",
        pattern=r'\bexec\s*\(',
        vuln_type="Command Injection",
        cwe_id="CWE-78",
        severity=Severity.HIGH,
        languages=["python"],
        description="exec() can execute attacker-supplied code.",
        confidence=0.80,
    ),
    _Rule(
        name="cmdi_runtime_java",
        pattern=r'Runtime\.getRuntime\(\)\.exec\s*\(',
        vuln_type="Command Injection",
        cwe_id="CWE-78",
        severity=Severity.HIGH,
        languages=["java"],
        description="Runtime.exec() called — ensure arguments are never user-supplied.",
        confidence=0.85,
    ),
    _Rule(
        name="cmdi_php_exec",
        pattern=r'\b(system|exec|shell_exec|passthru|popen)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
        vuln_type="Command Injection",
        cwe_id="CWE-78",
        severity=Severity.CRITICAL,
        languages=["php"],
        description="PHP shell function called directly with unsanitised superglobal.",
        confidence=0.95,
    ),

    # ── Buffer Overflow (CWE-120/121) ─────────────────────────────────────────
    _Rule(
        name="bof_gets",
        pattern=r'\bgets\s*\(',
        vuln_type="Buffer Overflow",
        cwe_id="CWE-120",
        severity=Severity.CRITICAL,
        languages=["c", "cpp"],
        description="gets() has no bounds checking — always causes a buffer overflow risk.",
        confidence=0.99,
    ),
    _Rule(
        name="bof_strcpy",
        pattern=r'\bstrcpy\s*\(',
        vuln_type="Buffer Overflow",
        cwe_id="CWE-120",
        severity=Severity.HIGH,
        languages=["c", "cpp"],
        description="strcpy() does not check destination buffer size. Use strlcpy() or strncpy().",
        confidence=0.90,
    ),
    _Rule(
        name="bof_strcat",
        pattern=r'\bstrcat\s*\(',
        vuln_type="Buffer Overflow",
        cwe_id="CWE-120",
        severity=Severity.HIGH,
        languages=["c", "cpp"],
        description="strcat() does not check buffer size. Use strncat() or strlcat().",
        confidence=0.88,
    ),
    _Rule(
        name="bof_sprintf",
        pattern=r'\bsprintf\s*\(',
        vuln_type="Buffer Overflow",
        cwe_id="CWE-120",
        severity=Severity.HIGH,
        languages=["c", "cpp"],
        description="sprintf() can overflow the destination buffer. Use snprintf().",
        confidence=0.85,
    ),
    _Rule(
        name="bof_scanf_s",
        pattern=r'\bscanf\s*\(\s*"[^"]*%s',
        vuln_type="Buffer Overflow",
        cwe_id="CWE-120",
        severity=Severity.HIGH,
        languages=["c", "cpp"],
        description="scanf() with %s has no length limit — can overflow buffer.",
        confidence=0.90,
    ),

    # ── Path Traversal (CWE-22) ───────────────────────────────────────────────
    _Rule(
        name="traversal_open_input",
        pattern=r'\bopen\s*\(\s*(request\.|input\(|argv\[|sys\.argv)',
        vuln_type="Path Traversal",
        cwe_id="CWE-22",
        severity=Severity.HIGH,
        languages=["python"],
        description="open() called with user-controlled path — '../' sequences can escape the intended directory.",
        confidence=0.80,
    ),
    _Rule(
        name="traversal_php_include",
        pattern=r'\b(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
        vuln_type="Path Traversal",
        cwe_id="CWE-22",
        severity=Severity.CRITICAL,
        languages=["php"],
        description="File inclusion with unsanitised superglobal allows remote/local file inclusion.",
        confidence=0.95,
    ),
    _Rule(
        name="traversal_java_filereader",
        pattern=r'new\s+File(Reader|InputStream)?\s*\(\s*request\.getParameter',
        vuln_type="Path Traversal",
        cwe_id="CWE-22",
        severity=Severity.HIGH,
        languages=["java"],
        description="File opened with request parameter — path traversal possible.",
        confidence=0.88,
    ),

    # ── Cross-Site Scripting (CWE-79) ─────────────────────────────────────────
    _Rule(
        name="xss_php_echo",
        pattern=r'\b(echo|print)\s+.*\$_(GET|POST|REQUEST|COOKIE)',
        vuln_type="Cross-Site Scripting",
        cwe_id="CWE-79",
        severity=Severity.HIGH,
        languages=["php"],
        description="Unsanitised superglobal echoed to HTML output.",
        confidence=0.90,
    ),
    _Rule(
        name="xss_js_innerhtml",
        pattern=r'\.innerHTML\s*=\s*(?!.*DOMPurify)',
        vuln_type="Cross-Site Scripting",
        cwe_id="CWE-79",
        severity=Severity.HIGH,
        languages=["javascript"],
        description="innerHTML assignment without sanitisation allows script injection.",
        confidence=0.80,
    ),
    _Rule(
        name="xss_js_document_write",
        pattern=r'document\.write\s*\(',
        vuln_type="Cross-Site Scripting",
        cwe_id="CWE-79",
        severity=Severity.MEDIUM,
        languages=["javascript"],
        description="document.write() can introduce XSS when used with external data.",
        confidence=0.70,
    ),

    # ── Insecure Deserialization (CWE-502) ────────────────────────────────────
    _Rule(
        name="insecure_deser_pickle",
        pattern=r'\bpickle\.(loads?|Unpickler)\s*\(',
        vuln_type="Insecure Deserialization",
        cwe_id="CWE-502",
        severity=Severity.CRITICAL,
        languages=["python"],
        description="pickle.loads() can execute arbitrary Python code from attacker-supplied data.",
        confidence=0.95,
    ),
    _Rule(
        name="insecure_deser_yaml_unsafe",
        pattern=r'\byaml\.load\s*\([^)]*Loader\s*=\s*yaml\.Loader',
        vuln_type="Insecure Deserialization",
        cwe_id="CWE-502",
        severity=Severity.HIGH,
        languages=["python"],
        description="yaml.load() with the full Loader is unsafe. Use yaml.safe_load().",
        confidence=0.90,
    ),
    _Rule(
        name="insecure_deser_yaml_no_loader",
        pattern=r'\byaml\.load\s*\([^)]*\)',
        vuln_type="Insecure Deserialization",
        cwe_id="CWE-502",
        severity=Severity.HIGH,
        languages=["python"],
        description="yaml.load() without explicit SafeLoader is unsafe.",
        confidence=0.80,
    ),
    _Rule(
        name="insecure_deser_marshal",
        pattern=r'\bmarshal\.loads?\s*\(',
        vuln_type="Insecure Deserialization",
        cwe_id="CWE-502",
        severity=Severity.HIGH,
        languages=["python"],
        description="marshal is not safe for untrusted data — can execute code.",
        confidence=0.90,
    ),
    _Rule(
        name="insecure_deser_java_ois",
        pattern=r'new\s+ObjectInputStream\s*\(',
        vuln_type="Insecure Deserialization",
        cwe_id="CWE-502",
        severity=Severity.HIGH,
        languages=["java"],
        description="Java ObjectInputStream deserialization — commonly exploited for RCE.",
        confidence=0.88,
    ),
    _Rule(
        name="insecure_deser_php_unserialize",
        pattern=r'\bunserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
        vuln_type="Insecure Deserialization",
        cwe_id="CWE-502",
        severity=Severity.CRITICAL,
        languages=["php"],
        description="PHP unserialize() with untrusted data can trigger object injection.",
        confidence=0.95,
    ),

    # ── Hardcoded Credentials (CWE-798) ───────────────────────────────────────
    _Rule(
        name="hardcoded_password",
        pattern=r'(password|passwd|secret|api_key|apikey|auth_token|access_token)'
                r'\s*=\s*["\'][^"\']{4,}["\']',
        vuln_type="Hardcoded Credentials",
        cwe_id="CWE-798",
        severity=Severity.HIGH,
        languages=[],   # all languages
        description="Credential or secret value hardcoded in source — use environment variables or a secrets manager.",
        confidence=0.80,
    ),
    _Rule(
        name="hardcoded_aws_key",
        pattern=r'(AKIA|ASIA)[A-Z0-9]{16}',
        vuln_type="Hardcoded Credentials",
        cwe_id="CWE-798",
        severity=Severity.CRITICAL,
        languages=[],
        description="AWS access key ID pattern detected — rotate immediately.",
        confidence=0.98,
    ),

    # ── Integer Overflow (CWE-190) ────────────────────────────────────────────
    _Rule(
        name="integer_overflow_malloc",
        pattern=r'\bmalloc\s*\([^)]*\*[^)]*\)',
        vuln_type="Integer Overflow",
        cwe_id="CWE-190",
        severity=Severity.MEDIUM,
        languages=["c", "cpp"],
        description="malloc() argument contains multiplication — can overflow before allocation.",
        confidence=0.70,
    ),
    _Rule(
        name="integer_overflow_int_cast",
        pattern=r'\(int\)\s*\w+\s*\*\s*\w+',
        vuln_type="Integer Overflow",
        cwe_id="CWE-190",
        severity=Severity.MEDIUM,
        languages=["c", "cpp", "java"],
        description="Casting multiplication result to int may truncate large values.",
        confidence=0.65,
    ),

    # ── Use After Free (CWE-416) ──────────────────────────────────────────────
    _Rule(
        name="use_after_free_free_then_use",
        pattern=r'\bfree\s*\(\s*(\w+)\s*\)',
        vuln_type="Use After Free",
        cwe_id="CWE-416",
        severity=Severity.CRITICAL,
        languages=["c", "cpp"],
        description="Pointer freed — verify it is not dereferenced after this point.",
        confidence=0.60,   # lower because we can't confirm subsequent use without context
    ),

    # ── XML External Entity (CWE-611) ─────────────────────────────────────────
    _Rule(
        name="xxe_python_lxml",
        pattern=r'etree\.(parse|fromstring|XML)\s*\(',
        vuln_type="XML External Entity Injection",
        cwe_id="CWE-611",
        severity=Severity.HIGH,
        languages=["python"],
        description="lxml parser may process external entities unless resolve_entities=False.",
        confidence=0.65,
    ),
    _Rule(
        name="xxe_java_documentbuilder",
        pattern=r'DocumentBuilderFactory\.newInstance\(\)',
        vuln_type="XML External Entity Injection",
        cwe_id="CWE-611",
        severity=Severity.HIGH,
        languages=["java"],
        description="DocumentBuilderFactory without disabling external entities is XXE-vulnerable.",
        confidence=0.75,
    ),

    # ── Race Condition (CWE-362) ──────────────────────────────────────────────
    _Rule(
        name="race_condition_no_lock",
        pattern=r'\bthreading\.Thread\s*\(',
        vuln_type="Race Condition",
        cwe_id="CWE-362",
        severity=Severity.MEDIUM,
        languages=["python"],
        description="Thread spawned — ensure shared state is protected with a Lock/RLock.",
        confidence=0.50,   # low; presence of Thread alone doesn't confirm race
    ),
    _Rule(
        name="race_condition_toctou",
        pattern=r'\bos\.path\.exists\s*\(.*\n.*\bopen\s*\(',
        vuln_type="Race Condition (TOCTOU)",
        cwe_id="CWE-362",
        severity=Severity.MEDIUM,
        languages=["python"],
        description="Time-of-check / time-of-use: file existence checked then opened separately.",
        confidence=0.65,
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Public class
# ─────────────────────────────────────────────────────────────────────────────

class PatternMatcher:
    """
    Fast regex-based vulnerability pattern scanner.

    Usage::

        matcher = PatternMatcher()
        matches = matcher.match(code, language="python")
    """

    def __init__(self) -> None:
        self._rules = _RULES

    def match(self, code: str, language: str) -> List[PatternMatch]:
        """
        Run all applicable rules against *code*.

        Parameters
        ----------
        code     : Source code as a string.
        language : Language tag (lowercase, e.g. 'python').

        Returns
        -------
        List[PatternMatch] sorted by line number.
        """
        lang = language.lower()
        results: List[PatternMatch] = []

        for rule in self._rules:
            # Skip if rule targets specific languages and this isn't one of them
            if rule.languages and lang not in rule.languages:
                continue

            line_numbers = rule.findall(code)
            if not line_numbers:
                continue

            # Extract the first matching line as a snippet
            lines = code.splitlines()
            snippet_lines = []
            for ln in line_numbers[:3]:  # show up to 3 matching lines
                if 1 <= ln <= len(lines):
                    snippet_lines.append(f"L{ln}: {lines[ln - 1].strip()}")
            snippet = "\n".join(snippet_lines)

            results.append(PatternMatch(
                pattern_name=rule.name,
                vulnerability_type=rule.vuln_type,
                cwe_id=rule.cwe_id,
                line_numbers=line_numbers,
                code_snippet=snippet,
                description=rule.description,
                confidence=rule.confidence,
                severity=rule.severity,
            ))
            logger.debug(
                f"Pattern '{rule.name}' matched at lines {line_numbers[:5]} in {language} code"
            )

        # Deduplicate same vuln_type + cwe on overlapping lines
        results = _deduplicate(results)

        logger.info(f"Pattern matcher: {len(results)} matches in {language} code")
        return sorted(results, key=lambda m: m.line_numbers[0] if m.line_numbers else 0)

    def rules_for_language(self, language: str) -> List[str]:
        """Return names of all rules applicable to *language*."""
        lang = language.lower()
        return [r.name for r in self._rules if not r.languages or lang in r.languages]


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _deduplicate(matches: List[PatternMatch]) -> List[PatternMatch]:
    """
    Remove lower-confidence duplicates when two rules flag the same
    (cwe_id, first_line) pair.
    """
    seen: Dict[tuple, PatternMatch] = {}
    for m in matches:
        key = (m.cwe_id, m.line_numbers[0] if m.line_numbers else -1)
        if key not in seen or m.confidence > seen[key].confidence:
            seen[key] = m
    return list(seen.values())
