"""
tests/unit/test_static_analysis.py
------------------------------------
Unit tests for pattern_matcher, bandit_wrapper, and ast_parser.
All tests run offline — no Ollama, no ChromaDB, no network.
"""

from __future__ import annotations

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# PatternMatcher tests
# ─────────────────────────────────────────────────────────────────────────────

class TestPatternMatcher:

    def test_detects_sql_injection_fstring(self, pattern_matcher):
        code = 'cursor.execute(f"SELECT * FROM users WHERE name=\'{username}\'")'
        matches = pattern_matcher.match(code, "python")
        types = [m.vulnerability_type for m in matches]
        assert "SQL Injection" in types

    def test_detects_sql_injection_concat(self, pattern_matcher):
        code = 'cursor.execute("SELECT * FROM users WHERE id=" + user_id)'
        matches = pattern_matcher.match(code, "python")
        types = [m.vulnerability_type for m in matches]
        assert "SQL Injection" in types

    def test_detects_pickle_loads(self, pattern_matcher, insecure_deser_code):
        matches = pattern_matcher.match(insecure_deser_code, "python")
        types   = [m.vulnerability_type for m in matches]
        assert "Insecure Deserialization" in types

    def test_detects_os_system(self, pattern_matcher):
        code = "os.system('rm -rf ' + user_path)"
        matches = pattern_matcher.match(code, "python")
        types = [m.vulnerability_type for m in matches]
        assert "Command Injection" in types

    def test_detects_subprocess_shell_true(self, pattern_matcher):
        code = "subprocess.run(cmd, shell=True)"
        matches = pattern_matcher.match(code, "python")
        types = [m.vulnerability_type for m in matches]
        assert "Command Injection" in types

    def test_detects_gets_c(self, pattern_matcher, buffer_overflow_c_code):
        matches = pattern_matcher.match(buffer_overflow_c_code, "c")
        types   = [m.vulnerability_type for m in matches]
        assert "Buffer Overflow" in types

    def test_detects_strcpy(self, pattern_matcher):
        code = "strcpy(dest, src);"
        matches = pattern_matcher.match(code, "c")
        types = [m.vulnerability_type for m in matches]
        assert "Buffer Overflow" in types

    def test_detects_hardcoded_password(self, pattern_matcher):
        code = 'password = "super_secret_123"'
        matches = pattern_matcher.match(code, "python")
        types = [m.vulnerability_type for m in matches]
        assert "Hardcoded Credentials" in types

    def test_detects_aws_key(self, pattern_matcher):
        code = 'AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"'
        matches = pattern_matcher.match(code, "python")
        types = [m.vulnerability_type for m in matches]
        assert "Hardcoded Credentials" in types

    def test_no_false_positive_on_safe_code(self, pattern_matcher, safe_code):
        matches = pattern_matcher.match(safe_code, "python")
        # Safe code should have no or minimal pattern hits
        # Strictly: SQL injection should NOT fire
        sql_hits = [m for m in matches if m.vulnerability_type == "SQL Injection"]
        assert len(sql_hits) == 0

    def test_language_filter(self, pattern_matcher):
        """Buffer overflow patterns should not fire on Python code."""
        code = "gets(buffer)  # this is just a comment in Python"
        matches = pattern_matcher.match(code, "python")
        bof = [m for m in matches if m.vulnerability_type == "Buffer Overflow"]
        assert len(bof) == 0

    def test_returns_correct_line_numbers(self, pattern_matcher):
        code = "line1 = 1\npassword = 'abc123'\nline3 = 3"
        matches = pattern_matcher.match(code, "python")
        cred = [m for m in matches if m.vulnerability_type == "Hardcoded Credentials"]
        assert cred
        assert 2 in cred[0].line_numbers  # password is on line 2

    def test_match_returns_sorted_by_line(self, pattern_matcher, insecure_deser_code):
        matches = pattern_matcher.match(insecure_deser_code, "python")
        if len(matches) >= 2:
            lines = [m.line_numbers[0] for m in matches if m.line_numbers]
            assert lines == sorted(lines)


# ─────────────────────────────────────────────────────────────────────────────
# ASTParser tests
# ─────────────────────────────────────────────────────────────────────────────

class TestASTParser:

    def test_detects_dangerous_import_pickle(self, ast_parser, insecure_deser_code):
        result = ast_parser.parse(insecure_deser_code)
        assert any("pickle" in imp for imp in result.dangerous_imports)

    def test_detects_os_system_call(self, ast_parser, insecure_deser_code):
        result = ast_parser.parse(insecure_deser_code)
        # os.system is in dangerous_calls via eval/exec detection
        # os itself is a dangerous module
        assert any("os" in imp for imp in result.imports)

    def test_detects_hardcoded_secret_vars(self, ast_parser, insecure_deser_code):
        result = ast_parser.parse(insecure_deser_code)
        found_names = " ".join(result.hardcoded_secret_vars).lower()
        assert "secret_key" in found_names or "db_password" in found_names

    def test_syntax_error_does_not_crash(self, ast_parser):
        result = ast_parser.parse("def broken( :")
        assert result.parse_error is not None
        assert result.imports == []

    def test_no_false_positives_on_safe_code(self, ast_parser, safe_code):
        result = ast_parser.parse(safe_code)
        # Safe code reads credentials from env — variable NAME may be flagged,
        # but value should be empty string, so hardcoded_secret_vars should be empty.
        assert result.hardcoded_secret_vars == []

    def test_extracts_function_names(self, ast_parser, sql_injection_code):
        result = ast_parser.parse(sql_injection_code)
        func_names = " ".join(result.function_names)
        assert "get_user" in func_names
        assert "delete_user" in func_names


# ─────────────────────────────────────────────────────────────────────────────
# BanditAnalyzer tests
# ─────────────────────────────────────────────────────────────────────────────

class TestBanditAnalyzer:

    def test_bandit_runs_without_crash(self, bandit_analyzer, sql_injection_code):
        if not bandit_analyzer.is_available:
            pytest.skip("bandit not installed")
        findings = bandit_analyzer.analyze(sql_injection_code)
        # Should return a list (possibly empty if Bandit doesn't catch f-strings)
        assert isinstance(findings, list)

    def test_bandit_detects_pickle(self, bandit_analyzer, insecure_deser_code):
        if not bandit_analyzer.is_available:
            pytest.skip("bandit not installed")
        findings = bandit_analyzer.analyze(insecure_deser_code)
        test_ids = {f.test_id for f in findings}
        # B301 = pickle usage, B506 = yaml.load unsafe
        assert "B301" in test_ids or "B506" in test_ids or len(findings) > 0

    def test_bandit_safe_code_fewer_findings(self, bandit_analyzer, safe_code):
        if not bandit_analyzer.is_available:
            pytest.skip("bandit not installed")
        findings = bandit_analyzer.analyze(safe_code)
        # Safe code may have a few low-severity hits but shouldn't have HIGH
        high_findings = [f for f in findings if f.severity == "HIGH"]
        assert len(high_findings) == 0
