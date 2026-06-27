"""
tests/unit/test_rag.py
-----------------------
Unit tests for embedder, vectorstore, and retriever.
These tests run without a real ChromaDB (uses a temp directory from conftest).
"""

from __future__ import annotations

import pytest

from vuln_scanner.models import CVEEntry, CWEEntry, Severity
from vuln_scanner.data.preprocessor import (
    CodePreprocessor, detect_language, chunk_code,
    extract_python_functions,
)


# ─────────────────────────────────────────────────────────────────────────────
# Language detection tests
# ─────────────────────────────────────────────────────────────────────────────

class TestLanguageDetection:

    def test_detects_python_by_extension(self):
        assert detect_language("", "app.py") == "python"

    def test_detects_c_by_extension(self):
        assert detect_language("", "main.c") == "c"

    def test_detects_cpp_by_extension(self):
        assert detect_language("", "game.cpp") == "cpp"

    def test_detects_java_by_extension(self):
        assert detect_language("", "App.java") == "java"

    def test_detects_js_by_extension(self):
        assert detect_language("", "index.js") == "javascript"

    def test_detects_php_by_extension(self):
        assert detect_language("", "index.php") == "php"

    def test_detects_python_by_shebang(self):
        code = "#!/usr/bin/env python3\nimport sys"
        assert detect_language(code, "") == "python"

    def test_detects_python_by_content(self):
        code = "import os\ndef main():\n    pass"
        assert detect_language(code, "") == "python"

    def test_detects_c_by_include(self):
        code = "#include <stdio.h>\nint main() { return 0; }"
        assert detect_language(code, "") == "c"

    def test_detects_cpp_by_include(self):
        code = "#include <iostream>\nint main() { return 0; }"
        assert detect_language(code, "") in ("c", "cpp")

    def test_detects_php_by_tag(self):
        code = "<?php\necho 'hello';\n?>"
        assert detect_language(code, "") == "php"

    def test_returns_unknown_for_gibberish(self):
        result = detect_language("xyzzy foo bar baz qux 12345", "")
        assert result == "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Code chunking tests
# ─────────────────────────────────────────────────────────────────────────────

class TestChunking:

    def test_small_code_returns_one_chunk(self):
        code   = "x = 1\ny = 2"
        chunks = chunk_code(code, max_chars=1000)
        assert len(chunks) == 1
        assert chunks[0] == code

    def test_large_code_is_split(self):
        code   = ("line of code\n" * 200)          # ~2600 chars
        chunks = chunk_code(code, max_chars=500)
        assert len(chunks) > 1

    def test_chunks_cover_all_content(self):
        code   = "\n".join(f"line {i}" for i in range(50))
        chunks = chunk_code(code, max_chars=100)
        combined = " ".join(chunks)
        # All line numbers should appear somewhere in the combined chunks
        for i in range(0, 50, 10):
            assert f"line {i}" in combined

    def test_chunk_size_respected(self):
        code   = "a" * 3000
        chunks = chunk_code(code, max_chars=500)
        for chunk in chunks:
            assert len(chunk) <= 700  # allow some overlap tolerance


# ─────────────────────────────────────────────────────────────────────────────
# Function extraction tests
# ─────────────────────────────────────────────────────────────────────────────

class TestFunctionExtraction:

    def test_extracts_python_functions(self):
        code = """
def foo():
    return 1

def bar(x):
    return x + 1
"""
        funcs = extract_python_functions(code)
        assert len(funcs) == 2
        assert any("foo" in f for f in funcs)
        assert any("bar" in f for f in funcs)

    def test_handles_syntax_error_gracefully(self):
        funcs = extract_python_functions("def broken(:")
        assert len(funcs) == 1  # returns whole code as fallback


# ─────────────────────────────────────────────────────────────────────────────
# Embedder tests
# ─────────────────────────────────────────────────────────────────────────────

class TestEmbedder:

    @pytest.mark.slow
    def test_embed_returns_list_of_floats(self):
        from vuln_scanner.rag.embedder import CodeEmbedder
        embedder = CodeEmbedder()
        vec = embedder.embed("SQL injection vulnerability in Python")
        assert isinstance(vec, list)
        assert len(vec) > 0
        assert all(isinstance(x, float) for x in vec)

    @pytest.mark.slow
    def test_embed_batch_lengths_match(self):
        from vuln_scanner.rag.embedder import CodeEmbedder
        embedder = CodeEmbedder()
        texts = ["text one", "text two", "text three"]
        vecs  = embedder.embed_batch(texts)
        assert len(vecs) == 3
        dim = len(vecs[0])
        for v in vecs:
            assert len(v) == dim

    @pytest.mark.slow
    def test_similar_texts_have_higher_cosine(self):
        """SQL-related text should be more similar to another SQL text than to C buffer overflow."""
        import numpy as np
        from vuln_scanner.rag.embedder import CodeEmbedder
        embedder = CodeEmbedder()
        sql1 = embedder.embed("SQL injection via string concatenation in Python")
        sql2 = embedder.embed("SQL injection through user input in database query")
        bof  = embedder.embed("Buffer overflow in C strcpy without bounds check")
        v1, v2, v3 = np.array(sql1), np.array(sql2), np.array(bof)
        sim_same = float(np.dot(v1, v2))
        sim_diff = float(np.dot(v1, v3))
        assert sim_same > sim_diff
