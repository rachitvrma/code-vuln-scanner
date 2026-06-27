"""
code-vuln-scanner
=================
LLM-based Code Vulnerability Scanner using RAG over CVE/CWE databases.

Workflow:
  1. Static analysis  (Bandit + regex pattern matcher)
  2. RAG retrieval    (ChromaDB + sentence-transformers)
  3. LLM analysis     (Ollama — CodeLlama / DeepSeek-Coder)
  4. Structured report (JSON / rich terminal / Streamlit UI)
"""

__version__ = "0.1.0"
__author__ = "NIELIT Project"
