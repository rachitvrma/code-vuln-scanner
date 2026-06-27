"""
rag/retriever.py
----------------
High-level retrieval interface used by the scanner pipeline.

At query time:
  1. The code chunk is embedded by CodeEmbedder.
  2. The embedding is used to query ChromaDB for similar CVEs and CWEs.
  3. Results are returned as typed model objects ready for prompt injection.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from loguru import logger

from ..config import settings
from ..models import CVEEntry, CWEEntry
from .embedder import CodeEmbedder
from .vectorstore import VectorStore


class CVERetriever:
    """
    Retrieves relevant CVE and CWE entries for a given code snippet.

    Usage::

        retriever = CVERetriever()
        cves, cwes = retriever.retrieve(code_snippet, language="python")
    """

    def __init__(self) -> None:
        self._embedder = CodeEmbedder()
        self._store    = VectorStore()

    def retrieve(
        self,
        code_chunk: str,
        language: str = "unknown",
        k_cve: Optional[int] = None,
        k_cwe: Optional[int] = None,
    ) -> Tuple[List[CVEEntry], List[CWEEntry]]:
        """
        Embed *code_chunk* and retrieve the most similar CVEs and CWEs.

        Parameters
        ----------
        code_chunk : A snippet of source code (ideally ≤ 800 characters for
                     best embedding quality).
        language   : Programming language tag (used to enrich the query).
        k_cve      : Override for TOP_K_CVE from settings.
        k_cwe      : Override for TOP_K_CWE from settings.

        Returns
        -------
        (cves, cwes) : Lists of the most relevant knowledge-base entries.
        """
        _k_cve = k_cve or settings.TOP_K_CVE
        _k_cwe = k_cwe or settings.TOP_K_CWE

        # Build an enriched query string (better retrieval than raw code alone)
        query_text = (
            f"Security vulnerability in {language} programming language:\n"
            f"{code_chunk[:800]}"
        )

        try:
            embedding = self._embedder.embed(query_text)
        except Exception as exc:
            logger.error(f"Embedding failed — RAG retrieval skipped: {exc}")
            return [], []

        cves = self._store.query_cves(embedding, k=_k_cve)
        cwes = self._store.query_cwes(embedding, k=_k_cwe)

        logger.info(
            f"RAG retrieval: {len(cves)} CVEs, {len(cwes)} CWEs "
            f"for {language} snippet ({len(code_chunk)} chars)"
        )
        return cves, cwes

    def retrieve_by_cwe(self, cwe_id: str) -> List[CVEEntry]:
        """
        Retrieve CVEs that reference a specific CWE ID (e.g. 'CWE-89').
        Useful for enriching pattern-matcher hits.
        """
        query_text = f"Vulnerability with weakness identifier {cwe_id}"
        try:
            embedding = self._embedder.embed(query_text)
            return self._store.query_cves(embedding, k=5)
        except Exception as exc:
            logger.error(f"CWE-based CVE retrieval failed: {exc}")
            return []

    @property
    def is_ready(self) -> bool:
        """Return True if the knowledge base has been populated."""
        return (
            self._store.cve_count > 0
            or self._store.cwe_count > 0
        )

    def knowledge_base_stats(self) -> dict:
        return {
            "cve_count": self._store.cve_count,
            "cwe_count": self._store.cwe_count,
            "embedding_model": settings.EMBEDDING_MODEL,
        }
