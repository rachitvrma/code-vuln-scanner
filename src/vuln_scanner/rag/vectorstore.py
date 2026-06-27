"""
rag/vectorstore.py
------------------
ChromaDB-backed vector store for the CVE and CWE knowledge bases.

Collections
-----------
  cve_database  — one document per CVE entry
  cwe_database  — one document per CWE weakness

Each document is the concatenated text used for embedding, and metadata
fields carry all structured data (id, severity, cvss_score, …) that can
be returned with results without needing a second lookup.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import chromadb
from chromadb.config import Settings as ChromaSettings
from loguru import logger

from ..config import settings
from ..models import CVEEntry, CWEEntry, Severity


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _cve_to_doc(entry: CVEEntry) -> str:
    """Convert a CVE entry to the text string that will be embedded."""
    cwe_str = " ".join(entry.cwe_ids)
    return (
        f"{entry.id} {entry.severity.value} CVSS:{entry.cvss_score:.1f} "
        f"CWEs:{cwe_str} "
        f"{entry.description}"
    )


def _cwe_to_doc(entry: CWEEntry) -> str:
    """Convert a CWE entry to the text string that will be embedded."""
    mitigations = " ".join(entry.mitigations[:3])
    return (
        f"{entry.id} {entry.name} "
        f"{entry.description} "
        f"Mitigations: {mitigations}"
    )


def _cve_metadata(entry: CVEEntry) -> Dict[str, Any]:
    return {
        "id":          entry.id,
        "severity":    entry.severity.value,
        "cvss_score":  entry.cvss_score,
        "cwe_ids":     json.dumps(entry.cwe_ids),
        "references":  json.dumps(entry.references[:5]),
        "published":   entry.published or "",
        "language_tags": json.dumps(entry.language_tags),
    }


def _cwe_metadata(entry: CWEEntry) -> Dict[str, Any]:
    return {
        "id":          entry.id,
        "name":        entry.name,
        "mitigations": json.dumps(entry.mitigations[:5]),
        "related":     json.dumps(entry.related_weaknesses[:5]),
    }


# ─────────────────────────────────────────────────────────────────────────────
# VectorStore
# ─────────────────────────────────────────────────────────────────────────────

class VectorStore:
    """
    Thin wrapper around ChromaDB providing typed add / query operations
    for CVE and CWE collections.

    The client uses PersistentClient so data survives across runs.

    Usage::

        store = VectorStore()
        store.add_cves(cve_list, embeddings)
        results = store.query_cves(query_embedding, k=5)
    """

    def __init__(self) -> None:
        persist_dir = Path(settings.CHROMA_PERSIST_DIR)
        persist_dir.mkdir(parents=True, exist_ok=True)

        self._client = chromadb.PersistentClient(
            path=str(persist_dir),
            settings=ChromaSettings(anonymized_telemetry=False),
        )

        # Get-or-create both collections
        self._cve_col = self._client.get_or_create_collection(
            name=settings.CHROMA_COLLECTION_CVE,
            metadata={"hnsw:space": "cosine"},
        )
        self._cwe_col = self._client.get_or_create_collection(
            name=settings.CHROMA_COLLECTION_CWE,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info(
            f"VectorStore ready — CVE: {self._cve_col.count()} docs, "
            f"CWE: {self._cwe_col.count()} docs"
        )

    # ── CVE operations ────────────────────────────────────────────────────────

    @property
    def cve_count(self) -> int:
        return self._cve_col.count()

    @property
    def cwe_count(self) -> int:
        return self._cwe_col.count()

    def add_cves(
        self,
        entries: List[CVEEntry],
        embeddings: List[List[float]],
        batch_size: int = 100,
    ) -> int:
        """
        Upsert CVE entries into ChromaDB.

        Upsert (not insert) so re-running setup_db.py is idempotent.

        Returns
        -------
        int : Number of entries added / updated.
        """
        if not entries:
            return 0

        total = 0
        for i in range(0, len(entries), batch_size):
            batch_e   = entries[i : i + batch_size]
            batch_emb = embeddings[i : i + batch_size]

            self._cve_col.upsert(
                ids        = [e.id for e in batch_e],
                documents  = [_cve_to_doc(e) for e in batch_e],
                embeddings = batch_emb,
                metadatas  = [_cve_metadata(e) for e in batch_e],
            )
            total += len(batch_e)
            logger.debug(f"Upserted CVE batch [{i}:{i + len(batch_e)}]")

        logger.info(f"Added/updated {total} CVE entries. Total: {self.cve_count}")
        return total

    def query_cves(
        self,
        embedding: List[float],
        k: int = 5,
        severity_filter: Optional[str] = None,
    ) -> List[CVEEntry]:
        """
        Retrieve the top-*k* CVEs most similar to *embedding*.

        Parameters
        ----------
        embedding       : Query embedding vector.
        k               : Number of results to return.
        severity_filter : If set, only return CVEs with this severity (e.g. "HIGH").

        Returns
        -------
        List[CVEEntry]
        """
        if self.cve_count == 0:
            logger.warning("CVE collection is empty. Run scripts/setup_db.py first.")
            return []

        where: Optional[Dict] = (
            {"severity": {"$eq": severity_filter}} if severity_filter else None
        )

        try:
            result = self._cve_col.query(
                query_embeddings=[embedding],
                n_results=min(k, self.cve_count),
                where=where,
                include=["documents", "metadatas", "distances"],
            )
        except Exception as exc:
            logger.error(f"ChromaDB CVE query failed: {exc}")
            return []

        return self._result_to_cves(result)

    # ── CWE operations ────────────────────────────────────────────────────────

    def add_cwes(
        self,
        entries: List[CWEEntry],
        embeddings: List[List[float]],
        batch_size: int = 100,
    ) -> int:
        if not entries:
            return 0

        total = 0
        for i in range(0, len(entries), batch_size):
            batch_e   = entries[i : i + batch_size]
            batch_emb = embeddings[i : i + batch_size]

            self._cwe_col.upsert(
                ids        = [e.id for e in batch_e],
                documents  = [_cwe_to_doc(e) for e in batch_e],
                embeddings = batch_emb,
                metadatas  = [_cwe_metadata(e) for e in batch_e],
            )
            total += len(batch_e)

        logger.info(f"Added/updated {total} CWE entries. Total: {self.cwe_count}")
        return total

    def query_cwes(
        self, embedding: List[float], k: int = 3
    ) -> List[CWEEntry]:
        if self.cwe_count == 0:
            logger.warning("CWE collection is empty. Run scripts/setup_db.py first.")
            return []

        try:
            result = self._cwe_col.query(
                query_embeddings=[embedding],
                n_results=min(k, self.cwe_count),
                include=["documents", "metadatas", "distances"],
            )
        except Exception as exc:
            logger.error(f"ChromaDB CWE query failed: {exc}")
            return []

        return self._result_to_cwes(result)

    # ── Utility ───────────────────────────────────────────────────────────────

    def reset(self) -> None:
        """Delete and recreate both collections (useful for re-indexing)."""
        self._client.delete_collection(settings.CHROMA_COLLECTION_CVE)
        self._client.delete_collection(settings.CHROMA_COLLECTION_CWE)
        self._cve_col = self._client.get_or_create_collection(
            settings.CHROMA_COLLECTION_CVE, metadata={"hnsw:space": "cosine"}
        )
        self._cwe_col = self._client.get_or_create_collection(
            settings.CHROMA_COLLECTION_CWE, metadata={"hnsw:space": "cosine"}
        )
        logger.warning("Both ChromaDB collections have been reset.")

    # ── Internal deserializers ────────────────────────────────────────────────

    @staticmethod
    def _result_to_cves(result: Dict) -> List[CVEEntry]:
        entries: List[CVEEntry] = []
        metadatas = (result.get("metadatas") or [[]])[0]
        documents = (result.get("documents") or [[]])[0]

        for i, meta in enumerate(metadatas):
            try:
                entries.append(CVEEntry(
                    id=meta.get("id", f"CVE-UNKNOWN-{i}"),
                    description=documents[i] if i < len(documents) else "",
                    severity=Severity(meta.get("severity", "UNKNOWN")),
                    cvss_score=float(meta.get("cvss_score", 0.0)),
                    cwe_ids=json.loads(meta.get("cwe_ids", "[]")),
                    references=json.loads(meta.get("references", "[]")),
                    published=meta.get("published") or None,
                    language_tags=json.loads(meta.get("language_tags", "[]")),
                ))
            except Exception as exc:
                logger.warning(f"Skipping malformed CVE result #{i}: {exc}")

        return entries

    @staticmethod
    def _result_to_cwes(result: Dict) -> List[CWEEntry]:
        entries: List[CWEEntry] = []
        metadatas = (result.get("metadatas") or [[]])[0]
        documents = (result.get("documents") or [[]])[0]

        for i, meta in enumerate(metadatas):
            try:
                entries.append(CWEEntry(
                    id=meta.get("id", f"CWE-{i}"),
                    name=meta.get("name", "Unknown"),
                    description=documents[i] if i < len(documents) else "",
                    mitigations=json.loads(meta.get("mitigations", "[]")),
                    related_weaknesses=json.loads(meta.get("related", "[]")),
                ))
            except Exception as exc:
                logger.warning(f"Skipping malformed CWE result #{i}: {exc}")

        return entries
