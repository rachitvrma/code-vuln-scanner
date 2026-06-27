"""
rag/embedder.py
---------------
Wraps sentence-transformers to generate dense vector embeddings.

The embeddings are used to:
  1. Represent CVE/CWE descriptions when building the knowledge base.
  2. Represent code snippets at query time to find semantically similar
     vulnerability descriptions via cosine similarity in ChromaDB.

The model is loaded once (singleton) and kept in memory.
"""

from __future__ import annotations

from typing import List

from loguru import logger

from ..config import settings


class CodeEmbedder:
    """
    Singleton wrapper around a SentenceTransformer model.

    Lazy-loads the model on first use so importing the module does not
    trigger a heavy download.

    Usage::

        embedder = CodeEmbedder()
        vec = embedder.embed("SQL injection in Python sqlite3")
        vecs = embedder.embed_batch(["text1", "text2"])
    """

    _instance: "CodeEmbedder | None" = None
    _model = None

    def __new__(cls) -> "CodeEmbedder":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def _load(self) -> None:
        if self._model is not None:
            return
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "sentence-transformers is not installed.\n"
                "Run: pip install sentence-transformers"
            ) from exc

        model_name = settings.EMBEDDING_MODEL
        logger.info(f"Loading embedding model: {model_name}")
        self._model = SentenceTransformer(model_name)
        logger.info("Embedding model ready.")

    def embed(self, text: str) -> List[float]:
        """
        Embed a single text string.

        Returns
        -------
        List[float] — a dense vector (length depends on the model;
        all-MiniLM-L6-v2 → 384 dimensions).
        """
        self._load()
        vec = self._model.encode(text, convert_to_numpy=True, normalize_embeddings=True)
        return vec.tolist()

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """
        Embed a batch of texts (faster than calling embed() in a loop).

        Parameters
        ----------
        texts : List of strings to embed.

        Returns
        -------
        List[List[float]] — one vector per input string.
        """
        if not texts:
            return []
        self._load()
        vecs = self._model.encode(
            texts,
            batch_size=settings.EMBEDDING_BATCH_SIZE,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=len(texts) > 50,
        )
        return [v.tolist() for v in vecs]

    @property
    def dimension(self) -> int:
        """Return the embedding dimensionality (requires model to be loaded)."""
        self._load()
        return self._model.get_sentence_embedding_dimension()
