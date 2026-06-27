"""
config.py
---------
All runtime settings, read from environment variables / .env file.
Importing `settings` from here gives a single, cached Settings object.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from loguru import logger
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# ── Project root (3 levels up from this file: src/vuln_scanner/config.py) ────
BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    """
    Application settings.

    Every field can be overridden by an environment variable with the same name
    (case-insensitive) or by a key in the .env file at the project root.
    """

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Ollama ────────────────────────────────────────────────────────────────
    OLLAMA_BASE_URL: str    = Field(default="http://localhost:11434")
    OLLAMA_MODEL: str       = Field(default="codellama:7b")
    OLLAMA_TIMEOUT: int     = Field(default=180)

    # ── ChromaDB ──────────────────────────────────────────────────────────────
    CHROMA_PERSIST_DIR: str    = Field(default=str(BASE_DIR / "data" / "chromadb"))
    CHROMA_COLLECTION_CVE: str = Field(default="cve_database")
    CHROMA_COLLECTION_CWE: str = Field(default="cwe_database")

    # ── NVD API ───────────────────────────────────────────────────────────────
    NVD_API_KEY: Optional[str] = Field(default=None)
    NVD_API_BASE_URL: str      = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0"
    )
    NVD_RATE_LIMIT_DELAY: float = Field(
        default=6.5,
        description="Seconds between requests. 6.5 s without key, 0.7 s with key.",
    )
    NVD_RESULTS_PER_PAGE: int  = Field(default=100)

    # ── Embeddings ────────────────────────────────────────────────────────────
    EMBEDDING_MODEL: str      = Field(default="all-MiniLM-L6-v2")
    EMBEDDING_BATCH_SIZE: int = Field(default=32)

    # ── Scanner ───────────────────────────────────────────────────────────────
    MAX_CODE_CHUNK_SIZE: int   = Field(default=2000)
    TOP_K_CVE: int             = Field(default=5)
    TOP_K_CWE: int             = Field(default=3)
    CONFIDENCE_THRESHOLD: float = Field(default=0.5)
    SKIP_LLM: bool             = Field(default=False)

    # ── Logging ───────────────────────────────────────────────────────────────
    LOG_LEVEL: str    = Field(default="INFO")
    LOG_FILE: str     = Field(default=str(BASE_DIR / "logs" / "scanner.log"))
    LOG_ROTATION: str = Field(default="10 MB")
    LOG_RETENTION: str = Field(default="1 week")

    # ── Output ────────────────────────────────────────────────────────────────
    REPORT_OUTPUT_DIR: str = Field(default=str(BASE_DIR / "reports"))

    # ── Paths ─────────────────────────────────────────────────────────────────
    DATA_DIR: str     = Field(default=str(BASE_DIR / "data"))
    CWE_XML_PATH: str = Field(default=str(BASE_DIR / "data" / "raw" / "cwec_latest.xml"))
    CWE_ZIP_URL: str  = Field(
        default="https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    )
    CONFIGS_DIR: str  = Field(default=str(BASE_DIR / "configs"))


def _bootstrap_directories(s: Settings) -> None:
    """Create required directories if they don't already exist."""
    dirs = [
        Path(s.CHROMA_PERSIST_DIR),
        Path(s.REPORT_OUTPUT_DIR),
        Path(s.LOG_FILE).parent,
        Path(s.DATA_DIR) / "raw",
        Path(s.DATA_DIR) / "processed",
        Path(s.DATA_DIR) / "cve_cache",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)


def _configure_logging(s: Settings) -> None:
    """Set up Loguru for file + stderr logging."""
    logger.remove()  # remove default handler

    logger.add(
        sys.stderr,
        level=s.LOG_LEVEL,
        format="<green>{time:HH:mm:ss}</green> | <level>{level:<8}</level> | "
               "<cyan>{name}</cyan>:<cyan>{line}</cyan> — <level>{message}</level>",
        colorize=True,
    )
    logger.add(
        s.LOG_FILE,
        level=s.LOG_LEVEL,
        rotation=s.LOG_ROTATION,
        retention=s.LOG_RETENTION,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level:<8} | {name}:{line} — {message}",
        encoding="utf-8",
    )


# ── Singleton ─────────────────────────────────────────────────────────────────
settings = Settings()
_bootstrap_directories(settings)
_configure_logging(settings)
