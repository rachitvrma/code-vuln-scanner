#!/usr/bin/env python3
"""
scripts/setup_db.py
--------------------
One-time setup script: downloads CVE and CWE data and indexes it into ChromaDB.

Run this ONCE before using the scanner for the first time.

Usage
-----
  python scripts/setup_db.py
  python scripts/setup_db.py --reset        # wipe and re-index everything
  python scripts/setup_db.py --cve-only     # only fetch CVEs (skip CWE XML)
  python scripts/setup_db.py --cwe-only     # only parse CWE XML (skip NVD)
  python scripts/setup_db.py --max-cve 50   # fetch fewer CVEs per keyword (faster)

What this script does
---------------------
1. Downloads CWE XML from MITRE (cached to data/raw/cwec_latest.xml)
2. Parses the CWE entries for the vulnerability categories we track
3. Fetches CVEs from NVD API v2.0 by keyword and by CWE ID (cached to data/cve_cache/)
4. Generates embeddings for all CVE / CWE descriptions
5. Upserts everything into ChromaDB (data/chromadb/)

Time estimates (all cached after first run):
  Without NVD API key : ~10–15 min  (rate-limited to 5 req/30 s)
  With NVD API key    : ~1–2 min    (50 req/30 s)
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# ── Make the src/ package importable when run as a script ─────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vuln_scanner.config import settings
from vuln_scanner.data.cwe_parser import CWEParser
from vuln_scanner.data.nvd_fetcher import NVDFetcher
from vuln_scanner.rag.embedder import CodeEmbedder
from vuln_scanner.rag.vectorstore import VectorStore

from loguru import logger
from tqdm import tqdm
import yaml


# ── Load seed configuration from configs/scanner_config.yaml ──────────────────
_CONFIG_PATH = Path(__file__).resolve().parents[1] / "configs" / "scanner_config.yaml"

with open(_CONFIG_PATH) as f:
    _CFG = yaml.safe_load(f)

NVD_KEYWORDS: list[str] = _CFG.get("nvd_seed_keywords", [])
CWE_IDS: list[str]      = _CFG.get("cwe_seed_ids", [])


# ─────────────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Populate the vulnerability knowledge base.")
    p.add_argument("--reset",    action="store_true", help="Wipe ChromaDB and re-index.")
    p.add_argument("--cve-only", action="store_true", help="Only fetch CVE data.")
    p.add_argument("--cwe-only", action="store_true", help="Only parse CWE data.")
    p.add_argument(
        "--max-cve",
        type=int,
        default=100,
        help="Max CVEs to fetch per NVD keyword/CWE query (default: 100).",
    )
    p.add_argument(
        "--no-cache",
        action="store_true",
        help="Ignore local cache and re-download from NVD.",
    )
    return p


def setup_cwes(store: VectorStore, embedder: CodeEmbedder) -> int:
    """Download, parse, embed, and store CWE entries."""
    logger.info("=== CWE Setup ===")
    parser  = CWEParser()
    targets = set(CWE_IDS)
    entries = parser.parse(target_ids=targets)

    if not entries:
        logger.warning("No CWE entries parsed — skipping.")
        return 0

    logger.info(f"Generating embeddings for {len(entries)} CWE entries …")
    texts      = [f"{e.id} {e.name} {e.description}" for e in entries]
    embeddings = embedder.embed_batch(texts)

    return store.add_cwes(entries, embeddings)


def setup_cves(
    store: VectorStore,
    embedder: CodeEmbedder,
    max_per_query: int = 100,
    use_cache: bool = True,
) -> int:
    """Fetch, embed, and store CVE entries from NVD."""
    logger.info("=== CVE Setup ===")
    fetcher  = NVDFetcher()
    all_cves = {}   # keyed by CVE-ID to deduplicate across queries

    # 1. By keyword
    for keyword in tqdm(NVD_KEYWORDS, desc="NVD keyword queries"):
        cves = fetcher.fetch_by_keyword(keyword, max_results=max_per_query, use_cache=use_cache)
        for c in cves:
            all_cves[c.id] = c
        time.sleep(0.1)  # brief pause between queries even with cache

    # 2. By CWE ID
    for cwe_id in tqdm(CWE_IDS, desc="NVD CWE queries"):
        cves = fetcher.fetch_by_cwe(cwe_id, max_results=max_per_query, use_cache=use_cache)
        for c in cves:
            all_cves[c.id] = c
        time.sleep(0.1)

    entries = list(all_cves.values())
    logger.info(f"Total unique CVEs: {len(entries)}")

    if not entries:
        logger.warning("No CVE entries fetched. Check your network and NVD_API_KEY.")
        return 0

    logger.info(f"Generating embeddings for {len(entries)} CVE entries …")
    texts = [
        f"{e.id} {e.severity.value} {' '.join(e.cwe_ids)} {e.description}"
        for e in entries
    ]
    embeddings = embedder.embed_batch(texts)

    return store.add_cves(entries, embeddings)


def main() -> None:
    args    = build_arg_parser().parse_args()
    store   = VectorStore()
    embedder = CodeEmbedder()

    if args.reset:
        logger.warning("Resetting ChromaDB collections …")
        store.reset()

    total_cves = 0
    total_cwes = 0

    if not args.cve_only:
        try:
            total_cwes = setup_cwes(store, embedder)
        except Exception as exc:
            logger.error(f"CWE setup failed: {exc}")

    if not args.cwe_only:
        try:
            total_cves = setup_cves(
                store,
                embedder,
                max_per_query=args.max_cve,
                use_cache=not args.no_cache,
            )
        except Exception as exc:
            logger.error(f"CVE setup failed: {exc}")

    logger.info("=" * 50)
    logger.info(f"Setup complete: {total_cves} CVEs, {total_cwes} CWEs indexed.")
    logger.info(f"ChromaDB stored at: {settings.CHROMA_PERSIST_DIR}")
    logger.info("You can now run the scanner:")
    logger.info("  vuln-scan <file>                         # CLI")
    logger.info("  streamlit run src/vuln_scanner/ui/app.py # Web UI")


if __name__ == "__main__":
    main()
