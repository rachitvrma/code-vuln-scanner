#!/usr/bin/env python3
"""
scripts/fetch_cve_data.py
--------------------------
Selectively fetch or refresh CVE data without re-indexing the CWE database.

Useful when:
  • You want to update the CVE cache after NVD has new entries.
  • You want to add a new keyword without running the full setup.

Usage
-----
  python scripts/fetch_cve_data.py                          # refresh all keywords
  python scripts/fetch_cve_data.py --keyword "path traversal"
  python scripts/fetch_cve_data.py --cwe CWE-89 CWE-78
  python scripts/fetch_cve_data.py --fresh                  # ignore cache
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vuln_scanner.data.nvd_fetcher import NVDFetcher
from vuln_scanner.rag.embedder import CodeEmbedder
from vuln_scanner.rag.vectorstore import VectorStore
from loguru import logger
import yaml


_CONFIG_PATH = Path(__file__).resolve().parents[1] / "configs" / "scanner_config.yaml"
with open(_CONFIG_PATH) as f:
    _CFG = yaml.safe_load(f)


def main() -> None:
    p = argparse.ArgumentParser(description="Fetch CVE data from NVD and (re-)index.")
    p.add_argument("--keyword", "-k", nargs="+", help="Keywords to fetch (e.g. 'SQL injection').")
    p.add_argument("--cwe",     "-c", nargs="+", help="CWE IDs to fetch (e.g. CWE-89 CWE-78).")
    p.add_argument("--max",     "-n", type=int, default=200, help="Max results per query.")
    p.add_argument("--fresh",   action="store_true", help="Ignore local cache, re-download.")
    args = p.parse_args()

    keywords = args.keyword or _CFG.get("nvd_seed_keywords", [])
    cwe_ids  = args.cwe     or _CFG.get("cwe_seed_ids",      [])

    fetcher  = NVDFetcher()
    store    = VectorStore()
    embedder = CodeEmbedder()
    all_cves = {}

    for kw in keywords:
        logger.info(f"Fetching CVEs for keyword: '{kw}' …")
        for c in fetcher.fetch_by_keyword(kw, max_results=args.max, use_cache=not args.fresh):
            all_cves[c.id] = c

    for cwe in cwe_ids:
        logger.info(f"Fetching CVEs for CWE: {cwe} …")
        for c in fetcher.fetch_by_cwe(cwe, max_results=args.max, use_cache=not args.fresh):
            all_cves[c.id] = c

    entries = list(all_cves.values())
    if not entries:
        logger.warning("No CVEs fetched.")
        return

    logger.info(f"Embedding {len(entries)} CVE entries …")
    texts = [
        f"{e.id} {e.severity.value} {' '.join(e.cwe_ids)} {e.description}"
        for e in entries
    ]
    embeddings = embedder.embed_batch(texts)
    added = store.add_cves(entries, embeddings)
    logger.info(f"Done — {added} CVE entries upserted into ChromaDB.")


if __name__ == "__main__":
    main()
