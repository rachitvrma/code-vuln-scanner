"""
data/nvd_fetcher.py
--------------------
Fetches CVE records from the NIST NVD API v2.0.

Rate limits (as of 2024):
  Without API key : 5 requests / 30 s  → 6.5 s delay between calls
  With API key    : 50 requests / 30 s → 0.7 s delay between calls

Get a free key at: https://nvd.nist.gov/developers/request-an-api-key

Fetched records are cached to data/cve_cache/<keyword>.json so
subsequent runs of setup_db.py don't hit the API again.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List, Optional

import requests
from loguru import logger
from tqdm import tqdm

from ..config import settings
from ..models import CVEEntry, Severity


# ─────────────────────────────────────────────────────────────────────────────
# Constants / helpers
# ─────────────────────────────────────────────────────────────────────────────

_CACHE_DIR = Path(settings.DATA_DIR) / "cve_cache"


def _severity_from_nvd(metrics: Dict) -> tuple[Severity, float]:
    """Extract severity and CVSS base score from NVD metrics block."""
    # Prefer CVSS v3.1, fall back to v3.0, then v2
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            score    = float(data.get("baseScore", 0.0))
            sev_raw  = data.get("baseSeverity", "UNKNOWN").upper()
            sev_map  = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH":     Severity.HIGH,
                "MEDIUM":   Severity.MEDIUM,
                "LOW":      Severity.LOW,
            }
            return sev_map.get(sev_raw, Severity.UNKNOWN), score
    return Severity.UNKNOWN, 0.0


def _parse_cve(raw: Dict) -> Optional[CVEEntry]:
    """Parse a single NVD vulnerability dict into a CVEEntry."""
    try:
        cve   = raw["cve"]
        cve_id = cve["id"]

        # English description
        descs = [d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"]
        description = descs[0] if descs else "(no description)"

        # Severity + CVSS
        severity, cvss = _severity_from_nvd(cve.get("metrics", {}))

        # CWE identifiers
        cwe_ids: List[str] = []
        for weakness in cve.get("weaknesses", []):
            for d in weakness.get("description", []):
                val = d.get("value", "")
                if val.startswith("CWE-"):
                    cwe_ids.append(val)

        # References (first 5)
        references = [r["url"] for r in cve.get("references", [])[:5]]

        return CVEEntry(
            id=cve_id,
            description=description,
            severity=severity,
            cvss_score=cvss,
            cwe_ids=list(set(cwe_ids)),
            references=references,
            published=cve.get("published", ""),
        )
    except (KeyError, TypeError) as exc:
        logger.debug(f"Could not parse CVE entry: {exc}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Fetcher class
# ─────────────────────────────────────────────────────────────────────────────

class NVDFetcher:
    """
    Downloads CVE records from the NVD API and caches them locally.

    Usage::

        fetcher = NVDFetcher()
        cves = fetcher.fetch_by_keyword("SQL injection", max_results=200)
        cves = fetcher.fetch_by_cwe("CWE-89", max_results=100)
    """

    def __init__(self) -> None:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self._headers: Dict[str, str] = {}
        if settings.NVD_API_KEY:
            self._headers["apiKey"] = settings.NVD_API_KEY
            logger.info("NVD API key found — using elevated rate limit.")
        else:
            logger.warning(
                "No NVD API key. Using 6.5 s delay between requests (slow).\n"
                "Set NVD_API_KEY in .env for 8× faster downloads."
            )
        self._delay = 0.7 if settings.NVD_API_KEY else settings.NVD_RATE_LIMIT_DELAY

    # ── Public methods ────────────────────────────────────────────────────────

    def fetch_by_keyword(
        self, keyword: str, max_results: int = 200, use_cache: bool = True
    ) -> List[CVEEntry]:
        """Fetch CVEs matching *keyword* (e.g. 'SQL injection')."""
        cache_key = f"keyword_{keyword.replace(' ', '_').lower()}"
        return self._fetch(
            params={"keywordSearch": keyword},
            cache_key=cache_key,
            max_results=max_results,
            use_cache=use_cache,
        )

    def fetch_by_cwe(
        self, cwe_id: str, max_results: int = 100, use_cache: bool = True
    ) -> List[CVEEntry]:
        """Fetch CVEs associated with *cwe_id* (e.g. 'CWE-89')."""
        cache_key = f"cwe_{cwe_id.replace('-', '_').lower()}"
        return self._fetch(
            params={"cweId": cwe_id},
            cache_key=cache_key,
            max_results=max_results,
            use_cache=use_cache,
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _fetch(
        self,
        params: Dict,
        cache_key: str,
        max_results: int,
        use_cache: bool,
    ) -> List[CVEEntry]:
        cache_path = _CACHE_DIR / f"{cache_key}.json"

        if use_cache and cache_path.exists():
            logger.info(f"Cache hit: {cache_path.name}")
            return self._load_cache(cache_path)

        entries: List[CVEEntry] = []
        start   = 0
        per_page = min(settings.NVD_RESULTS_PER_PAGE, max_results)

        with tqdm(total=max_results, desc=f"NVD {list(params.values())[0]}", unit="CVE") as pbar:
            while len(entries) < max_results:
                batch = self._request_page(params, start, per_page)
                if not batch:
                    break
                entries.extend(batch)
                pbar.update(len(batch))
                start += per_page
                if len(batch) < per_page:
                    break  # last page
                time.sleep(self._delay)

        entries = entries[:max_results]
        self._save_cache(cache_path, entries)
        logger.info(f"Fetched {len(entries)} CVEs → cached to {cache_path.name}")
        return entries

    def _request_page(
        self, params: Dict, start: int, results_per_page: int
    ) -> List[CVEEntry]:
        """Make a single paginated request to the NVD API."""
        full_params = {
            **params,
            "startIndex":     start,
            "resultsPerPage": results_per_page,
        }
        try:
            r = requests.get(
                settings.NVD_API_BASE_URL,
                params=full_params,
                headers=self._headers,
                timeout=30,
            )
            r.raise_for_status()
            data = r.json()
        except requests.exceptions.RequestException as exc:
            logger.error(f"NVD API request failed: {exc}")
            return []

        raw_vulns = data.get("vulnerabilities", [])
        parsed    = [_parse_cve(v) for v in raw_vulns]
        return [e for e in parsed if e is not None]

    @staticmethod
    def _save_cache(path: Path, entries: List[CVEEntry]) -> None:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump([e.model_dump(mode="json") for e in entries], f, indent=2)
        except Exception as exc:
            logger.warning(f"Could not write CVE cache: {exc}")

    @staticmethod
    def _load_cache(path: Path) -> List[CVEEntry]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            return [CVEEntry(**item) for item in raw]
        except Exception as exc:
            logger.warning(f"Could not read CVE cache ({exc}) — re-fetching.")
            return []
