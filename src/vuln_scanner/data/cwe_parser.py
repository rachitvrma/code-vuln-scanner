"""
data/cwe_parser.py
-------------------
Downloads and parses the CWE (Common Weakness Enumeration) XML database
from MITRE and converts entries into CWEEntry objects.

The XML is ~12 MB compressed / ~130 MB uncompressed.
It is cached to data/raw/cwec_latest.xml after the first download.

MITRE CWE download URL:
  https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
"""

from __future__ import annotations

import io
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.request import urlretrieve

import requests
from loguru import logger
from tqdm import tqdm

from ..config import settings
from ..models import CWEEntry


# ─────────────────────────────────────────────────────────────────────────────
# XML namespace
# ─────────────────────────────────────────────────────────────────────────────
# The MITRE CWE XML uses a versioned namespace.
# We use a wildcard approach so it works regardless of version.
_NS_PREFIX = "{http://cwe.mitre.org/cwe-"


def _tag(local: str) -> str:
    """Produce a wildcard-free tag match for any CWE namespace version."""
    return local  # we'll use .find() with local names after stripping NS


def _strip_ns(tag: str) -> str:
    """Remove namespace prefix from an XML tag."""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _find(element: ET.Element, local: str) -> Optional[ET.Element]:
    """Find a direct child by local name, ignoring namespace."""
    for child in element:
        if _strip_ns(child.tag) == local:
            return child
    return None


def _findall(element: ET.Element, local: str) -> List[ET.Element]:
    """Find all direct children by local name, ignoring namespace."""
    return [child for child in element if _strip_ns(child.tag) == local]


def _text(element: Optional[ET.Element]) -> str:
    """Return cleaned text content of an element, or empty string."""
    if element is None:
        return ""
    return " ".join((element.text or "").split())


# ─────────────────────────────────────────────────────────────────────────────
# Parser
# ─────────────────────────────────────────────────────────────────────────────

class CWEParser:
    """
    Downloads and parses MITRE's CWE XML database.

    Usage::

        parser = CWEParser()
        entries = parser.parse(target_ids=["CWE-89", "CWE-78", "CWE-120"])
    """

    def __init__(self) -> None:
        self._xml_path = Path(settings.CWE_XML_PATH)
        self._zip_url  = settings.CWE_ZIP_URL

    def ensure_downloaded(self) -> Path:
        """Download and unzip the CWE XML if not already present."""
        if self._xml_path.exists():
            logger.info(f"CWE XML already present at {self._xml_path}")
            return self._xml_path

        self._xml_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"Downloading CWE database from {self._zip_url} …")

        try:
            r = requests.get(self._zip_url, stream=True, timeout=60)
            r.raise_for_status()
            total = int(r.headers.get("content-length", 0))

            buf = io.BytesIO()
            with tqdm(total=total, unit="B", unit_scale=True, desc="CWE XML") as pbar:
                for chunk in r.iter_content(chunk_size=8192):
                    buf.write(chunk)
                    pbar.update(len(chunk))

            buf.seek(0)
            with zipfile.ZipFile(buf) as zf:
                xml_name = next(n for n in zf.namelist() if n.endswith(".xml"))
                with zf.open(xml_name) as src, open(self._xml_path, "wb") as dst:
                    dst.write(src.read())

            logger.info(f"CWE XML saved to {self._xml_path}")
            return self._xml_path

        except Exception as exc:
            logger.error(f"Failed to download CWE XML: {exc}")
            raise

    def parse(
        self, target_ids: Optional[Set[str]] = None
    ) -> List[CWEEntry]:
        """
        Parse the CWE XML file and return CWEEntry objects.

        Parameters
        ----------
        target_ids : If provided, only parse these CWE IDs (e.g. {"CWE-89"}).
                     If None, parse all weaknesses (can be slow — 900+ entries).

        Returns
        -------
        List[CWEEntry]
        """
        xml_path = self.ensure_downloaded()
        logger.info(f"Parsing CWE XML: {xml_path}")

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
        except ET.ParseError as exc:
            logger.error(f"CWE XML parse error: {exc}")
            return []

        # Navigate to <Weaknesses> container
        weaknesses_el = _find(root, "Weaknesses")
        if weaknesses_el is None:
            logger.error("Could not find <Weaknesses> element in CWE XML.")
            return []

        entries: List[CWEEntry] = []
        for weakness in _findall(weaknesses_el, "Weakness"):
            cwe_id = f"CWE-{weakness.attrib.get('ID', '0')}"
            if target_ids and cwe_id not in target_ids:
                continue

            entry = self._parse_weakness(weakness, cwe_id)
            if entry:
                entries.append(entry)

        logger.info(f"Parsed {len(entries)} CWE entries.")
        return entries

    # ── Internal ──────────────────────────────────────────────────────────────

    def _parse_weakness(self, el: ET.Element, cwe_id: str) -> Optional[CWEEntry]:
        try:
            name = el.attrib.get("Name", "Unknown")

            desc_el = _find(el, "Description")
            description = _text(desc_el)

            ext_el = _find(el, "Extended_Description")
            extended_description = _text(ext_el) if ext_el is not None else None

            # Mitigations
            mitigations: List[str] = []
            mit_container = _find(el, "Potential_Mitigations")
            if mit_container is not None:
                for mit in _findall(mit_container, "Mitigation"):
                    desc = _find(mit, "Description")
                    text = _text(desc)
                    if text:
                        mitigations.append(text[:300])

            # Code examples
            examples: List[str] = []
            ex_container = _find(el, "Demonstrative_Examples")
            if ex_container is not None:
                for ex in _findall(ex_container, "Demonstrative_Example"):
                    body = _find(ex, "Body_Text")
                    text = _text(body)
                    if text:
                        examples.append(text[:400])

            # Related weaknesses
            related: List[str] = []
            rel_container = _find(el, "Related_Weaknesses")
            if rel_container is not None:
                for rw in _findall(rel_container, "Related_Weakness"):
                    rel_id = rw.attrib.get("CWE_ID")
                    if rel_id:
                        related.append(f"CWE-{rel_id}")

            return CWEEntry(
                id=cwe_id,
                name=name,
                description=description or f"Weakness: {name}",
                extended_description=extended_description,
                examples=examples[:3],
                mitigations=mitigations[:5],
                related_weaknesses=related[:5],
            )
        except Exception as exc:
            logger.warning(f"Could not parse {cwe_id}: {exc}")
            return None
