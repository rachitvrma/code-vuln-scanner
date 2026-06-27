#!/usr/bin/env python3
"""
scripts/evaluate.py
--------------------
Measures scanner performance on the labelled fixture files in tests/fixtures/.

For a NIELIT/resume project this gives you real numbers to cite:
  "Achieved 87% precision and 79% recall on our curated test suite."

Ground truth
------------
Each fixture file has a companion <filename>.labels.json that lists the
expected vulnerability types.  Missing label files are skipped gracefully.

Label file format (example: tests/fixtures/vulnerable_code/sql_injection.py.labels.json):
  {
    "expected_vulns": ["SQL Injection"],
    "expected_cwes":  ["CWE-89"],
    "is_vulnerable":  true
  }

Usage
-----
  python scripts/evaluate.py
  python scripts/evaluate.py --dir tests/fixtures/vulnerable_code
  python scripts/evaluate.py --no-llm   # fast run without LLM
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import os
from loguru import logger
from rich.console import Console
from rich.table import Table
from rich import box

_console = Console()


def load_label(code_path: Path) -> Dict:
    """Load the .labels.json companion file for a fixture."""
    label_path = code_path.with_suffix(code_path.suffix + ".labels.json")
    if not label_path.exists():
        return {}
    with open(label_path) as f:
        return json.load(f)


def evaluate_file(
    scanner,
    code_path: Path,
    label: Dict,
) -> Dict:
    """Run the scanner on one file and compare to the expected label."""
    result = scanner.scan_file(code_path)

    found_types = {v.type for v in result.vulnerabilities}
    found_cwes  = {v.cwe_id for v in result.vulnerabilities if v.cwe_id}

    expected_types = set(label.get("expected_vulns", []))
    expected_cwes  = set(label.get("expected_cwes", []))
    is_vulnerable  = label.get("is_vulnerable", True)

    # True positive: expected vuln type is found
    tp_types = found_types & expected_types
    fp_types = found_types - expected_types
    fn_types = expected_types - found_types

    return {
        "file":           code_path.name,
        "is_vulnerable":  is_vulnerable,
        "found_count":    len(result.vulnerabilities),
        "expected_types": list(expected_types),
        "found_types":    list(found_types),
        "tp":             len(tp_types),
        "fp":             len(fp_types),
        "fn":             len(fn_types),
        "scan_time":      result.scan_time,
        "model":          result.model_used,
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Evaluate scanner on fixture files.")
    p.add_argument(
        "--dir", "-d",
        default="tests/fixtures",
        help="Root directory containing fixture files (default: tests/fixtures).",
    )
    p.add_argument(
        "--no-llm", action="store_true", help="Skip LLM analysis (fast)."
    )
    p.add_argument(
        "--output", "-o", default=None, help="Save results as JSON to this file."
    )
    args = p.parse_args()

    if args.no_llm:
        os.environ["SKIP_LLM"] = "true"

    from vuln_scanner.core.scanner import VulnerabilityScanner
    scanner = VulnerabilityScanner()

    fixture_dir = Path(args.dir)
    code_exts   = {".py", ".c", ".cpp", ".java", ".js", ".php"}
    code_files  = [
        f for f in fixture_dir.rglob("*")
        if f.suffix in code_exts and not f.name.endswith(".labels.json")
    ]

    if not code_files:
        logger.warning(f"No fixture files found in {fixture_dir}")
        return

    results = []
    for code_path in sorted(code_files):
        label = load_label(code_path)
        if not label:
            logger.debug(f"No label file for {code_path.name} — skipping.")
            continue
        logger.info(f"Evaluating {code_path.name} …")
        res = evaluate_file(scanner, code_path, label)
        results.append(res)
        _console.print(
            f"  {'✓' if res['tp'] > 0 else '✗'} {code_path.name}: "
            f"TP={res['tp']} FP={res['fp']} FN={res['fn']} "
            f"({res['scan_time']:.1f}s)"
        )

    if not results:
        logger.warning("No labelled fixtures evaluated.")
        return

    # ── Aggregate metrics ──────────────────────────────────────────────────────
    total_tp = sum(r["tp"] for r in results)
    total_fp = sum(r["fp"] for r in results)
    total_fn = sum(r["fn"] for r in results)

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    recall    = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    f1        = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0 else 0.0
    )
    avg_time  = sum(r["scan_time"] for r in results) / len(results)

    table = Table(title="Evaluation Results", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("File",      style="dim")
    table.add_column("TP", justify="right")
    table.add_column("FP", justify="right")
    table.add_column("FN", justify="right")
    table.add_column("Expected",  width=30)
    table.add_column("Found",     width=30)

    for r in results:
        table.add_row(
            r["file"],
            str(r["tp"]), str(r["fp"]), str(r["fn"]),
            ", ".join(r["expected_types"])[:28],
            ", ".join(r["found_types"])[:28],
        )

    _console.print(table)
    _console.print(f"\n[bold]Precision:[/bold] {precision:.2%}")
    _console.print(f"[bold]Recall:   [/bold] {recall:.2%}")
    _console.print(f"[bold]F1 Score: [/bold] {f1:.2%}")
    _console.print(f"[bold]Avg scan: [/bold] {avg_time:.1f}s")

    if args.output:
        out = {
            "summary": {
                "precision": precision, "recall": recall,
                "f1": f1, "avg_scan_time": avg_time,
            },
            "per_file": results,
        }
        Path(args.output).write_text(json.dumps(out, indent=2), encoding="utf-8")
        logger.info(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()
