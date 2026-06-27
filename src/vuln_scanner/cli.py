"""
cli.py
------
Command-line interface for the vulnerability scanner.

Installed as the `vuln-scan` command via pyproject.toml entry_points.

Usage examples
--------------
  vuln-scan app.py
  vuln-scan app.py --language python --format json
  vuln-scan main.c --output report.json
  vuln-scan app.py --no-llm          # pattern + static only, no Ollama needed
  vuln-scan app.py --model deepseek-coder:6.7b
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vuln-scan",
        description="LLM-based Code Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  vuln-scan app.py
  vuln-scan main.c --language c
  vuln-scan app.py --no-llm --format json --output report.json
  vuln-scan app.py --model deepseek-coder:6.7b
        """,
    )
    parser.add_argument(
        "file",
        help="Path to the source code file to scan.",
    )
    parser.add_argument(
        "--language", "-l",
        default="auto",
        choices=["auto", "python", "c", "cpp", "java", "javascript", "php"],
        help="Programming language (default: auto-detect).",
    )
    parser.add_argument(
        "--format", "-f",
        default="text",
        choices=["text", "json"],
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Write report to this file (default: print to stdout).",
    )
    parser.add_argument(
        "--model", "-m",
        default=None,
        help="Ollama model to use (overrides OLLAMA_MODEL in .env).",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM analysis; run static + pattern matching only.",
    )
    parser.add_argument(
        "--confidence",
        type=float,
        default=None,
        help="Minimum confidence threshold [0.0–1.0] (default: from .env).",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress info-level logging.",
    )
    return parser


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    # ── Apply overrides before importing heavy modules ─────────────────────────
    if args.model:
        os.environ["OLLAMA_MODEL"] = args.model
    if args.no_llm:
        os.environ["SKIP_LLM"] = "true"
    if args.confidence is not None:
        os.environ["CONFIDENCE_THRESHOLD"] = str(args.confidence)
    if args.quiet:
        os.environ["LOG_LEVEL"] = "WARNING"

    # ── Import after env overrides so Settings picks them up ──────────────────
    from .config import settings
    from .core.reporter import ReportGenerator
    from .core.scanner import VulnerabilityScanner

    # ── Validate input file ────────────────────────────────────────────────────
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"[ERROR] File not found: {file_path}", file=sys.stderr)
        sys.exit(1)
    if not file_path.is_file():
        print(f"[ERROR] Not a file: {file_path}", file=sys.stderr)
        sys.exit(1)

    # ── Run scan ───────────────────────────────────────────────────────────────
    scanner  = VulnerabilityScanner()
    reporter = ReportGenerator()

    try:
        result = scanner.scan_file(file_path)
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Scan cancelled.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print(f"[ERROR] Scan failed: {exc}", file=sys.stderr)
        sys.exit(1)

    # ── Output ────────────────────────────────────────────────────────────────
    if args.format == "json":
        output_str = json.dumps(reporter.to_dict(result), indent=2, default=str)
        if args.output:
            Path(args.output).write_text(output_str, encoding="utf-8")
            print(f"Report written to: {args.output}")
        else:
            print(output_str)
    else:
        # Rich text summary
        reporter.print_summary(result)
        if args.output:
            saved = reporter.save_json(result, filename=Path(args.output).name)
            print(f"JSON report saved: {saved}")

    # ── Exit code reflects risk ────────────────────────────────────────────────
    # 0 = no issues, 1 = low, 2 = medium, 3 = high, 4 = critical
    exit_codes = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": 0}
    sys.exit(exit_codes.get(result.overall_risk.value, 0))


if __name__ == "__main__":
    main()
