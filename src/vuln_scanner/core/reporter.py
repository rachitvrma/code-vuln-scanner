"""
core/reporter.py
-----------------
Generates human-readable and machine-readable reports from ScanResult objects.

Supported output formats:
  • JSON   — full structured output (for CI/CD integration)
  • Text   — rich terminal summary (for CLI users)
  • Dict   — plain Python dict (for Streamlit UI)
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from ..models import ScanReport, ScanResult, Severity


# ── Console singleton (no colour when piped to a file) ────────────────────────
_console = Console(highlight=False)

# ── Severity colour map for Rich ──────────────────────────────────────────────
_SEV_COLOUR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "cyan",
    Severity.INFO:     "green",
    Severity.UNKNOWN:  "white",
}


class ReportGenerator:
    """
    Converts a ScanResult into various output formats.

    Usage::

        gen = ReportGenerator()
        gen.print_summary(result)               # rich terminal output
        path = gen.save_json(result)            # writes JSON to disk
        d = gen.to_dict(result)                 # for Streamlit consumption
    """

    def __init__(self, output_dir: Optional[str] = None) -> None:
        from ..config import settings
        self._output_dir = Path(output_dir or settings.REPORT_OUTPUT_DIR)
        self._output_dir.mkdir(parents=True, exist_ok=True)

    # ── Terminal output ───────────────────────────────────────────────────────

    def print_summary(self, result: ScanResult) -> None:
        """Print a coloured summary to stdout using Rich."""
        risk_colour = _SEV_COLOUR.get(result.overall_risk, "white")

        _console.print()
        _console.print(Panel(
            f"[bold]File:[/bold] {result.filename}   "
            f"[bold]Language:[/bold] {result.language.upper()}   "
            f"[bold]Model:[/bold] {result.model_used}   "
            f"[bold]Scan time:[/bold] {result.scan_time:.1f}s",
            title="[bold cyan]🔒 Code Vulnerability Scanner[/bold cyan]",
            border_style="cyan",
        ))

        # ── Overall risk banner ───────────────────────────────────────────────
        _console.print(
            Panel(
                f"[{risk_colour}]● Overall Risk: {result.overall_risk.value}[/{risk_colour}]   "
                f"Critical: {result.critical_count}   High: {result.high_count}   "
                f"Medium: {result.medium_count}   Low: {result.low_count}   "
                f"Total: {result.total_vulnerabilities}",
                border_style=risk_colour,
            )
        )

        if result.error:
            _console.print(f"[bold red]Error:[/bold red] {result.error}")
            return

        if result.total_vulnerabilities == 0:
            _console.print("[bold green]✓ No vulnerabilities detected.[/bold green]\n")
            return

        # ── Vulnerability table ───────────────────────────────────────────────
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
        table.add_column("#",          width=4,  style="dim")
        table.add_column("Severity",   width=10)
        table.add_column("Type",       width=28)
        table.add_column("CWE",        width=10)
        table.add_column("Lines",      width=12)
        table.add_column("Confidence", width=11)
        table.add_column("Source",     width=8, style="dim")

        for i, v in enumerate(result.vulnerabilities, 1):
            colour = _SEV_COLOUR.get(v.severity, "white")
            lines_str = ", ".join(str(ln) for ln in v.line_numbers[:4])
            if len(v.line_numbers) > 4:
                lines_str += "…"
            table.add_row(
                str(i),
                f"[{colour}]{v.severity.value}[/{colour}]",
                v.type,
                v.cwe_id or "—",
                lines_str or "—",
                f"{v.confidence:.0%}",
                v.source,
            )

        _console.print(table)

        # ── Detailed findings ─────────────────────────────────────────────────
        for i, v in enumerate(result.vulnerabilities, 1):
            colour = _SEV_COLOUR.get(v.severity, "white")
            _console.print(
                Panel(
                    f"[bold]{v.description}[/bold]\n\n"
                    f"[yellow]Code:[/yellow]\n{v.code_snippet or '(not extracted)'}\n\n"
                    f"[green]Fix:[/green] {v.remediation}",
                    title=f"[{colour}]{i}. {v.type}[/{colour}]  {v.cwe_id or ''}",
                    border_style=colour,
                    expand=False,
                )
            )

        # ── Static analysis hits ──────────────────────────────────────────────
        if result.static_findings:
            _console.print("\n[bold]Bandit Static Analysis:[/bold]")
            for f in result.static_findings:
                _console.print(
                    f"  L{f.line_number} [{f.severity}] {f.test_name}: {f.issue_text}"
                )
        _console.print()

    # ── JSON export ───────────────────────────────────────────────────────────

    def save_json(self, result: ScanResult, filename: Optional[str] = None) -> Path:
        """
        Save the full scan result as a JSON file.

        Returns
        -------
        Path : Location of the written file.
        """
        if filename is None:
            ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
            stem  = Path(result.filename).stem or "scan"
            filename = f"{stem}_{ts}.json"

        out_path = self._output_dir / filename
        report   = ScanReport(scan_result=result)

        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(report.model_dump(mode="json"), f, indent=2, default=str)
            logger.info(f"Report saved: {out_path}")
        except Exception as exc:
            logger.error(f"Failed to save JSON report: {exc}")

        return out_path

    # ── Dict for Streamlit ────────────────────────────────────────────────────

    def to_dict(self, result: ScanResult) -> dict:
        """Return the scan result as a plain dict (JSON-serialisable)."""
        return result.model_dump(mode="json")
