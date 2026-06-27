"""
ui/app.py
----------
Streamlit web interface for the Code Vulnerability Scanner.

Run with:
    streamlit run src/vuln_scanner/ui/app.py

Features
--------
  • Paste code or upload a file
  • Language auto-detection
  • Live scan progress with spinner
  • Colour-coded severity cards per vulnerability
  • Bandit / pattern-matcher results in expanders
  • JSON export button
  • Knowledge-base status in sidebar
"""

from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

# ── Page config — must be FIRST Streamlit call ────────────────────────────────
st.set_page_config(
    page_title="Code Vulnerability Scanner",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Imports (after page config) ───────────────────────────────────────────────
from ..config import settings
from ..core.reporter import ReportGenerator
from ..core.scanner import VulnerabilityScanner
from ..models import Severity


# ─────────────────────────────────────────────────────────────────────────────
# CSS — cybersecurity dark theme
# ─────────────────────────────────────────────────────────────────────────────

_CSS = """
<style>
  /* Dark background */
  .stApp { background-color: #0d1117; color: #c9d1d9; }
  .main .block-container { padding-top: 1.5rem; max-width: 1200px; }

  /* Severity badge */
  .badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    margin-right: 6px;
  }
  .badge-CRITICAL { background:#ff0040; color:#fff; }
  .badge-HIGH     { background:#e85c00; color:#fff; }
  .badge-MEDIUM   { background:#e5a200; color:#000; }
  .badge-LOW      { background:#1a73e8; color:#fff; }
  .badge-INFO     { background:#28a745; color:#fff; }
  .badge-UNKNOWN  { background:#555;    color:#fff; }

  /* Vuln card */
  .vuln-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 12px;
  }
  .vuln-card-title {
    font-size: 1.05rem;
    font-weight: 700;
    color: #f0f6fc;
    margin-bottom: 6px;
  }
  .vuln-card p { font-size: 0.9rem; color: #8b949e; margin: 4px 0; }
  .vuln-card code {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 6px 10px;
    font-family: 'Courier New', monospace;
    font-size: 0.85rem;
    display: block;
    white-space: pre-wrap;
    color: #79c0ff;
  }
  .fix-box {
    background: #0f2a16;
    border-left: 3px solid #28a745;
    padding: 8px 12px;
    border-radius: 4px;
    font-size: 0.88rem;
    color: #3fb950;
    margin-top: 8px;
  }

  /* Metric card row */
  .metric-row { display: flex; gap: 12px; margin-bottom: 18px; flex-wrap: wrap; }
  .metric-box {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 14px 20px;
    min-width: 110px;
    text-align: center;
  }
  .metric-label { font-size: 0.75rem; color: #8b949e; text-transform: uppercase; }
  .metric-value { font-size: 2rem; font-weight: 700; color: #f0f6fc; }

  /* Header */
  h1 { color: #58a6ff !important; }
  h2, h3 { color: #c9d1d9 !important; }

  /* Code area */
  textarea { font-family: 'Courier New', monospace !important; font-size: 0.85rem !important; }
</style>
"""

st.markdown(_CSS, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Cached resource: scanner (loaded once per session)
# ─────────────────────────────────────────────────────────────────────────────

@st.cache_resource(show_spinner="Initialising scanner …")
def _get_scanner() -> VulnerabilityScanner:
    return VulnerabilityScanner()


@st.cache_resource(show_spinner=False)
def _get_reporter() -> ReportGenerator:
    return ReportGenerator()


# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────

def _badge(severity: str) -> str:
    return f'<span class="badge badge-{severity}">{severity}</span>'


def _sev_colour(severity: str) -> str:
    return {
        "CRITICAL": "#ff0040",
        "HIGH":     "#e85c00",
        "MEDIUM":   "#e5a200",
        "LOW":      "#1a73e8",
        "INFO":     "#28a745",
    }.get(severity, "#555")


def _render_vuln_card(v: dict, index: int) -> None:
    sev  = v.get("severity", "UNKNOWN")
    col  = _sev_colour(sev)
    lines = ", ".join(str(l) for l in (v.get("line_numbers") or []))
    cwe   = v.get("cwe_id") or ""
    cvs   = ", ".join(v.get("cve_references") or [])

    snippet  = v.get("code_snippet", "") or ""
    fix_text = v.get("remediation", "") or ""
    conf     = int(float(v.get("confidence", 0.8)) * 100)

    html = f"""
    <div class="vuln-card" style="border-left: 4px solid {col};">
      <div class="vuln-card-title">
        {_badge(sev)}
        {index}. {v.get('type', 'Unknown Vulnerability')}
        {(' &nbsp; <span style="font-size:0.85rem;color:#8b949e;">' + cwe + '</span>') if cwe else ''}
        &nbsp; <span style="font-size:0.78rem;color:#8b949e;">confidence {conf}%</span>
      </div>
      <p>{v.get('description', '')}</p>
    """
    if lines:
        html += f'<p><b style="color:#c9d1d9;">Lines:</b> {lines}</p>'
    if cvs:
        html += f'<p><b style="color:#c9d1d9;">CVEs:</b> {cvs}</p>'
    if snippet:
        escaped = snippet.replace("<", "&lt;").replace(">", "&gt;")
        html += f'<code>{escaped}</code>'
    if fix_text:
        html += f'<div class="fix-box">✅ Fix: {fix_text}</div>'
    html += "</div>"
    st.markdown(html, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────────────────────

def _render_sidebar() -> None:
    with st.sidebar:
        st.markdown("## ⚙️ Configuration")

        st.markdown(f"**Model:** `{settings.OLLAMA_MODEL}`")
        st.markdown(f"**Embedding:** `{settings.EMBEDDING_MODEL}`")
        st.markdown(f"**Top-K CVE:** {settings.TOP_K_CVE}")
        st.markdown(f"**Confidence threshold:** {settings.CONFIDENCE_THRESHOLD:.0%}")

        st.divider()

        # Knowledge-base status
        st.markdown("#### 📚 Knowledge Base")
        try:
            from ..rag.retriever import CVERetriever
            r = CVERetriever()
            stats = r.knowledge_base_stats()
            st.success(f"CVEs: {stats['cve_count']:,}   CWEs: {stats['cwe_count']:,}")
        except Exception as exc:
            st.warning(f"KB not ready: {exc}")
            st.info("Run `python scripts/setup_db.py` to populate.")

        st.divider()

        # Ollama status
        st.markdown("#### 🤖 Ollama")
        try:
            from ..llm.ollama_client import OllamaClient
            client = OllamaClient()
            if client.health_check():
                models = client.list_models()
                st.success(f"Running  •  {len(models)} model(s) available")
            else:
                st.error("Offline — run `ollama serve`")
        except Exception:
            st.error("Cannot reach Ollama server.")

        st.divider()
        st.caption(
            "**Quick start**\n"
            "```\n"
            "ollama serve\n"
            "ollama pull codellama:7b\n"
            "python scripts/setup_db.py\n"
            "streamlit run src/vuln_scanner/ui/app.py\n"
            "```"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Main app
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    _render_sidebar()

    # ── Header ────────────────────────────────────────────────────────────────
    st.markdown("# 🔒 Code Vulnerability Scanner")
    st.markdown(
        "Powered by **RAG + LLM** (Ollama) over the NVD CVE & MITRE CWE databases. "
        "Paste code or upload a file to scan for security vulnerabilities."
    )
    st.divider()

    # ── Input tabs ────────────────────────────────────────────────────────────
    tab_paste, tab_upload = st.tabs(["📋 Paste Code", "📁 Upload File"])

    code: str = ""
    filename: str = "pasted_code"
    language_hint: str = "auto"

    with tab_paste:
        col_lang, col_empty = st.columns([2, 5])
        with col_lang:
            lang_sel = st.selectbox(
                "Language",
                ["auto", "python", "c", "cpp", "java", "javascript", "php"],
                index=0,
            )
        code_input = st.text_area(
            "Source code",
            height=300,
            placeholder="Paste your source code here …",
            label_visibility="collapsed",
        )
        if code_input.strip():
            code          = code_input
            language_hint = lang_sel

    with tab_upload:
        uploaded = st.file_uploader(
            "Upload a source code file",
            type=["py", "c", "cpp", "h", "java", "js", "php"],
        )
        if uploaded:
            code          = uploaded.read().decode("utf-8", errors="replace")
            filename      = uploaded.name
            language_hint = "auto"
            st.code(code[:1500] + ("…" if len(code) > 1500 else ""), language="python")

    # ── Scan button ───────────────────────────────────────────────────────────
    st.divider()
    col_btn, col_info = st.columns([1, 4])
    with col_btn:
        scan_clicked = st.button("🔍  Scan for Vulnerabilities", type="primary", use_container_width=True)
    with col_info:
        if not code.strip():
            st.info("Paste or upload code, then click Scan.")

    # ── Run scan ──────────────────────────────────────────────────────────────
    if scan_clicked and code.strip():
        scanner  = _get_scanner()
        reporter = _get_reporter()

        with st.spinner("Scanning … this may take 30–120 seconds depending on your model."):
            try:
                result = scanner.scan(code, language=language_hint, filename=filename)
            except Exception as exc:
                st.error(f"Scan failed: {exc}")
                return

        # ── Store in session so we can re-render on re-run ────────────────────
        st.session_state["last_result"] = reporter.to_dict(result)

    # ── Render results ────────────────────────────────────────────────────────
    if "last_result" in st.session_state:
        _render_results(st.session_state["last_result"])


def _render_results(r: dict) -> None:
    """Render a scan result dict to the page."""
    st.divider()
    st.markdown("## 📊 Scan Results")

    error = r.get("error")
    if error:
        st.error(f"Scan error: {error}")

    # ── Summary metrics ───────────────────────────────────────────────────────
    overall_risk = r.get("overall_risk", "INFO")
    risk_col     = _sev_colour(overall_risk)
    total        = r.get("total_vulnerabilities", 0)

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Overall Risk", overall_risk)
    with col2:
        st.metric("Total", total)
    with col3:
        st.metric("🔴 Critical", r.get("critical_count", 0))
    with col4:
        st.metric("🟠 High", r.get("high_count", 0))
    with col5:
        st.metric("🟡 Medium", r.get("medium_count", 0))

    st.divider()

    vulns = r.get("vulnerabilities", [])
    if not vulns:
        st.success("✅ No vulnerabilities detected by LLM analysis.")
    else:
        st.markdown(f"### 🚨 Vulnerabilities ({len(vulns)})")
        for i, v in enumerate(vulns, 1):
            _render_vuln_card(v, i)

    # ── Static analysis expander ──────────────────────────────────────────────
    static = r.get("static_findings", [])
    if static:
        with st.expander(f"🔧 Bandit Static Analysis ({len(static)} findings)"):
            for f in static:
                colour = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}.get(f.get("severity", ""), "⚪")
                st.markdown(
                    f"{colour} **L{f.get('line_number',0)}** "
                    f"[{f.get('severity','')}] `{f.get('test_name','')}` — {f.get('issue_text','')}"
                )

    # ── Pattern-matcher expander ──────────────────────────────────────────────
    patterns = r.get("pattern_matches", [])
    if patterns:
        with st.expander(f"🔍 Pattern Matcher ({len(patterns)} hits)"):
            for p in patterns:
                sev   = p.get("severity", "UNKNOWN")
                lines = ", ".join(str(l) for l in (p.get("line_numbers") or [])[:4])
                st.markdown(
                    f"{_badge(sev)} **{p.get('vulnerability_type','')}** "
                    f"({p.get('cwe_id','')})  lines: {lines}  "
                    f"confidence: {int(p.get('confidence',0)*100)}%",
                    unsafe_allow_html=True,
                )
                st.caption(p.get("description", ""))

    # ── Metadata + export ─────────────────────────────────────────────────────
    with st.expander("📋 Scan Metadata"):
        col_a, col_b, col_c = st.columns(3)
        with col_a:
            st.write(f"**File:** {r.get('filename','')}")
            st.write(f"**Language:** {r.get('language','').upper()}")
        with col_b:
            st.write(f"**Model:** {r.get('model_used','')}")
            st.write(f"**Scan time:** {r.get('scan_time',0):.1f}s")
        with col_c:
            ts = r.get("timestamp", "")
            st.write(f"**Timestamp:** {str(ts)[:19]}")
            st.write(f"**Code hash:** `{str(r.get('code_hash',''))[:12]}…`")

    json_bytes = json.dumps(r, indent=2, default=str).encode("utf-8")
    st.download_button(
        label="⬇️  Export JSON report",
        data=json_bytes,
        file_name=f"vuln_report_{r.get('filename','scan')}.json",
        mime="application/json",
    )


if __name__ == "__main__":
    main()
