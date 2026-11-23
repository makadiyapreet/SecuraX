"""
main.py — SecuraX: Interactive Vulnerability Analysis & Refinement Dashboard.

Launch:
    TOKENIZERS_PARALLELISM=false streamlit run app/main.py
"""

import os
import sys
import time
import difflib
import warnings
import json
from pathlib import Path
from typing import Dict, Any, Optional, List

# ── Suppress noisy tokenizer / model weight / deprecation warnings ────────────
os.environ["TOKENIZERS_PARALLELISM"] = "false"
warnings.filterwarnings("ignore")
import transformers
transformers.logging.set_verbosity_error()

import streamlit as st
import pandas as pd
try:
    from dotenv import load_dotenv
    _has_dotenv = True
except ImportError:
    _has_dotenv = False

# ── Project root setup ────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

if _has_dotenv:
    load_dotenv(PROJECT_ROOT / ".env")

from src.pipeline.language_detector import get_supported_languages
from src.pipeline.securax_pipeline import SecuraXPipeline
from src.data.cwe_taxonomy import CLASS_NAMES, CWE_METADATA, CWE_SEMANTIC_GROUPS

# ══════════════════════════════════════════════════════════════════════════════
# PAGE CONFIG
# ══════════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="SecuraX — AI Vulnerability Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ══════════════════════════════════════════════════════════════════════════════
# CUSTOM CSS — Modern Professional Design
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
/* ── Import Google Font ─────────────────────────────────────────── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

/* ── Global Overrides ───────────────────────────────────────────── */
html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
}
.block-container {
    padding-top: 5.5rem !important;
    padding-bottom: 4rem !important;
    max-width: 1400px;
}
header[data-testid="stHeader"] {
    background: rgba(255, 255, 255, 0.90) !important;
    backdrop-filter: blur(12px) !important;
    -webkit-backdrop-filter: blur(12px) !important;
    border-bottom: 1px solid rgba(226, 232, 240, 0.6);
    z-index: 999 !important;
    height: 3.5rem;
}

/* ── Hero Banner ────────────────────────────────────────────────── */
.hero-banner {
    background: linear-gradient(135deg, #0F172A 0%, #1E293B 50%, #0F172A 100%);
    border-radius: 16px;
    padding: 2.2rem 2.5rem;
    margin-top: 0.6rem;
    margin-bottom: 1.6rem;
    position: relative;
    overflow: hidden;
    border: 1px solid rgba(99,102,241,0.25);
    box-shadow: 0 10px 25px -5px rgba(15, 23, 42, 0.3);
}
.hero-banner::before {
    content: '';
    position: absolute;
    top: -50%;
    right: -20%;
    width: 400px;
    height: 400px;
    background: radial-gradient(circle, rgba(99,102,241,0.15) 0%, transparent 70%);
    border-radius: 50%;
}
.hero-banner::after {
    content: '';
    position: absolute;
    bottom: -60%;
    left: -10%;
    width: 300px;
    height: 300px;
    background: radial-gradient(circle, rgba(139,92,246,0.1) 0%, transparent 70%);
    border-radius: 50%;
}
.hero-title {
    font-size: 1.95rem;
    font-weight: 800;
    color: white;
    margin-bottom: 0.35rem;
    position: relative;
    z-index: 1;
    letter-spacing: -0.02em;
    line-height: 1.35;
    padding-top: 4px;
}
.hero-title span.accent {
    background: linear-gradient(135deg, #818CF8, #A78BFA, #C084FC);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.hero-sub {
    font-size: 0.9rem;
    color: #94A3B8;
    position: relative;
    z-index: 1;
    letter-spacing: 0.01em;
}
.hero-badges {
    display: flex;
    gap: 8px;
    margin-top: 0.8rem;
    position: relative;
    z-index: 1;
    flex-wrap: wrap;
}
.hero-badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    background: rgba(255,255,255,0.06);
    border: 1px solid rgba(255,255,255,0.1);
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 0.72rem;
    color: #CBD5E1;
    font-weight: 500;
    backdrop-filter: blur(4px);
}

/* ── Section Headers ────────────────────────────────────────────── */
.section-hdr {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 1.15rem;
    font-weight: 700;
    color: #1E293B;
    margin: 1.6rem 0 0.8rem 0;
    padding-bottom: 8px;
    border-bottom: 2px solid #E2E8F0;
}
.section-hdr .icon {
    width: 32px;
    height: 32px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 8px;
    font-size: 1rem;
}
.section-hdr .icon.blue   { background: #EEF2FF; color: #4F46E5; }
.section-hdr .icon.green  { background: #F0FDF4; color: #16A34A; }
.section-hdr .icon.purple { background: #FAF5FF; color: #9333EA; }
.section-hdr .icon.red    { background: #FEF2F2; color: #DC2626; }
.section-hdr .icon.amber  { background: #FFFBEB; color: #D97706; }

/* ── KPI Metric Cards ──────────────────────────────────────────── */
.kpi-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    margin-bottom: 1.2rem;
}
.kpi-card {
    background: white;
    border: 1px solid #E2E8F0;
    border-radius: 12px;
    padding: 16px 18px;
    transition: box-shadow 0.2s, transform 0.2s;
}
.kpi-card:hover {
    box-shadow: 0 4px 12px rgba(0,0,0,0.06);
    transform: translateY(-1px);
}
.kpi-label {
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #64748B;
    margin-bottom: 4px;
    display: flex;
    align-items: center;
    gap: 6px;
}
.kpi-value {
    font-size: 1.6rem;
    font-weight: 800;
    color: #0F172A;
    line-height: 1.2;
}
.kpi-value.red    { color: #DC2626; }
.kpi-value.green  { color: #16A34A; }
.kpi-value.blue   { color: #2563EB; }
.kpi-value.purple { color: #7C3AED; }
.kpi-sub {
    font-size: 0.72rem;
    color: #94A3B8;
    margin-top: 2px;
    font-weight: 500;
}

/* ── VF Badges ──────────────────────────────────────────────────── */
.vf-badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 4px 12px;
    border-radius: 6px;
    font-size: 0.78rem;
    font-weight: 700;
    white-space: nowrap;
}
.vf-vuln {
    background: #FEE2E2;
    color: #991B1B;
    border: 1px solid #FECACA;
}
.vf-safe {
    background: #DCFCE7;
    color: #166534;
    border: 1px solid #BBF7D0;
}
.vf-defended {
    background: #FEF3C7;
    color: #92400E;
    border: 1px solid #FDE68A;
}

/* ── Severity Pill ──────────────────────────────────────────────── */
.sev-pill {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 700;
}
.sev-critical { background: #7F1D1D; color: #FEE2E2; }
.sev-high     { background: #DC2626; color: white; }
.sev-medium   { background: #F59E0B; color: #1E293B; }
.sev-low      { background: #16A34A; color: white; }
.sev-info     { background: #64748B; color: white; }

/* ── Attention Score Bar ────────────────────────────────────────── */
.attr-bar-wrap {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 4px 0;
    padding: 6px 10px;
    border-radius: 8px;
    background: #F8FAFC;
    border: 1px solid #E2E8F0;
}
.attr-line-num {
    font-size: 0.75rem;
    font-weight: 700;
    color: #64748B;
    min-width: 50px;
}
.attr-bar {
    height: 6px;
    border-radius: 3px;
    background: linear-gradient(90deg, #EF4444, #F97316);
    transition: width 0.6s ease;
}
.attr-bar-bg {
    flex: 0 0 100px;
    height: 6px;
    border-radius: 3px;
    background: #E2E8F0;
    position: relative;
    overflow: hidden;
}
.attr-score {
    font-size: 0.72rem;
    font-weight: 700;
    color: #DC2626;
    min-width: 36px;
    text-align: right;
}
.attr-code {
    flex: 1;
    font-family: 'SF Mono', 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 0.78rem;
    color: #334155;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

/* ── Self-Verification Status Card ──────────────────────────────── */
.sv-card {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    border-radius: 10px;
    margin-bottom: 12px;
    font-size: 0.85rem;
    font-weight: 600;
}
.sv-pass1 {
    background: linear-gradient(135deg, #F0FDF4, #DCFCE7);
    border: 1px solid #86EFAC;
    color: #166534;
}
.sv-pass2 {
    background: linear-gradient(135deg, #EFF6FF, #DBEAFE);
    border: 1px solid #93C5FD;
    color: #1E40AF;
}
.sv-improved {
    background: linear-gradient(135deg, #FFFBEB, #FEF3C7);
    border: 1px solid #FCD34D;
    color: #92400E;
}
.sv-unresolved {
    background: linear-gradient(135deg, #FFF7ED, #FED7AA);
    border: 1px solid #FDBA74;
    color: #9A3412;
}

/* ── Snippet Inspector Cards ────────────────────────────────────── */
div[data-testid="stExpander"] {
    border: 1px solid #E2E8F0;
    border-radius: 12px;
    margin-bottom: 8px;
    overflow: hidden;
}
div[data-testid="stExpander"] > details > summary {
    font-weight: 600;
    font-size: 0.92rem;
}

/* ── Tab Styling ────────────────────────────────────────────────── */
div[data-baseweb="tab-list"] {
    gap: 4px;
    border-bottom: 2px solid #E2E8F0;
    padding-bottom: 0px;
    margin-bottom: 1.4rem;
    overflow-x: auto;
    white-space: nowrap;
}
button[data-baseweb="tab"] {
    font-weight: 600;
    font-size: 0.88rem;
    padding: 10px 18px;
    border-radius: 8px 8px 0 0;
    color: #64748B;
    background: transparent;
    border: 1px solid transparent;
    border-bottom: none;
    transition: all 0.2s ease;
}
button[data-baseweb="tab"]:hover {
    color: #4F46E5;
    background: #F8FAFC;
}
button[data-baseweb="tab"][aria-selected="true"] {
    color: #4F46E5 !important;
    background: #FFFFFF !important;
    border-color: #CBD5E1 #CBD5E1 transparent #CBD5E1 !important;
    border-bottom: 3px solid #4F46E5 !important;
    font-weight: 700 !important;
    box-shadow: 0 -2px 8px rgba(0,0,0,0.03);
}

/* ── Sidebar ────────────────────────────────────────────────────── */
section[data-testid="stSidebar"] > div:first-child {
    padding-top: 0.5rem;
}
.sb-brand {
    text-align: center;
    padding: 1.2rem 0.8rem;
    margin-bottom: 0.5rem;
    background: linear-gradient(135deg, #0F172A, #1E293B);
    border-radius: 12px;
}
.sb-brand h2 {
    font-size: 1.45rem;
    font-weight: 800;
    margin: 0;
    color: white;
    letter-spacing: -0.02em;
}
.sb-brand h2 span {
    background: linear-gradient(135deg, #818CF8, #C084FC);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.sb-brand p {
    color: #94A3B8;
    font-size: 0.75rem;
    margin: 2px 0 0 0;
    font-weight: 500;
}
.sb-section {
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #94A3B8;
    margin: 1rem 0 0.5rem 0;
    padding-top: 0.5rem;
    border-top: 1px solid #E2E8F0;
}

/* ── Footer ─────────────────────────────────────────────────────── */
.app-footer {
    background: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-radius: 12px;
    padding: 16px 20px;
    margin-top: 2rem;
    font-size: 0.78rem;
    color: #64748B;
    line-height: 1.6;
}
.app-footer strong { color: #475569; }

/* ── Misc ───────────────────────────────────────────────────────── */
.code-label {
    font-size: 0.78rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #64748B;
    margin-bottom: 6px;
}
.diff-container pre {
    border-radius: 8px;
}
.empty-state {
    text-align: center;
    padding: 3rem 1rem;
    color: #94A3B8;
    font-size: 0.95rem;
}
.empty-state .icon { font-size: 2.5rem; margin-bottom: 0.5rem; }

/* ── CWE Knowledge Base & Defenses Studio ────────────────────────── */
.cwe-card {
    background: white;
    border: 1px solid #E2E8F0;
    border-radius: 12px;
    padding: 1.2rem 1.4rem;
    margin-bottom: 1rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.03);
    transition: all 0.2s ease;
}
.cwe-card:hover {
    border-color: #CBD5E1;
    box-shadow: 0 4px 12px rgba(0,0,0,0.06);
    transform: translateY(-1px);
}
.cwe-badge-id {
    display: inline-flex;
    align-items: center;
    background: #EEF2FF;
    color: #4338CA;
    border: 1px solid #C7D2FE;
    font-weight: 700;
    font-size: 0.75rem;
    padding: 3px 8px;
    border-radius: 6px;
    font-family: monospace;
}
.cwe-badge-group {
    display: inline-flex;
    align-items: center;
    background: #F1F5F9;
    color: #475569;
    font-size: 0.72rem;
    padding: 3px 8px;
    border-radius: 6px;
    font-weight: 600;
}
.defense-card {
    background: #FAFAFA;
    border: 1px solid #E2E8F0;
    border-left: 4px solid #10B981;
    border-radius: 10px;
    padding: 1.1rem 1.3rem;
    margin-bottom: 1rem;
}
.defense-tag {
    display: inline-block;
    padding: 3px 9px;
    border-radius: 6px;
    font-size: 0.72rem;
    font-weight: 700;
    background: #DCFCE7;
    color: #15803D;
    margin-right: 6px;
}
.schema-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: 20px;
    background: #F1F5F9;
    border: 1px solid #E2E8F0;
    color: #475569;
    font-family: monospace;
    font-size: 0.75rem;
    font-weight: 600;
    margin-bottom: 0.8rem;
}
</style>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# CACHED PIPELINE SINGLETON
# ══════════════════════════════════════════════════════════════════════════════
@st.cache_resource(show_spinner="⚙️ Loading SecuraX neural models & API client…")
def get_pipeline() -> SecuraXPipeline:
    return SecuraXPipeline()

pipeline = get_pipeline()


# ══════════════════════════════════════════════════════════════════════════════
# SESSION STATE DEFAULTS
# ══════════════════════════════════════════════════════════════════════════════
_defaults = {
    "input_code": "",
    "input_filename": None,
    "paste_area": "",
    "results": None,
    "scan_history": [],
}
for k, v in _defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ══════════════════════════════════════════════════════════════════════════════
# CURATED EXAMPLES
# ══════════════════════════════════════════════════════════════════════════════
EXAMPLES = {
    "C — Buffer Overflow": {
        "filename": "vuln_buffer.c",
        "lang_hint": "c",
        "icon": "🔴",
        "desc": "Unbounded strcpy into fixed-size stack buffer",
        "code": """\
#include <stdio.h>
#include <string.h>

void safe_helper(int count) {
    if (count > 0) printf("Processed items: %d\\n", count);
}

void parse_packet(char *network_payload) {
    char stack_buf[16];
    // Vulnerable: unbounded memory copy
    strcpy(stack_buf, network_payload);
    printf("Payload received: %s\\n", stack_buf);
}
""",
    },
    "Python — SQL Injection": {
        "filename": "db_auth.py",
        "lang_hint": "python",
        "icon": "🟡",
        "desc": "f-string interpolation in SQL query",
        "code": """\
import sqlite3

def get_status(conn):
    return "Database connection active"

def authenticate_user(conn, username, password):
    cursor = conn.cursor()
    # Vulnerable: string interpolation in SQL command
    query = f"SELECT id, role FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    return cursor.fetchone()
""",
    },
    "PHP — Cross-Site Scripting": {
        "filename": "render_view.php",
        "lang_hint": "php",
        "icon": "🟠",
        "desc": "Unescaped user input echoed to DOM",
        "code": """\
<?php
function log_visit($ip) {
    file_put_contents('visit.log', $ip . PHP_EOL, FILE_APPEND);
}

function render_greeting($user_name) {
    // Vulnerable: echoing untrusted parameter directly into DOM
    echo "<h1>Welcome back, " . $user_name . "!</h1>";
}
?>
""",
    },
    "JavaScript — Command Injection": {
        "filename": "server_exec.js",
        "lang_hint": "javascript",
        "icon": "🔵",
        "desc": "Unsanitized input passed to child_process.exec",
        "code": """\
const { exec } = require('child_process');

function pingServer(userSuppliedHost) {
    // Vulnerable: shell execution with unescaped parameter
    const cmd = "ping -c 2 " + userSuppliedHost;
    exec(cmd, (err, stdout, stderr) => {
        if (err) console.error(err);
        console.log(stdout);
    });
}
""",
    },
    "C++ — Out-of-Bounds": {
        "filename": "metrics.cpp",
        "lang_hint": "cpp",
        "icon": "🟣",
        "desc": "Direct vector indexing without bounds check",
        "code": """\
#include <vector>
#include <iostream>

int read_metric(const std::vector<int>& data, int index) {
    // Vulnerable: direct indexing without length verification
    return data[index];
}
""",
    },
    "Go — Path Traversal": {
        "filename": "file_server.go",
        "lang_hint": "go",
        "icon": "🟢",
        "desc": "Unsanitized path concatenation passed to os.ReadFile",
        "code": """\
package main

import (
    "os"
)

func ReadReport(name string) ([]byte, error) {
    // Vulnerable: path traversal concatenation
    return os.ReadFile("/var/reports/" + name)
}
""",
    },
    "Java — Weak Crypto": {
        "filename": "AuthDigest.java",
        "lang_hint": "java",
        "icon": "☕",
        "desc": "Use of cryptographically broken MD5 message digest",
        "code": """\
import java.security.MessageDigest;

public class AuthDigest {
    public static byte[] hashPassword(byte[] password) throws Exception {
        // Vulnerable: MD5 is cryptographically broken
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password);
    }
}
""",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# HELPER: severity band + CSS class
# ══════════════════════════════════════════════════════════════════════════════
def severity_pill(score: Optional[float], band: str = "?") -> str:
    if score is None:
        return '<span class="sev-pill sev-info">N/A</span>'
    cls = "sev-info"
    if score >= 9.0:
        cls = "sev-critical"
    elif score >= 7.0:
        cls = "sev-high"
    elif score >= 4.0:
        cls = "sev-medium"
    elif score >= 0.1:
        cls = "sev-low"
    return f'<span class="sev-pill {cls}">{score:.1f} — {band}</span>'


# ══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("""
    <div class="sb-brand">
        <h2>🛡️ Secura<span>X</span></h2>
        <p>AI-Powered Vulnerability Intelligence</p>
    </div>
    """, unsafe_allow_html=True)

    # ── Language Routing ──
    st.markdown('<div class="sb-section">🌐 Language Routing</div>', unsafe_allow_html=True)
    supported_langs = get_supported_languages()
    lang_options = ["Auto-Detect"] + supported_langs
    selected_lang = st.selectbox(
        "Source Language",
        options=lang_options,
        index=0,
        help="Auto-detects via Pygments lexer analysis; override to force a specific detection tier.",
        label_visibility="collapsed",
    )

    # ── Refinement Settings ──
    st.markdown('<div class="sb-section">🔧 Refinement Engine</div>', unsafe_allow_html=True)
    refinement_cap = st.slider(
        "Max Refinements per Run",
        min_value=1, max_value=50, value=20,
        help="Limits Groq API calls per analysis run to protect free-tier quota.",
    )

    active_model = st.selectbox(
        "Groq Model",
        options=["qwen/qwen3.8-27b", "openai/gpt-oss-120b", "llama-3.3-70b-versatile"],
        index=0,
        help="Open-weight LLM served on Groq LPU for secure code repair generation.",
    )
    pipeline.groq_client.model = active_model

    # ── Phase 7 Stretch Features ──
    st.markdown('<div class="sb-section">🧪 Stretch Goals</div>', unsafe_allow_html=True)
    enable_sv = st.toggle(
        "🔄 Self-Verification Loop",
        value=False,
        help="After patch generation, re-runs neural detector + static analysis. If residual risk detected, re-prompts LLM with diagnostic feedback (adds ~2-4s latency per snippet).",
    )
    show_explainability = st.checkbox(
        "🔍 Attention Line Attribution",
        value=True,
        help="Highlights top suspicious lines and renders heatmap using AttentionPooling weights from Phase 1 model.",
    )

    # ── System Status ──
    st.markdown('<div class="sb-section">📡 System Status</div>', unsafe_allow_html=True)
    api_ok = pipeline.groq_client.is_available
    n_keys = len(pipeline.groq_client.api_keys)
    if api_ok:
        st.success(f"✅ Groq API Connected — {n_keys} key{'s' if n_keys > 1 else ''} in failover pool")
    else:
        st.error("❌ Groq API Key Missing — set GROQ_API_KEY in .env")

    dev = pipeline.model_manager.device.type.upper()
    st.info(f"💻 Inference Device: **{dev}** {'(Apple Silicon)' if dev == 'MPS' else ''}")

    # ── Clear Cache ──
    st.markdown('<div class="sb-section">🗂️ Cache Management</div>', unsafe_allow_html=True)
    if st.button("🗑️ Clear Groq Response Cache", width="stretch"):
        cache_dir = pipeline.groq_client.cache.cache_dir
        count = len(list(cache_dir.glob("*.json")))
        for f in cache_dir.glob("*.json"):
            f.unlink()
        st.toast(f"Cleared {count} cached Groq responses.", icon="🗑️")

    # ── About ──
    with st.expander("ℹ️ About SecuraX"):
        st.markdown("""
        **SecuraX** is an AI-based framework for automated source code vulnerability detection,
        multi-class CWE classification, CVSS severity scoring, and LLM-assisted code repair.

        **Architecture:**
        - Phase 1–3: Fine-tuned GraphCodeBERT + CodeT5 (local PyTorch)
        - Phase 4: Groq-hosted LLM repair (open-weight models)
        - Phase 7: Self-verification loop + attention explainability

        **Supported Languages:** C, C++, Python, PHP, JavaScript, Go, Java, Ruby, TypeScript

        **Constraint Exception:** Groq is a hosted API serving open-weight models on a free tier.
        """)


# ══════════════════════════════════════════════════════════════════════════════
# HERO BANNER
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="hero-banner">
    <div class="hero-title">🛡️ SecuraX — <span class="accent">Vulnerability Intelligence</span></div>
    <div class="hero-sub">
        Language-routed vulnerability detection · CWE classification · CVSS severity scoring · LLM-powered code repair
    </div>
    <div class="hero-badges">
        <span class="hero-badge">🧠 GraphCodeBERT + CodeT5</span>
        <span class="hero-badge">⚡ Groq LPU Inference</span>
        <span class="hero-badge">🌐 10+ Languages</span>
        <span class="hero-badge">🔄 Self-Verification</span>
        <span class="hero-badge">🔍 Explainability</span>
    </div>
</div>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN CONTENT TABS (4 Dedicated Modules)
# ══════════════════════════════════════════════════════════════════════════════
tab_analyze, tab_results, tab_bench, tab_reference = st.tabs([
    "🔬 Analyze Code",
    "📊 Scan Results & Inspector",
    "🧪 Test Bench & Catalog",
    "ℹ️ Architecture & Reference",
])

# ──────────────────────────────────────────────────────────────────────────────
# TAB 1: ANALYZE CODE
# ──────────────────────────────────────────────────────────────────────────────
with tab_analyze:
    st.markdown("""
    <div class="section-hdr">
        <span class="icon blue">📥</span> Input Source Code
    </div>
    """, unsafe_allow_html=True)

    input_tab_upload, input_tab_paste, input_tab_examples = st.tabs([
        "📁 Upload File",
        "✍️ Paste Code",
        "💡 Quick Examples",
    ])

    with input_tab_upload:
        uploaded = st.file_uploader(
            "Drag & drop a source file",
            type=["c", "cpp", "h", "hpp", "py", "php", "js", "ts", "go", "java", "rb"],
            help="Supported formats: C, C++, Python, PHP, JavaScript, TypeScript, Go, Java, Ruby",
        )
        if uploaded is not None:
            raw = uploaded.read()
            if b"\x00" in raw[:1024]:
                st.error("⚠️ Binary file detected — please upload plain-text source code.")
            else:
                decoded = raw.decode("utf-8", errors="replace")
                st.session_state.input_code = decoded
                st.session_state.input_filename = uploaded.name
                n_lines = len(decoded.splitlines())
                st.success(f"✅ Loaded **{uploaded.name}** — {n_lines} lines, ready to analyze")

    with input_tab_paste:
        col_paste_hdr, col_paste_clear = st.columns([4, 1])
        with col_paste_hdr:
            st.caption("Paste source code directly or choose a quick test template below:")
        with col_paste_clear:
            if st.button("🧹 Clear Input", key="btn_clear_input", width="stretch"):
                st.session_state.input_code = ""
                st.session_state.input_filename = None
                st.session_state.results = None
                if "paste_area" in st.session_state:
                    st.session_state["paste_area"] = ""
                st.rerun()

        # Quick Load Templates
        col_t1, col_t2, col_t3, col_t4, col_t5 = st.columns(5)
        with col_t1:
            if st.button("🐍 SQLi (Py)", key="tpl_sqli", width="stretch", help="Load Python SQL Injection (CWE-89) sample"):
                st.session_state.input_code = 'import sqlite3\n\ndef search_users(username):\n    conn = sqlite3.connect("app.db")\n    cursor = conn.cursor()\n    # Vulnerable: string formatting into SQL query\n    query = f"SELECT * FROM users WHERE username = \'{username}\'"\n    return cursor.execute(query).fetchall()\n'
                st.session_state.input_filename = "user_lookup.py"
                st.session_state.results = None
                st.session_state["paste_area"] = st.session_state.input_code
                st.rerun()
        with col_t2:
            if st.button("🐘 XSS (PHP)", key="tpl_xss", width="stretch", help="Load PHP Cross-Site Scripting (CWE-79) sample"):
                st.session_state.input_code = '<?php\nfunction render_greeting($user_name) {\n    // Vulnerable: echoing untrusted parameter directly into DOM\n    echo "<h1>Welcome back, " . $user_name . "!</h1>";\n}\n?>'
                st.session_state.input_filename = "greeting.php"
                st.session_state.results = None
                st.session_state["paste_area"] = st.session_state.input_code
                st.rerun()
        with col_t3:
            if st.button("⚡ Exec (JS)", key="tpl_cmd", width="stretch", help="Load JavaScript OS Command Injection (CWE-78) sample"):
                st.session_state.input_code = 'const { exec } = require("child_process");\n\nfunction pingHost(target) {\n    // Vulnerable: shell execution with unescaped parameter\n    exec("ping -c 1 " + target, (err, stdout) => {\n        console.log(stdout);\n    });\n}\n'
                st.session_state.input_filename = "net_diag.js"
                st.session_state.results = None
                st.session_state["paste_area"] = st.session_state.input_code
                st.rerun()
        with col_t4:
            if st.button("🛡️ Safe Upload (PHP)", key="tpl_safe_php", width="stretch", help="Load PHP Secure Upload (Hard-Negative Safe Control) sample"):
                st.session_state.input_code = '<?php\nfunction uploadFile($file) {\n    $allowed = ["jpg", "png", "gif"];\n    $ext = pathinfo($file["name"], PATHINFO_EXTENSION);\n    if (in_array(strtolower($ext), $allowed, true)) {\n        if (mime_content_type($file["tmp_name"]) === "image/jpeg") {\n            $dest = "uploads/" . uniqid("img_") . "." . $ext;\n            move_uploaded_file($file["tmp_name"], $dest);\n            return true;\n        }\n    }\n    return false;\n}\n?>'
                st.session_state.input_filename = "secure_upload.php"
                st.session_state.results = None
                st.session_state["paste_area"] = st.session_state.input_code
                st.rerun()
        with col_t5:
            if st.button("☕ Deser (Java)", key="tpl_deser", width="stretch", help="Load Java Insecure Deserialization (CWE-502) sample"):
                st.session_state.input_code = 'import java.io.*;\n\npublic class DataHandler {\n    public static Object readPayload(byte[] bytes) throws Exception {\n        // Vulnerable: ObjectInputStream without ObjectInputFilter\n        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);\n        ObjectInputStream ois = new ObjectInputStream(bais);\n        return ois.readObject();\n    }\n}\n'
                st.session_state.input_filename = "DataHandler.java"
                st.session_state.results = None
                st.session_state["paste_area"] = st.session_state.input_code
                st.rerun()

        pasted = st.text_area(
            "Paste source code below",
            height=220,
            placeholder="Paste C, Python, PHP, JavaScript, Go, Java, or C++ code here…",
            key="paste_area",
        )
        if pasted and pasted.strip():
            st.session_state.input_code = pasted.strip()
            if not st.session_state.input_filename:
                st.session_state.input_filename = "pasted_code"

    with input_tab_examples:
        st.caption("Click any example to load it into the analyzer:")
        cols = st.columns(len(EXAMPLES))
        for i, (label, data) in enumerate(EXAMPLES.items()):
            with cols[i]:
                if st.button(
                    f"{data['icon']}\n{label.split('—')[0].strip()}",
                    key=f"ex_{i}",
                    width="stretch",
                    help=data["desc"],
                ):
                    st.session_state.input_code = data["code"]
                    st.session_state.input_filename = data["filename"]
                    st.session_state["paste_area"] = data["code"]
                    st.session_state.results = None
                    st.rerun()

    # ── Preview loaded code ──
    if st.session_state.input_code.strip():
        st.markdown("---")
        fname = st.session_state.input_filename or "pasted_code"
        ext = fname.rsplit(".", 1)[-1] if "." in fname else "text"
        lang_map = {"c": "c", "cpp": "cpp", "py": "python", "php": "php", "js": "javascript",
                     "go": "go", "java": "java", "rb": "ruby", "ts": "typescript"}
        preview_lang = lang_map.get(ext, "text")

        col_preview, col_meta = st.columns([3, 1])
        with col_preview:
            st.markdown(f'<div class="code-label">📄 {fname}</div>', unsafe_allow_html=True)
            st.code(st.session_state.input_code, language=preview_lang, line_numbers=True)
        with col_meta:
            lines = st.session_state.input_code.strip().splitlines()
            st.metric("Lines of Code", len(lines))
            st.metric("Characters", len(st.session_state.input_code))
            if st.session_state.input_filename:
                st.caption(f"**File:** `{st.session_state.input_filename}`")

    # ── Run button ──
    st.markdown("")
    col_btn, col_spacer = st.columns([1, 2])
    with col_btn:
        run_clicked = st.button(
            "🚀 Run SecuraX Pipeline",
            type="primary",
            width="stretch",
            disabled=not st.session_state.input_code.strip(),
        )

    if run_clicked and st.session_state.input_code.strip():
        with st.status("🔬 Executing SecuraX Analysis Pipeline…", expanded=True) as status:
            st.write("🌐 **Step 1/5** — Detecting source language & routing to trained tier…")
            time.sleep(0.2)
            st.write("🧩 **Step 2/5** — Parsing code into function-level chunks…")
            time.sleep(0.15)
            st.write("🔬 **Step 3/5** — Running Phase 1 binary vulnerability detection…")
            time.sleep(0.15)
            st.write("🏷️ **Step 4/5** — Classifying CWE types & scoring CVSS severity…")
            time.sleep(0.1)
            st.write("🔧 **Step 5/5** — Generating secure refinements via Groq LPU…")

            results = pipeline.analyze_source(
                code=st.session_state.input_code,
                filename=st.session_state.input_filename,
                language_override=selected_lang,
                refinement_cap=refinement_cap,
                enable_self_verification=enable_sv,
            )
            st.session_state.results = results

            # Add to scan history
            if results["success"]:
                st.session_state.scan_history.append({
                    "time": time.strftime("%H:%M:%S"),
                    "language": results["language"],
                    "functions": results["total_functions"],
                    "vulnerable": results["vulnerable_count"],
                    "elapsed": results["elapsed_seconds"],
                })

            if results["success"]:
                status.update(
                    label=f"✅ Analysis Complete — {results['vulnerable_count']} vulnerable, {results['safe_count']} safe ({results['elapsed_seconds']:.1f}s)",
                    state="complete",
                    expanded=False,
                )
            else:
                status.update(label="❌ Analysis Failed", state="error", expanded=True)

        if results["success"]:
            st.markdown("---")
            st.markdown("""
            <div class="section-hdr">
                <span class="icon green">✅</span> Scan Analysis Results
            </div>
            """, unsafe_allow_html=True)

            q_c1, q_c2, q_c3, q_c4 = st.columns(4)
            q_c1.metric("Language", results["language"], results["tier"] or "Standard Tier")
            q_c2.metric("Total Functions", results["total_functions"])
            q_c3.metric("Vulnerable Flagged", results["vulnerable_count"], f"{results['vulnerable_count']} flagged")
            q_c4.metric("Safe / Defended", results["safe_count"], "Clean / Verified")

            if results["rows"]:
                df_prev = pd.DataFrame(results["rows"])
                def style_vf_prev(val):
                    if val == "Vulnerable":
                        return "background-color: #FEE2E2; color: #991B1B; font-weight: bold;"
                    elif val == "Controls detected - likely safe":
                        return "background-color: #FEF3C7; color: #92400E; font-weight: 600;"
                    elif val == "Safe":
                        return "background-color: #DCFCE7; color: #166534; font-weight: 600;"
                    return ""

                styled_prev = df_prev.style.map(style_vf_prev, subset=["VF"])
                st.dataframe(
                    styled_prev,
                    width="stretch",
                    hide_index=True,
                    height=min(350, 48 + 38 * len(df_prev)),
                )

                col_dl, col_nav = st.columns([1, 2])
                with col_dl:
                    st.download_button(
                        "📥 Download CSV Report",
                        df_prev.to_csv(index=False),
                        file_name=f"securax_{results['language'].lower()}.csv",
                        mime="text/csv",
                        width="stretch",
                    )
                with col_nav:
                    st.info("💡 **Deep Analysis:** Open **📊 Results Dashboard** for full KPIs and exports, or **🔎 Code Inspector** for side-by-side patch diffs and attention heatmaps.")


# ══════════════════════════════════════════════════════════════════════════════
# HELPER: Formal Security Advisory Generator (.md)
# ══════════════════════════════════════════════════════════════════════════════
def _generate_security_advisory_markdown(results: Dict[str, Any]) -> str:
    lang = results.get("language", "Unknown")
    total = results.get("total_functions", 0)
    vuln = results.get("vulnerable_count", 0)
    safe = results.get("safe_count", 0)
    patched = results.get("refined_count", 0)
    elapsed = results.get("elapsed_seconds", 0.0)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        f"# SecuraX Automated Vulnerability Assessment & Advisory Report",
        f"",
        f"**Generated:** {timestamp}  ",
        f"**Author / Researcher:** Preet Makadiya (B.Tech Minor Project)  ",
        f"**Project Advisor:** [GUIDE_NAME], [INSTITUTE_NAME]  ",
        f"**Analyzed Language:** `{lang}` ({results.get('tier') or 'Standard Tier'})  ",
        f"**Analysis Execution Time:** {elapsed:.2f} seconds  ",
        f"",
        f"---",
        f"",
        f"## 1. Executive Summary",
        f"",
        f"SecuraX performed automated static and neural vulnerability analysis across `{total}` extracted code units.",
        f"",
        f"| Metric | Value | Interpretation |",
        f"|---|---|---|",
        f"| **Total Functions Analyzed** | `{total}` | Code segments parsed via AST/brace parser |",
        f"| **Vulnerable Identified** | `{vuln}` | Flagged exceeding calibrated threshold |",
        f"| **Safe / Controls Verified** | `{safe}` | Below threshold or verified hard-negative defenses |",
        f"| **Automated LLM Patches** | `{patched}` | Secure remediations generated via Groq open-weight LLMs |",
        f"| **Vulnerability Density** | `{(vuln / max(total, 1)):.1%}` | Proportion of codebase flagged with security weaknesses |",
        f"",
        f"---",
        f"",
        f"## 2. Assessment Findings Summary (Standard 7-Column Schema)",
        f"",
        f"| PL | Snippet | Verdict (VF) | CWE Classification | Refined Code Status | LOC | CVSS Severity |",
        f"|---|---|---|---|---|:---:|:---:|",
    ]

    for row in results.get("rows", []):
        pl = row.get("PL", lang)
        snip = f"`{row.get('Snippet', 'fn')}()`"
        vf = row.get("VF", "Unknown")
        cwe = row.get("CWE-id", "N/A")
        raw_ref = str(row.get("Refined Code", "Safe"))
        ref_status = "Patch Generated" if ("function" in raw_ref.lower() or "def" in raw_ref.lower() or len(raw_ref) > 40) else (raw_ref[:35] + "...")
        loc_val = row.get("LOC", 0)
        sev_val = row.get("Severity Score", "N/A")
        lines.append(f"| {pl} | {snip} | **{vf}** | `{cwe}` | {ref_status} | {loc_val} | `{sev_val}` |")

    lines.extend([
        f"",
        f"---",
        f"",
        f"## 3. Detailed Vulnerability Analyses & LLM Remediations",
        f"",
    ])

    for item in results.get("details", []):
        fn_name = item.get("name", "anonymous")
        idx = item.get("index", 1)
        is_vuln = item.get("is_vulnerable", False)
        vf_str = item.get("vf_label", "Vulnerable" if is_vuln else "Safe")
        override = item.get("override_applied", False)

        lines.append(f"### Finding #{idx}: `{fn_name}()` — {vf_str}")
        lines.append(f"")
        lines.append(f"- **Verdict (VF):** `{vf_str}`")
        lines.append(f"- **LOC:** `{item.get('loc', 0)}` lines")

        if is_vuln:
            cwe_id = item.get("cwe_id", "CWE-Unknown")
            sem_group = item.get("semantic_group", "General Weakness")
            cwe_meta = CWE_METADATA.get(cwe_id, {})
            cwe_name = cwe_meta.get("name", sem_group)
            cwe_desc = cwe_meta.get("desc", "No description available.")
            sev_score = item.get("severity_score", 5.0)
            sev_band = item.get("severity_band", "Medium")
            prob = item.get("prob_vuln", 0.0)

            lines.append(f"- **MITRE Weakness:** `{cwe_id}`: **{cwe_name}** (Semantic Group: `{sem_group}`)")
            lines.append(f"- **Weakness Description:** {cwe_desc}")
            lines.append(f"- **Neural Detector Confidence:** `{prob:.1%}`")
            lines.append(f"- **Predicted CVSS 3.1 Severity:** `{sev_score:.1f}/10.0` (**{sev_band.upper()}**)")
            lines.append(f"")
            lines.append(f"#### Original Code:")
            lines.append(f"```{lang.lower()}")
            lines.append(item.get("original_code", "").strip())
            lines.append(f"```")
            lines.append(f"")
            lines.append(f"#### Remediated Secure Patch (Groq LPU):")
            lines.append(f"```{lang.lower()}")
            lines.append(item.get("refined_code", "").strip())
            lines.append(f"```")

            sv = item.get("self_verification")
            if sv:
                lines.append(f"")
                lines.append(f"> **Automated Post-Patch Verification:** Status: `{sv.get('status')}` (Pass 1 prob: `{sv.get('pass1_prob', 0):.1%}` → Pass 2 prob: `{sv.get('pass2_prob', 0):.1%}`)")

            diff_text = "".join(difflib.unified_diff(
                item["original_code"].splitlines(keepends=True),
                item["refined_code"].splitlines(keepends=True),
                fromfile=f"a/{fn_name}",
                tofile=f"b/{fn_name}",
                n=3,
            ))
            if diff_text:
                lines.append(f"")
                lines.append(f"#### Unified Diff:")
                lines.append(f"```diff")
                lines.append(diff_text.strip())
                lines.append(f"```")

        elif override:
            lines.append(f"> 🛡️ **Defensive Security Controls Active:** Neural raw probability: `{item.get('neural_prob')}`.")
            lines.append(f"> **Verified Defensive Pattern:** {item.get('override_reason')}")
            lines.append(f"")
            lines.append(f"```{lang.lower()}")
            lines.append(item.get("original_code", "").strip())
            lines.append(f"```")
        else:
            lines.append(f"- Function classified **Safe** by neural detector (sub-threshold).")
            lines.append(f"")
            lines.append(f"```{lang.lower()}")
            lines.append(item.get("original_code", "").strip())
            lines.append(f"```")

        lines.append(f"")
        lines.append(f"---")
        lines.append(f"")

    lines.extend([
        f"## 4. Architectural Disclosure & Integrity Statement",
        f"",
        f"- **Model Framework:** Local fine-tuned GraphCodeBERT & CodeT5 on PyTorch (CPU deterministic inference).",
        f"- **Repair Engine:** Hosted Groq LPU serving open-weight models (`qwen/qwen3.8-27b`).",
        f"- **Neuro-Symbolic Reporting:** Verified defensive patterns are labeled `Controls detected - likely safe`.",
        f"- **Certification:** Generated by **SecuraX** research framework — Preet Makadiya (B.Tech Minor Project).",
        f"",
    ])

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# HELPER: Deep Code Inspector & Heatmap Renderer
# ══════════════════════════════════════════════════════════════════════════════
def _render_code_inspector(results: Dict[str, Any], refinement_cap: int, pipeline: SecuraXPipeline, enable_sv: bool, show_explainability: bool):
    st.markdown("""
    <div class="section-hdr">
        <span class="icon red">🔎</span> Detailed Snippet & Patch Inspection
    </div>
    """, unsafe_allow_html=True)

    filter_opt = st.radio(
        "Filter Functions:",
        ["All Functions", "🚨 Vulnerable Only", "✅ Safe Only"],
        horizontal=True,
        label_visibility="collapsed",
    )

    details = results.get("details", [])
    if not details:
        st.info("No extracted functions available to inspect.")
        return

    for item in details:
        idx = item["index"]
        name = item["name"]
        is_vuln = item["is_vulnerable"]
        loc_val = item["loc"]
        ref_code = item["refined_code"]

        # Apply filter
        if filter_opt == "🚨 Vulnerable Only" and not is_vuln:
            continue
        if filter_opt == "✅ Safe Only" and is_vuln:
            continue

        vf_str = item.get("vf_label", "Vulnerable" if is_vuln else "Safe")
        is_override = item.get("override_applied", False)

        if is_vuln:
            badge = "🚨 VULNERABLE"
            label = f"#{idx} · `{name}()` — 🚨 Vulnerable · LOC: {loc_val}"
        elif is_override or "likely safe" in vf_str.lower():
            badge = "🛡️ CONTROLS DETECTED"
            label = f"#{idx} · `{name}()` — 🛡️ Controls detected - likely safe · LOC: {loc_val}"
        else:
            badge = "✅ SAFE"
            label = f"#{idx} · `{name}()` — ✅ Safe · LOC: {loc_val}"

        with st.expander(label, expanded=is_vuln):
            if is_override or "likely safe" in vf_str.lower():
                st.markdown(f"""
                <div style="background: linear-gradient(135deg, #FEF3C7, #FFFBEB); border: 1px solid #FCD34D; border-left: 4px solid #D97706; padding: 10px 14px; border-radius: 8px; margin-bottom: 12px; color: #92400E; font-size: 0.85rem;">
                    🛡️ <strong>Defensive Security Controls Active:</strong> Neural raw vulnerability probability: <code>{item.get('neural_prob', 'N/A')}</code>.<br>
                    <strong>Verified Security Control:</strong> <em>{item.get('override_reason', 'Defensive guard pattern detected')}</em>
                </div>
                """, unsafe_allow_html=True)

            # ── Self-Verification Badge ───────────────────────
            sv_info = item.get("self_verification")
            if sv_info and is_vuln:
                sv_status = sv_info.get("status", "")
                if sv_status == "verified_safe_pass1":
                    st.markdown(
                        '<div class="sv-card sv-pass1">🛡️ <strong>Verified Safe (Pass 1)</strong> — '
                        'Neural detector & static analysis confirmed patch is secure.</div>',
                        unsafe_allow_html=True,
                    )
                elif sv_status == "self_corrected_pass2":
                    prob_r = sv_info.get("prob_reduction", 0.0)
                    extra_t = sv_info.get("extra_tokens", 0)
                    st.markdown(
                        f'<div class="sv-card sv-pass2">⚡ <strong>Self-Corrected (Pass 2)</strong> — '
                        f'Pass 1 rejected → re-prompted with diagnostics. '
                        f'Prob Δ: -{prob_r:.1%} | Extra tokens: {extra_t}</div>',
                        unsafe_allow_html=True,
                    )
                elif sv_status == "improved_pass2":
                    p2 = sv_info.get("pass2_prob", 0.0)
                    st.markdown(
                        f'<div class="sv-card sv-improved">📈 <strong>Improved (Pass 2)</strong> — '
                        f'Vulnerability probability reduced to {p2:.1%}, but threshold not yet crossed.</div>',
                        unsafe_allow_html=True,
                    )
                elif sv_status in ("unresolved_pass2", "reverted_to_pass1"):
                    p2 = sv_info.get("pass2_prob", sv_info.get("pass1_prob", 0.0))
                    st.markdown(
                        f'<div class="sv-card sv-unresolved">⚠️ <strong>Unresolved</strong> — '
                        f'Residual risk after Pass 2 (p={p2:.1%}). Best-effort patch provided.</div>',
                        unsafe_allow_html=True,
                    )

            # ── Two-column: Original vs Patched ───────────────
            col_l, col_r = st.columns(2)

            with col_l:
                st.markdown('<div class="code-label">📄 Original Code</div>', unsafe_allow_html=True)
                st.code(item["original_code"], language=item["language"].lower(), line_numbers=True)

                if is_vuln:
                    prob = item.get("prob_vuln", 0.0)
                    cwe = item.get("cwe_id", "?")
                    sev = item.get("severity_score")
                    band = item.get("severity_band", "?")

                    tag_cols = st.columns(3)
                    tag_cols[0].markdown(f"**Confidence:** `{prob:.1%}`")
                    tag_cols[1].markdown(f"**CWE:** `{cwe}`")
                    if sev is not None:
                        tag_cols[2].markdown(
                            f'**Severity:** {severity_pill(sev, band)}',
                            unsafe_allow_html=True,
                        )

                    # ── CVSS 3.1 Severity Gauge & Range Description ──
                    if sev is not None:
                        if sev >= 9.0:
                            gauge_color = "#991B1B"
                            range_label = "CRITICAL"
                            range_desc = "🚨 <strong>Critical (9.0 – 10.0):</strong> Catastrophic severity; exploitable without authentication, allows full system takeover or data exfiltration."
                        elif sev >= 7.0:
                            gauge_color = "#DC2626"
                            range_label = "HIGH"
                            range_desc = "🔴 <strong>High (7.0 – 8.9):</strong> Severe impact; enables arbitrary code execution, SQL injection, or significant privilege escalation."
                        elif sev >= 4.0:
                            gauge_color = "#D97706"
                            range_label = "MEDIUM"
                            range_desc = "🟡 <strong>Medium (4.0 – 6.9):</strong> Moderate impact; typical for reflected XSS, sensitive information disclosure, or requires user interaction."
                        elif sev >= 0.1:
                            gauge_color = "#16A34A"
                            range_label = "LOW"
                            range_desc = "🟢 <strong>Low (0.1 – 3.9):</strong> Minimal impact; requires high administrative privileges, local physical access, or minor denial of service."
                        else:
                            gauge_color = "#64748B"
                            range_label = "NONE"
                            range_desc = "⚪ <strong>None (0.0):</strong> No actionable security vulnerability detected."

                        sev_pct = min(100, max(5, int((sev / 10.0) * 100)))

                        st.markdown(f"""
                        <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 10px 14px; margin-top: 10px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                                <span style="font-size: 0.76rem; font-weight: 700; color: #475569;">CVSS 3.1 BASE SCORE:</span>
                                <span style="font-size: 0.95rem; font-weight: 800; color: {gauge_color};">{sev:.1f} / 10.0 ({range_label})</span>
                            </div>
                            <div style="width: 100%; height: 8px; background: #E2E8F0; border-radius: 4px; overflow: hidden; margin-bottom: 6px;">
                                <div style="width: {sev_pct}%; height: 100%; background: {gauge_color}; border-radius: 4px; transition: width 0.5s ease;"></div>
                            </div>
                            <div style="font-size: 0.74rem; color: #475569; line-height: 1.4;">
                                {range_desc}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)

                        with st.expander("ℹ️ CVSS 3.1 Severity Rating Scale Guide", expanded=False):
                            st.markdown("""
                            | Rating Band | Score Range | Description & Typical Vulnerabilities |
                            |---|:---:|---|
                            | 🟢 **Low** | `0.1 – 3.9` | Minimal impact; attacker needs high local privileges or physical access. |
                            | 🟡 **Medium** | `4.0 – 6.9` | Moderate impact; reflected XSS, directory browsing, or requires social engineering. |
                            | 🔴 **High** | `7.0 – 8.9` | High impact; SQL injection, unauthenticated SSRF, local privilege escalation. |
                            | 🚨 **Critical** | `9.0 – 10.0` | Critical exploitability; unauthenticated remote code execution (RCE), full system takeover. |
                            """)

            with col_r:
                st.markdown('<div class="code-label">🔧 Refined Code</div>', unsafe_allow_html=True)
                if is_vuln:
                    if "Refinement cap reached" in ref_code or "Refinement unavailable" in ref_code:
                        st.warning(ref_code)
                        if st.button(f"⚡ Refine {name}() Now", key=f"od_{idx}"):
                            with st.spinner("Calling Groq LLM…"):
                                od = pipeline.refine_single_snippet_on_demand(
                                    snippet_code=item["original_code"],
                                    language=item["language"],
                                    cwe_id=item.get("cwe_id", "CWE-Unknown"),
                                    semantic_group=item.get("semantic_group"),
                                    severity_score=item.get("severity_score"),
                                    tier=item.get("tier"),
                                    enable_self_verification=enable_sv,
                                )
                                if od["success"]:
                                    st.success("✅ Patch generated!")
                                    st.code(od["refined_code"], language=item["language"].lower(), line_numbers=True)
                                else:
                                    st.error(f"Refinement failed: {od.get('error')}")
                    else:
                        st.code(ref_code, language=item["language"].lower(), line_numbers=True)

                        # ── Download Patched Code & .patch file ────────
                        ext_map = {"python": "py", "c": "c", "cpp": "cpp", "php": "php", "javascript": "js", "typescript": "ts", "go": "go", "java": "java", "ruby": "rb"}
                        ext_cur = ext_map.get(item["language"].lower(), "txt")
                        diff_patch = "".join(difflib.unified_diff(
                            item["original_code"].splitlines(keepends=True),
                            ref_code.splitlines(keepends=True),
                            fromfile=f"a/{name}.{ext_cur}",
                            tofile=f"b/{name}.{ext_cur}",
                            n=3,
                        ))
                        col_dl_fix, col_dl_patch = st.columns(2)
                        with col_dl_fix:
                            st.download_button(
                                "💾 Download Fixed Code",
                                ref_code,
                                file_name=f"{name}_fixed.{ext_cur}",
                                mime="text/plain",
                                key=f"dl_fix_{idx}",
                                width="stretch",
                            )
                        with col_dl_patch:
                            st.download_button(
                                "📝 Download .patch File",
                                diff_patch or f"# No modifications between original and patch for {name}",
                                file_name=f"{name}_fix.patch",
                                mime="text/x-diff",
                                key=f"dl_patch_{idx}",
                                width="stretch",
                            )
                else:
                    st.info("Function classified **safe** — no patch required.")

            # ── Phase 7 Option C: Attention Explainability ────
            if is_vuln and show_explainability and item.get("explainability"):
                exp = item["explainability"]
                top_lines = exp.get("top_lines", [])

                st.markdown("---")
                st.markdown("""
                <div class="section-hdr" style="margin-top:0.5rem;">
                    <span class="icon amber">🔍</span> Line-Level Vulnerability Attribution
                </div>
                """, unsafe_allow_html=True)
                st.caption("AttentionPooling weights — higher score = more influential for vulnerability prediction")

                if top_lines:
                    for tl in top_lines[:5]:
                        score_pct = tl["score"]
                        bar_w = max(5, int(score_pct * 100))
                        line_text = tl.get("text", "").strip()
                        st.markdown(f"""
                        <div class="attr-bar-wrap">
                            <span class="attr-line-num">Line {tl['line_no']}</span>
                            <div class="attr-bar-bg">
                                <div class="attr-bar" style="width:{bar_w}%;"></div>
                            </div>
                            <span class="attr-score">{score_pct:.0%}</span>
                            <span class="attr-code">{line_text}</span>
                        </div>
                        """, unsafe_allow_html=True)

                if exp.get("html_heatmap"):
                    with st.expander("📊 Full Attention Heatmap", expanded=False):
                        st.html(exp["html_heatmap"], width="stretch")

            # ── Self-Verification Diagnostics ─────────────────
            if sv_info and sv_info.get("attempts", 1) > 1:
                with st.expander("🛠️ Self-Verification Diagnostics"):
                    d_cols = st.columns(4)
                    d_cols[0].metric("Status", sv_info.get("status", "—"))
                    d_cols[1].metric("Pass 1 p(vuln)", f"{sv_info.get('pass1_prob', 0):.1%}")
                    d_cols[2].metric("Pass 2 p(vuln)", f"{sv_info.get('pass2_prob', 0):.1%}")
                    d_cols[3].metric("Extra Tokens", sv_info.get("extra_tokens", 0))

                    if sv_info.get("feedback"):
                        st.markdown("**Feedback Prompt Sent to LLM:**")
                        st.code(sv_info["feedback"], language="text")

            # ── Unified Diff ──────────────────────────────────
            if is_vuln and not ("Refinement cap reached" in ref_code or "Refinement unavailable" in ref_code):
                with st.expander("📝 Unified Diff", expanded=False):
                    diff = difflib.unified_diff(
                        item["original_code"].splitlines(keepends=True),
                        ref_code.splitlines(keepends=True),
                        fromfile=f"{name}_original",
                        tofile=f"{name}_patched",
                        n=3,
                    )
                    diff_text = "".join(diff)
                    if diff_text:
                        st.code(diff_text, language="diff")
                    else:
                        st.caption("No textual differences between original and patch.")


# ──────────────────────────────────────────────────────────────────────────────
# TAB 2: SCAN RESULTS & INSPECTOR
# ──────────────────────────────────────────────────────────────────────────────
with tab_results:
    results = st.session_state.results

    if results is None:
        st.markdown("""
        <div class="empty-state">
            <div class="icon">📊</div>
            <div style="font-size: 1.15rem; font-weight: 700; color: #1E293B; margin-bottom: 6px;">No scan results available yet</div>
            <div style="color: #64748B; margin-bottom: 20px;">Run an analysis in the <strong>🔬 Analyze Code</strong> tab, or load a quick test case below to inspect live results:</div>
        </div>
        """, unsafe_allow_html=True)
        col_s1, col_s2, col_s3, col_s4 = st.columns(4)
        with col_s1:
            if st.button("🐍 Load Python SQLi", key="res_empty_sqli", width="stretch"):
                st.session_state.input_code = EXAMPLES["Python — SQL Injection"]["code"]
                st.session_state.input_filename = EXAMPLES["Python — SQL Injection"]["filename"]
                st.session_state.results = None
                st.rerun()
        with col_s2:
            if st.button("🐘 Load PHP XSS", key="res_empty_xss", width="stretch"):
                st.session_state.input_code = EXAMPLES["PHP — Cross-Site Scripting"]["code"]
                st.session_state.input_filename = EXAMPLES["PHP — Cross-Site Scripting"]["filename"]
                st.session_state.results = None
                st.rerun()
        with col_s3:
            if st.button("⚡ Load JS Command Exec", key="res_empty_cmd", width="stretch"):
                st.session_state.input_code = EXAMPLES["JavaScript — Command Injection"]["code"]
                st.session_state.input_filename = EXAMPLES["JavaScript — Command Injection"]["filename"]
                st.session_state.results = None
                st.rerun()
        with col_s4:
            if st.button("🛡️ Load PHP Safe Control", key="res_empty_safe", width="stretch"):
                st.session_state.input_code = '<?php\nfunction uploadFile($file) {\n    $allowed = ["jpg", "png", "gif"];\n    $ext = pathinfo($file["name"], PATHINFO_EXTENSION);\n    if (in_array(strtolower($ext), $allowed, true)) {\n        if (mime_content_type($file["tmp_name"]) === "image/jpeg") {\n            $dest = "uploads/" . uniqid("img_") . "." . $ext;\n            move_uploaded_file($file["tmp_name"], $dest);\n            return true;\n        }\n    }\n    return false;\n}\n?>'
                st.session_state.input_filename = "secure_upload.php"
                st.session_state.results = None
                st.rerun()

    elif not results.get("success", False):
        st.error(f"**Analysis Failed:** {results.get('error', 'Unknown execution error')}")

    else:
        # ── KPI Metric Cards ──────────────────────────────────────
        vuln_pct = (results['vulnerable_count'] / max(results['total_functions'], 1)) * 100

        st.markdown(f"""
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-label">🌐 Language</div>
                <div class="kpi-value blue">{results['language']}</div>
                <div class="kpi-sub">{results['tier'] or 'Standard'}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">📦 Functions Analyzed</div>
                <div class="kpi-value">{results['total_functions']}</div>
                <div class="kpi-sub">Extracted via AST/brace parser</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">🚨 Vulnerable</div>
                <div class="kpi-value red">{results['vulnerable_count']}</div>
                <div class="kpi-sub">{vuln_pct:.0f}% of functions flagged</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">✅ Safe / Defended</div>
                <div class="kpi-value green">{results['safe_count']}</div>
                <div class="kpi-sub">Below threshold / Verified controls</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">🔧 Patched</div>
                <div class="kpi-value purple">{results['refined_count']}</div>
                <div class="kpi-sub">{results['elapsed_seconds']:.1f}s total</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        if results.get("cap_hit"):
            st.warning(
                f"⚠️ Refinement cap ({refinement_cap}) reached. "
                "Remaining vulnerable functions can be refined on-demand in the Deep Code Inspector tab below."
            )

        # ── Two Integrated Sub-Tabs: Table vs Deep Inspector ───────
        res_sub_table, res_sub_inspector = st.tabs([
            "📋 Vulnerability Report Table",
            "🔎 Deep Code Inspector & Heatmap",
        ])

        with res_sub_table:
            st.markdown("""
            <div class="schema-pill">
                📌 Mandatory Output Schema: <code>PL | Snippet | VF | CWE-id | Refined Code | LOC | Severity Score</code>
            </div>
            """, unsafe_allow_html=True)

            if results.get("rows"):
                df = pd.DataFrame(results["rows"])

                column_config = {
                    "PL": st.column_config.TextColumn("Language", width="small", help="Detected source code programming language"),
                    "Snippet": st.column_config.TextColumn("Function / Symbol", width="medium", help="Extracted function or code snippet identifier"),
                    "VF": st.column_config.TextColumn("Verdict (VF)", width="small", help="Binary vulnerability classification (Safe vs Vulnerable vs Controls detected)"),
                    "CWE-id": st.column_config.TextColumn("CWE Classification", width="medium", help="MITRE CWE identifier and category name"),
                    "Refined Code": st.column_config.TextColumn("Refined Code Summary", width="large", help="LLM-assisted security patch or verification status"),
                    "LOC": st.column_config.NumberColumn("LOC", width="small", help="Lines of code analyzed"),
                    "Severity Score": st.column_config.TextColumn("CVSS Score", width="small", help="Predicted continuous CVSS severity score out of 10.0"),
                }

                def style_vf(val):
                    if val == "Vulnerable":
                        return "background-color: #FEE2E2; color: #991B1B; font-weight: bold;"
                    elif val == "Controls detected - likely safe":
                        return "background-color: #FEF3C7; color: #92400E; font-weight: 600;"
                    elif val == "Safe":
                        return "background-color: #DCFCE7; color: #166534; font-weight: 600;"
                    return ""

                styled = df.style.map(style_vf, subset=["VF"])
                st.dataframe(
                    styled,
                    column_config=column_config,
                    width="stretch",
                    hide_index=True,
                    height=min(450, 48 + 38 * len(df)),
                )

                col_down_csv, col_down_json, col_down_advisory = st.columns(3)
                with col_down_csv:
                    csv_data = df.to_csv(index=False)
                    st.download_button(
                        "📥 Download CSV Report",
                        csv_data,
                        file_name=f"securax_results_{results['language'].lower()}.csv",
                        mime="text/csv",
                        width="stretch",
                        key="btn_dl_results_csv",
                    )
                with col_down_json:
                    json_data = json.dumps(results, indent=2, default=str)
                    st.download_button(
                        "📋 Export JSON Data",
                        json_data,
                        file_name=f"securax_scan_{results['language'].lower()}.json",
                        mime="application/json",
                        width="stretch",
                        key="btn_dl_results_json",
                    )
                with col_down_advisory:
                    advisory_md = _generate_security_advisory_markdown(results)
                    st.download_button(
                        "📄 Export Security Advisory (.md)",
                        advisory_md,
                        file_name=f"SECURAX_ADVISORY_{results['language'].upper()}_{time.strftime('%Y%m%d_%H%M%S')}.md",
                        mime="text/markdown",
                        width="stretch",
                        key="btn_dl_advisory_md",
                    )
                st.caption("💡 **Tip:** Switch to the **🔎 Deep Code Inspector & Heatmap** sub-tab above to inspect side-by-side patch diffs, attention heatmaps, and download individual repaired files or `.patch` diffs.")
            else:
                st.info("No function-level results to display.")

        with res_sub_inspector:
            _render_code_inspector(results, refinement_cap, pipeline, enable_sv, show_explainability)



# ──────────────────────────────────────────────────────────────────────────────
# TAB 3: TEST BENCH & CATALOG
# ──────────────────────────────────────────────────────────────────────────────
with tab_bench:
    st.markdown("""
    <div class="section-hdr">
        <span class="icon purple">🧪</span> Ground-Truth Test Bench & Fixture Catalog
    </div>
    """, unsafe_allow_html=True)
    st.caption("50 authoritative test fixtures (25 vulnerable, 25 safe) across 11 languages and 15 CWE categories.")

    from tests.fixtures.catalog import TEST_CASES
    from tests.run_all_tests import run_catalog_benchmarks

    # Top metrics
    b_col1, b_col2, b_col3, b_col4 = st.columns(4)
    b_col1.metric("Total Fixtures", len(TEST_CASES))
    b_col2.metric("Vulnerable Cases", sum(1 for tc in TEST_CASES if tc["expected_vf"]), "25 Flagged")
    b_col3.metric("Safe Baseline Cases", sum(1 for tc in TEST_CASES if not tc["expected_vf"]), "25 Clean")
    b_col4.metric("Supported Languages", len(set(tc["language"] for tc in TEST_CASES)), "11 Languages")

    # Filter controls
    f_col1, f_col2 = st.columns([1, 2])
    with f_col1:
        type_filter = st.radio("Show Fixtures:", ["All 50 Fixtures", "🚨 Vulnerable Only", "✅ Safe Baseline Only"], horizontal=True)
    with f_col2:
        lang_filter = st.selectbox("Filter by Language:", ["All Languages"] + sorted(list(set(tc["language"] for tc in TEST_CASES))))

    filtered_tcs = TEST_CASES
    if type_filter == "🚨 Vulnerable Only":
        filtered_tcs = [tc for tc in filtered_tcs if tc["expected_vf"]]
    elif type_filter == "✅ Safe Baseline Only":
        filtered_tcs = [tc for tc in filtered_tcs if not tc["expected_vf"]]

    if lang_filter != "All Languages":
        filtered_tcs = [tc for tc in filtered_tcs if tc["language"] == lang_filter]

    st.markdown(f"**Showing {len(filtered_tcs)} fixtures:**")

    ext_map = {"python": "py", "c": "c", "cpp": "cpp", "php": "php", "javascript": "js", "typescript": "ts", "go": "go", "java": "java", "ruby": "rb"}

    for tc in filtered_tcs:
        badge = "🚨 VULN" if tc["expected_vf"] else "✅ SAFE"
        cwe_label = f"[{tc['expected_cwe']}] " if tc["expected_cwe"] != "N/A" else ""
        header_text = f"**{tc['id']}** · {tc['language']} · {badge} · {cwe_label}{tc['category']}"
        with st.expander(header_text, expanded=False):
            desc = tc.get("explanation") or tc.get("description", "No description provided.")
            st.markdown(f"**Explanation:** {desc}")
            if tc.get("remediation"):
                st.markdown(f"**Remediation:** {tc['remediation']}")
            col_l, col_r = st.columns([3, 1])
            with col_l:
                st.code(tc["code"], language=ext_map.get(tc["language"].lower(), "text"), line_numbers=True)
            with col_r:
                st.markdown(f"**Tier:** `{tc.get('tier', 'tier1_c_cpp')}`")
                st.markdown(f"**Expected VF:** `{'Vulnerable' if tc['expected_vf'] else 'Safe'}`")
                st.markdown(f"**Target CWE:** `{tc['expected_cwe']}`")
                st.markdown(f"**Group:** `{tc['expected_semantic_group']}`")
                if st.button("📥 Load into Analyzer", key=f"load_bench_{tc['id']}", width="stretch"):
                    st.session_state.input_code = tc["code"]
                    st.session_state.input_filename = f"{tc['id']}_{tc['language']}.{ext_map.get(tc['language'].lower(), 'txt')}"
                    st.session_state.results = None
                    st.toast(f"Loaded {tc['id']} into Analyzer!", icon="📥")
                    st.rerun()

    # One-click regression test runner
    st.markdown("---")
    st.markdown("""
    <div class="section-hdr">
        <span class="icon green">⚡</span> Execute Live Regression Test Benchmark
    </div>
    """, unsafe_allow_html=True)
    st.caption("Runs automated verification across all 50 fixtures and verifies language routing, syntax, static analysis, and CWE classification.")

    if st.button("🚀 Run Live 50-Fixture Benchmark", type="primary", width="content"):
        with st.spinner("Executing full 50-fixture regression suite…"):
            bench_results = run_catalog_benchmarks(mode="lightweight")
            st.success(f"✅ Benchmark Complete — Pass Rate: {bench_results['pass_rate']:.1%} ({bench_results['total_passed']}/{bench_results['total_test_cases']})")

            # Show summary metrics
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Overall Pass Rate", f"{bench_results['pass_rate']:.1%}")
            m2.metric("Vulnerable Recall", f"{bench_results['vulnerable_recall']:.1%}")
            m3.metric("Safe Specificity", f"{bench_results['safe_specificity']:.1%}")
            m4.metric("CWE Accuracy", f"{bench_results['cwe_group_accuracy']:.1%}")

            # Show results dataframe
            bench_df = pd.DataFrame(bench_results["results"])
            st.dataframe(bench_df[["id", "language", "category", "expected_vf", "predicted_vf", "expected_cwe", "predicted_cwe", "status"]], width="stretch", hide_index=True)




# ══════════════════════════════════════════════════════════════════════════════
# ARCHITECTURE & REFERENCE SUB-VIEW RENDERERS
# ══════════════════════════════════════════════════════════════════════════════
def _render_reference_arch():
    st.markdown("""
    <div class="section-hdr">
        <span class="icon blue">ℹ️</span> System Architecture, Audit & Academic Attribution
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="background: linear-gradient(135deg, #F8FAFC, #EEF2FF); border: 1px solid #C7D2FE; border-left: 5px solid #4F46E5; border-radius: 12px; padding: 16px 20px; margin-bottom: 20px;">
        <h4 style="margin: 0 0 6px 0; color: #1E1B4B; font-size: 1.15rem;">🎓 Academic Research Project — B.Tech Minor Project</h4>
        <div style="font-size: 0.92rem; color: #3730A3; font-weight: 600;">
            SecuraX: An AI-Based Framework for Automated Source Code Vulnerability Detection, Multi-Class Classification, Severity Scoring and LLM-Assisted Code Refinement
        </div>
        <div style="font-size: 0.85rem; color: #4338CA; margin-top: 4px;">
            <strong>Author:</strong> Preet Makadiya &nbsp;|&nbsp; <strong>Project Guide:</strong> [GUIDE_NAME] &nbsp;|&nbsp; <strong>Institution:</strong> [INSTITUTE_NAME]
        </div>
    </div>
    """, unsafe_allow_html=True)

    about_col1, about_col2 = st.columns(2)

    with about_col1:
        st.markdown("""
        ### 🛡️ What is SecuraX?

        **SecuraX** is an end-to-end neuro-symbolic framework for automated source code vulnerability
        detection, multi-class CWE classification, CVSS severity scoring, and
        LLM-assisted code repair.

        The system processes source code through a **7-phase pipeline**:

        | Phase | Component | Method |
        |-------|-----------|--------|
        | **0/0.5** | Data Collection & Tiering | BigVul, CVEFixes, MegaVul, DiverseVul, VUDENC |
        | **1** | Binary Detection | Fine-tuned GraphCodeBERT + CodeT5 with LoRA |
        | **2** | CWE Classification | 15-class MITRE semantic group classifier |
        | **3** | Severity Scoring | CVSS 0–10 regression (Approach A/B/C) |
        | **4** | Code Repair | Groq-hosted LLM (open-weight models) |
        | **5** | Pipeline Integration | Language-routed end-to-end + Streamlit UI |
        | **6** | Evaluation & Ablation | Consolidated metrics, ablation studies |
        | **7** | Stretch Goals | Self-verification loop + attention explainability |

        ### 🌐 Supported Languages (11 Languages Across 3 Tiers)

        - **Tier 1 (Trained Weights):** C, C++ (`tier1_c_cpp`)
        - **Tier 2 (Trained Weights):** PHP (`tier2_php`) , Python (`tier2_python`)
        - **Tier 3 (Transfer & Multi-Language):** JavaScript, TypeScript, Go, Java, Ruby (`tier3_shared`)
        """)

    with about_col2:
        st.markdown("""
        ### 🏗️ Architecture Pipeline

        ```
        Source Code
            │
            ▼
        ┌──────────────────┐
        │ Language Detection│ ← Pygments lexer + heuristics
        │ & Tier Routing    │
        └────────┬─────────┘
                 ▼
        ┌──────────────────┐
        │  Function Chunker │ ← AST & brace balance parser
        └────────┬─────────┘
                 ▼
        ┌──────────────────┐
        │ Phase 1: Binary   │ ← GraphCodeBERT + LoRA
        │ Detection         │
        └────────┬─────────┘
                 │ (if vulnerable)
                 ▼
        ┌──────────────────┐
        │ Phase 2: CWE      │ ← CodeT5 multi-class classifier
        │ Classification    │   (15 disjoint semantic groups)
        └────────┬─────────┘
                 ▼
        ┌──────────────────┐
        │ Phase 3: CVSS     │ ← Severity regression (0.0–10.0)
        │ Severity          │
        └────────┬─────────┘
                 ▼
        ┌──────────────────┐
        │ Phase 4: Groq LLM │ ← Open-weight code repair API
        │ Refinement        │   (qwen/qwen3.8-27b on LPU)
        └────────┬─────────┘
                 ▼
        ┌──────────────────┐
        │ Phase 7: Post-    │ ← Self-verification loop &
        │ Verification      │   attention pooling explainability
        └──────────────────┘
        ```

        ### ⚠️ Academic Constraint Disclosure

        Groq is a hosted API serving **open-weight models** on a free tier.
        The service is rate-limited and sends code to a third-party server.
        Phases 1–3 run **entirely locally** on PyTorch with deterministic CPU inference.

        ### 📋 Mandatory Output Schema

        `PL | Snippet | VF | CWE-id | Refined Code | LOC | Severity Score`
        """)

    st.markdown("---")
    st.markdown("""
    <div class="section-hdr">
        <span class="icon green">🔬</span> Engineering Audit & Rigorous Validation Findings
    </div>
    """, unsafe_allow_html=True)

    audit_c1, audit_c2 = st.columns(2)

    with audit_c1:
        st.markdown("""
        #### 1. Relabeled Defensive Override Layer (Honest Neuro-Symbolic Reporting)
        Pre-trained neural language models often over-flag defensive code due to security API token co-occurrence. SecuraX uses an independent AST/regex control verifier.
        - **Correction:** When active defensive controls are confirmed on flagged code, the pipeline emits `VF = "Controls detected - likely safe"` (internal `LIKELY_SAFE_CONTROLS`), reserving plain `"Safe"` exclusively for sub-threshold inferences without rule overrides.
        - **Transparency:** The raw neural probability (`neural_prob`) and verified rule reason (`override_reason`) are permanently preserved in reports and audit trails.

        #### 2. Real-World Generalization on Held-Out CVEFixes Pairs
        To measure real-world performance beyond synthetic test cases, a held-out dataset of **250 commit pairs (500 real functions)** was extracted from CVEFixes with 0 training hash leakage:
        - Evaluated across 5 languages: PHP, Python, C++, JavaScript, and Java.
        - Provides unbiased Recall, Specificity, and F1 across Neural-Only, Full-System, and Override-Only configurations (`results/audit/heldout_summary.md`).

        #### 3. Data Leakage & Class Balance Root Cause Resolution
        An audit of the evaluation splits revealed that historical `tier2_php` ($N=291$) and `tier3_shared` ($N=449$) test sets comprised 100% vulnerable instances (`vul=1`, 0 safe).
        - This explained why historical evaluations reported an artificial 1.000 F1 score: with no negative instances, precision was trivially 1.0 and AUROC was mathematically undefined (`NaN`).
        - Reconciled with 1,000 bootstrap confidence interval iterations (`results/audit/leakage_report.md`).
        """)

    with audit_c2:
        st.markdown("""
        #### 4. Validation-Based Threshold Optimization
        In historical reports, Tier 1 recall dropped to 45.8% because the decision threshold was locked at $\\theta = 0.70$ based on an arbitrary $P \\ge 0.75$ precision floor on an unbalanced split.
        - Selecting $\\theta = 0.20$ based on validation set ROC-PR restores Tier 1 Recall to **80.90%** (+35.1% absolute gain) under a realistic $P_{floor} = 0.30$.
        - Documented in `config/threshold_policy.yaml` and `docs/audit/thresholds.md`.

        #### 5. Disjoint 1-to-1 CWE Taxonomy Mapping
        Audited the 15 semantic CWE macro-groups encompassing 25+ MITRE CWEs:
        - Confirmed zero overlap / duplicates between groups. Added `CWE-124` to `OOB-Write` and registered metadata for `CWE-124` and `CWE-693`.
        - Verified by automated unit tests (`tests/unit/test_cwe_taxonomy.py`).

        #### 6. Statistical Baselines & Wilson 95% Confidence Intervals
        - Benchmarked Phase 3 severity regression against Global Mean (5.47), Median (5.00), and Per-CWE Mean (1.28 MAE).
        - Evaluated Phase 7 Option C Attention Explainability with 95% Wilson CIs: Top-1 50.0% [23.7%, 76.3%]; Top-3 100.0% [72.2%, 100.0%].
        - Benchmarked 50 authoritative catalog fixtures: **48/50 passed (96.0%)**.
        """)

    st.markdown("---")
    st.markdown("""
    ### 🔗 Project Audit Reports & Documentation

    | Document | Path / Artifact | Purpose |
    |----------|-----------------|---------|
    | 🛡️ Audit Summary | `docs/audit/AUDIT_SUMMARY.md` | Comprehensive synthesis of all audit findings & metrics |
    | 📝 Audit Changelog | `docs/audit/CHANGELOG_AUDIT.md` | Detailed changelog of fixes, relabeling, and tests |
    | ⚠️ Limitations & Validity | `docs/audit/LIMITATIONS_AND_VALIDITY.md` | Honest threats to validity, leakage disclosure, and scope |
    | 📚 Related Work | `docs/audit/RELATED_WORK.md` | Scholarly survey of GNN, LLM, and neuro-symbolic code security |
    | 🎯 Threshold Policy | `docs/audit/thresholds.md` | Empirical threshold re-selection data and curves |
    | 🛡️ Override Impact | `docs/audit/override_impact.md` | Hard-negative override impact analysis & ablation |
    | 📊 Leakage Report | `results/audit/leakage_report.md` | Class balance audit & bootstrap confidence intervals |
    | 🌐 Held-Out Evaluation | `results/audit/heldout_summary.md` | 500-function CVEFixes real-world evaluation |
    | 📄 Final Project Report | `reports/FINAL_PROJECT_REPORT.md` | Academic minor project dissertation report |
    """)



def _render_reference_cwe():
    st.markdown("""
    <div class="section-hdr">
        <span class="icon purple">📚</span> MITRE CWE Semantic Taxonomy & Defensive Mitigations
    </div>
    """, unsafe_allow_html=True)
    st.caption("Authoritative 15-class MITRE semantic taxonomy mapping 25+ CWEs across 11 languages with code signatures and mitigation playbooks.")

    # Top metrics
    cwe_col1, cwe_col2, cwe_col3, cwe_col4 = st.columns(4)
    cwe_col1.metric("Semantic Classes", len(CLASS_NAMES), "15 Macro Categories")
    cwe_col2.metric("Tracked CWE IDs", len(CWE_METADATA), "MITRE CWEs")
    cwe_col3.metric("Supported Languages", "11", "Multi-Language")
    cwe_col4.metric("Calibration Mode", "Hybrid", "Entropy + Signatures")

    # Search & Filter
    st.markdown("---")
    search_q = st.text_input("🔍 Search CWE ID, Name, or Concept (e.g., 'SQL', 'CWE-79', 'Buffer', 'Integer', 'Traversal'):", "")

    for group_name in CLASS_NAMES:
        cwes_in_group = CWE_SEMANTIC_GROUPS.get(group_name, [])

        # Apply search filter
        if search_q.strip():
            sq = search_q.lower()
            matches_group = sq in group_name.lower()
            matches_cwe = any(sq in c.lower() or sq in CWE_METADATA.get(c, {}).get("name", "").lower() or sq in CWE_METADATA.get(c, {}).get("desc", "").lower() for c in cwes_in_group)
            if not (matches_group or matches_cwe):
                continue

        exp_title = f"🏷️ **{group_name}** ({len(cwes_in_group)} CWEs: {', '.join(cwes_in_group[:4])}{'...' if len(cwes_in_group) > 4 else ''})"
        with st.expander(exp_title, expanded=(bool(search_q.strip()))):
            st.markdown(f"**Semantic Group:** `{group_name}`")
            st.markdown(f"**Encompassed MITRE CWEs:** {', '.join([f'`{c}`' for c in cwes_in_group])}")

            # Show details of each CWE in this group
            for c_id in cwes_in_group:
                meta = CWE_METADATA.get(c_id, {})
                c_name = meta.get("name", "Unknown Vulnerability")
                c_desc = meta.get("desc", "No description available.")
                st.markdown(f"""
                <div class="cwe-card">
                    <div>
                        <span class="cwe-badge-id">{c_id}</span>
                        <strong style="margin-left: 8px; font-size: 0.95rem; color: #0F172A;">{c_name}</strong>
                    </div>
                    <div style="font-size: 0.82rem; color: #475569; margin: 6px 0 8px 0; line-height: 1.5;">
                        {c_desc}
                    </div>
                </div>
                """, unsafe_allow_html=True)

            # Recommendations & Signatures
            st.markdown("##### 🛡️ Mitigation & Defensive Guidelines")
            mitigations = {
                "Buffer-Overflow": "Replace unbounded memory APIs (`strcpy`, `strcat`, `sprintf`, `gets`) with length-bounded variants (`strncpy`, `strncat`, `snprintf`, `fgets`). Always verify buffer limits before write.",
                "OOB-Read": "Validate all array indexes and buffer pointer offsets against bounds before memory reads. Ensure null termination on strings.",
                "OOB-Write": "Enforce strict boundary checks before memory writes. Use safe array wrappers or standard library containers with automatic bounds checking.",
                "Use-After-Free": "Set freed pointers to `NULL` immediately after calling `free()`. Use RAII, smart pointers (`std::unique_ptr`, `std::shared_ptr`), or garbage collection.",
                "Double-Free": "Nullify pointers after deallocation. Ensure strict single-ownership semantics for heap-allocated resources.",
                "NULL-Deref": "Perform explicit null checks (`ptr != NULL`) prior to pointer dereferencing. Use static analysis or non-nullable types.",
                "Integer-Issues": "Perform arithmetic overflow validation before buffer allocation or sizing: `if (b > SIZE_MAX / a) return ERROR;`. Use compiler-provided overflow intrinsics (`__builtin_mul_overflow`).",
                "Input-Validation": "Employ parameterized queries (PreparedStatements) for databases, context-aware output encoding (XSS defense), and safe argument lists for process invocation (Command Injection defense).",
                "Info-Exposure": "Disable verbose debug errors in production environments. Strip stack traces and sensitive database credentials from API responses.",
                "Access-Control": "Enforce strict role-based access control (RBAC) at the service boundary. Avoid reliance on client-supplied parameters for privilege decisions.",
                "Crypto-Issues": "Use modern cryptographic primitives: SHA-256/SHA-512 instead of MD5/SHA-1; AES-GCM instead of ECB/DES; Argon2id or bcrypt with salt for password hashing.",
                "Resource-Mgmt": "Use RAII, `with` statements, or `try-with-resources` / `try-finally` blocks to guarantee file, socket, and memory cleanup.",
                "Race-Condition": "Use synchronization primitives (`std::mutex`, `pthread_mutex_t`, semaphores) to synchronize access to shared resources across threads or processes.",
                "Path-Traversal": "Use canonical filename containment (`os.path.basename` / `filepath.Base`), reject directory traversal sequences (`..`), and validate paths against strict base directory allowlists.",
                "Other-Security": "Apply defense-in-depth principles: least privilege, comprehensive input validation, continuous dependency vulnerability auditing, and strict Content Security Policies (CSP).",
            }
            st.info(mitigations.get(group_name, "Apply least privilege and rigorous input validation."))



def _render_reference_defenses():
    st.markdown("""
    <div class="section-hdr">
        <span class="icon green">🛡️</span> Independent Defensive Controls & Hard-Negative Studio
    </div>
    """, unsafe_allow_html=True)
    st.caption("Demonstrating how SecuraX's AST and regex security control verification layer eliminates false positives on secure code without modifying neural model weights.")

    st.markdown("""
    When code contains security-sensitive API calls (like `move_uploaded_file`, `sqlite3.connect`, `document.getElementById`, or `exec`),
    pre-trained neural language models often flag them as vulnerable due to high token co-occurrence in training corpora.

    **SecuraX's Solution:** Before rendering a final verdict, an independent security control analyzer checks for the presence of **active defensive patterns** (e.g., extension allowlists, parameterized placeholders, HTML entity escaping, or boundary checks). If proven secure, SecuraX classifies the code as **`Safe`** (`VF: 0`, `CWE: N/A`, `Severity: N/A`), achieving 100% specificity on hard negatives!
    """)

    DEFENSIVE_CONTROLS = [
        {
            "title": "PHP Secure File Upload (CWE-434 Hard Negative)",
            "lang": "PHP",
            "tag": "Defense: Extension & MIME Whitelist + Unique Name",
            "cwe": "CWE-434 (Unrestricted File Upload)",
            "explanation": "Validates the file extension against an allowlist, checks the verified MIME type with mime_content_type, and stores the file under a randomized uniqid filename.",
            "code": """<?php
    function uploadFile($file) {
    $allowed = ["jpg", "png", "gif"];
    $ext = pathinfo($file["name"], PATHINFO_EXTENSION);
    if (in_array(strtolower($ext), $allowed, true)) {
        if (mime_content_type($file["tmp_name"]) === "image/jpeg") {
            $dest = "uploads/" . uniqid("img_") . "." . $ext;
            move_uploaded_file($file["tmp_name"], $dest);
            return true;
        }
    }
    return false;
    }
    ?>""",
        },
        {
            "title": "Python Parameterized Database Query (CWE-89 Hard Negative)",
            "lang": "Python",
            "tag": "Defense: PEP 249 Query Parameterization",
            "cwe": "CWE-89 (SQL Injection)",
            "explanation": "Uses standard SQL parameter placeholders (?) instead of string concatenation, preventing SQL injection completely.",
            "code": """import sqlite3

    def get_user_by_username(username: str):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # Safe: Parameterized query placeholder
    cursor.execute("SELECT id, username, email FROM users WHERE username = ?", (username,))
    return cursor.fetchone()""",
        },
        {
            "title": "JavaScript Safe DOM Assignment (CWE-79 Hard Negative)",
            "lang": "JavaScript",
            "tag": "Defense: textContent DOM Property",
            "cwe": "CWE-79 (Cross-Site Scripting)",
            "explanation": "Assigns user input via element.textContent instead of innerHTML, treating the string purely as text and eliminating script execution.",
            "code": """function displayMessage(userText) {
    const el = document.getElementById('output');
    // Safe: textContent escapes HTML entities automatically
    el.textContent = userText;
    }""",
        },
        {
            "title": "PHP Output Escaping (CWE-79 Hard Negative)",
            "lang": "PHP",
            "tag": "Defense: htmlspecialchars with ENT_QUOTES",
            "cwe": "CWE-79 (Cross-Site Scripting)",
            "explanation": "Uses htmlspecialchars with ENT_QUOTES and UTF-8 encoding to sanitize untrusted strings before embedding them into HTML templates.",
            "code": """<?php
    function render_profile($name) {
    // Safe: HTML entity encoding prevents XSS
    echo "<h1>Hello " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "</h1>";
    }
    ?>""",
        },
        {
            "title": "Python Safe Process Execution (CWE-78 Hard Negative)",
            "lang": "Python",
            "tag": "Defense: Subprocess Argument Array without shell=True",
            "cwe": "CWE-78 (Command Injection)",
            "explanation": "Passes command arguments as an array directly to execve without invoking an intermediate shell (shell=False).",
            "code": """import subprocess

    def ping_host_safe(hostname: str):
    # Safe: Argument list without shell=True avoids command injection
    result = subprocess.run(["ping", "-c", "1", hostname], capture_output=True, text=True)
    return result.stdout""",
        },
        {
            "title": "Python Path Sanitization (CWE-22 Hard Negative)",
            "lang": "Python",
            "tag": "Defense: os.path.basename Path Stripping",
            "cwe": "CWE-22 (Path Traversal)",
            "explanation": "Strips all directory prefixes using os.path.basename, preventing relative directory traversal (e.g., ../../etc/passwd).",
            "code": """import os

    def read_user_file_safe(untrusted_filename: str):
    # Safe: os.path.basename strips directory traversal sequences
    safe_name = os.path.basename(untrusted_filename)
    full_path = os.path.join("/var/app/data", safe_name)
    with open(full_path, "r") as f:
        return f.read()""",
        },
        {
            "title": "C Arithmetic Overflow Boundary Check (CWE-190 Hard Negative)",
            "lang": "C",
            "tag": "Defense: Pre-Allocation SIZE_MAX Bound Check",
            "cwe": "CWE-190 (Integer Overflow)",
            "explanation": "Validates multiplication limits against SIZE_MAX before passing the product to malloc, preventing integer wraparound heap overflows.",
            "code": """#include <stdlib.h>
    #include <stdint.h>

    void* allocate_canvas(size_t width, size_t height) {
    // Safe: Explicit pre-allocation arithmetic bounds verification
    if (width > 0 && height > SIZE_MAX / width) {
        return NULL;
    }
    size_t total = width * height;
    return malloc(total);
    }""",
        },
    ]

    for d_idx, def_case in enumerate(DEFENSIVE_CONTROLS):
        with st.expander(f"🛡️ **{def_case['title']}**", expanded=False):
            st.markdown(f"<span class='defense-tag'>{def_case['tag']}</span> <span class='defense-cwe'>{def_case['cwe']}</span>", unsafe_allow_html=True)
            st.markdown(f"**Security Assurance:** {def_case['explanation']}")

            c_code, c_act = st.columns([3, 1])
            with c_code:
                st.code(def_case["code"], language=def_case["lang"].lower(), line_numbers=True)
            with c_act:
                st.markdown(f"**Language:** `{def_case['lang']}`")
                st.markdown("**Expected Result:** `Safe`")
                st.markdown("**Expected CWE:** `N/A`")
                if st.button("🧪 Stage into Analyzer", key=f"btn_def_{d_idx}", width="stretch"):
                    st.session_state.input_code = def_case["code"]
                    st.session_state.input_filename = f"safe_test_{d_idx}.{def_case['lang'].lower()}"
                    st.session_state.results = None
                    if "paste_area" in st.session_state:
                        st.session_state["paste_area"] = def_case["code"]
                    st.toast(f"Staged {def_case['title']} into Analyzer!", icon="🛡️")
                    st.rerun()



def _render_reference_stats(results):
    results = st.session_state.results

    if results is None:
        st.markdown("""
        <div class="empty-state">
            <div class="icon">📈</div>
            <div><strong>No scan data available</strong></div>
            <div>Run an analysis first to see statistics and model performance metrics.</div>
        </div>
        """, unsafe_allow_html=True)

    elif not results["success"]:
        st.error(f"**Analysis Failed:** {results['error']}")

    else:
        st.markdown("""
        <div class="section-hdr">
            <span class="icon green">📈</span> Scan Statistics & Metrics
        </div>
        """, unsafe_allow_html=True)

        stat_col1, stat_col2 = st.columns(2)

        with stat_col1:
            # ── Vulnerability Distribution ──
            st.markdown("##### 🎯 Vulnerability Distribution")
            vuln_count = results["vulnerable_count"]
            safe_count = results["safe_count"]
            total = results["total_functions"]

            dist_df = pd.DataFrame({
                "Category": ["🚨 Vulnerable", "✅ Safe"],
                "Count": [vuln_count, safe_count],
                "Percentage": [
                    f"{(vuln_count / max(total, 1) * 100):.1f}%",
                    f"{(safe_count / max(total, 1) * 100):.1f}%",
                ],
            })
            st.dataframe(dist_df, width="stretch", hide_index=True)

            # ── CWE Distribution ──
            st.markdown("##### 🏷️ CWE Distribution")
            cwe_data = {}
            for item in results["details"]:
                if item["is_vulnerable"]:
                    cwe_id = item.get("cwe_id", "Unknown")
                    sem = item.get("semantic_group", "")
                    key = f"{cwe_id} ({sem})" if sem else cwe_id
                    cwe_data[key] = cwe_data.get(key, 0) + 1

            if cwe_data:
                cwe_df = pd.DataFrame([
                    {"CWE Category": k, "Count": v}
                    for k, v in sorted(cwe_data.items(), key=lambda x: -x[1])
                ])
                st.dataframe(cwe_df, width="stretch", hide_index=True)
            else:
                st.caption("No vulnerable functions detected — no CWE data.")

        with stat_col2:
            # ── Severity Distribution ──
            st.markdown("##### ⚠️ Severity Score Distribution")
            sev_data = []
            for item in results["details"]:
                if item["is_vulnerable"] and item.get("severity_score") is not None:
                    sev_data.append({
                        "Function": item["name"],
                        "Score": item["severity_score"],
                        "Band": item.get("severity_band", "?"),
                    })

            if sev_data:
                sev_df = pd.DataFrame(sev_data)
                st.dataframe(sev_df, width="stretch", hide_index=True)

                # Severity bar chart
                avg_sev = sum(d["Score"] for d in sev_data) / len(sev_data)
                max_sev = max(d["Score"] for d in sev_data)
                min_sev = min(d["Score"] for d in sev_data)
                sev_metric_cols = st.columns(3)
                sev_metric_cols[0].metric("Avg Severity", f"{avg_sev:.1f}/10")
                sev_metric_cols[1].metric("Max Severity", f"{max_sev:.1f}/10")
                sev_metric_cols[2].metric("Min Severity", f"{min_sev:.1f}/10")
            else:
                st.caption("No severity data to display.")

            # ── Performance Metrics ──
            st.markdown("##### ⚡ Pipeline Performance")
            perf_data = {
                "Total Time": f"{results['elapsed_seconds']:.2f}s",
                "Functions Parsed": str(results["total_functions"]),
                "API Calls Made": str(results["refined_count"]),
                "Refinement Cap": str(results["refinement_cap"]),
                "Cap Hit": "Yes ⚠️" if results["cap_hit"] else "No ✅",
                "Groq Model": active_model,
            }
            perf_df = pd.DataFrame([
                {"Metric": k, "Value": v} for k, v in perf_data.items()
            ])
            st.dataframe(perf_df, width="stretch", hide_index=True)

        # ── Scan History ──
        if st.session_state.scan_history:
            st.markdown("---")
            st.markdown("##### 📜 Session Scan History")
            hist_df = pd.DataFrame(st.session_state.scan_history)
            st.dataframe(hist_df, width="stretch", hide_index=True)



# ──────────────────────────────────────────────────────────────────────────────
# TAB 4: ARCHITECTURE & REFERENCE
# ──────────────────────────────────────────────────────────────────────────────
with tab_reference:
    st.markdown("""
    <div class="section-hdr">
        <span class="icon blue">ℹ️</span> Technical Reference & Knowledge Base
    </div>
    """, unsafe_allow_html=True)
    st.caption("Complete MITRE CWE taxonomy, independent defensive controls studio, system architecture, and historical session scan metrics.")

    ref_sub_arch, ref_sub_cwe, ref_sub_defenses, ref_sub_stats = st.tabs([
        "🏗️ System Architecture & Pipeline",
        "📚 MITRE CWE Taxonomy (15 Classes)",
        "🛡️ Defensive Controls Studio",
        "📈 Scan Statistics & Metrics",
    ])

    with ref_sub_arch:
        _render_reference_arch()

    with ref_sub_cwe:
        _render_reference_cwe()

    with ref_sub_defenses:
        _render_reference_defenses()

    with ref_sub_stats:
        _render_reference_stats(st.session_state.results)


# ══════════════════════════════════════════════════════════════════════════════
# FOOTER
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="app-footer">
    <strong>SecuraX</strong> — AI-Based Framework for Automated Source Code Vulnerability Detection,
    Multi-Class Classification, Severity Scoring and LLM-Assisted Code Refinement.<br>
    <strong>Constraint Exception:</strong>
    Phases 1–3 run entirely on local PyTorch models (GraphCodeBERT & CodeT5).
    Phase 4 code refinement connects to Groq's hosted LPU inference engine
    serving open-weight models (free-tier). Responses are cached locally to minimize API usage.
    Phase 7 adds self-verification (Option B) and attention explainability (Option C).
</div>
""", unsafe_allow_html=True)
