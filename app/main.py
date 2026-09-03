#!/usr/bin/env python3
"""
Streamlit App — Automated Code Vulnerability Detection
(Placeholder for Phase 0 — will be built out in later phases)

Usage:
    streamlit run app/main.py
"""
import streamlit as st

st.set_page_config(
    page_title="VulnDetect — Code Vulnerability Scanner",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ VulnDetect")
st.subheader("Automated Code Vulnerability Detection, Classification & Severity Scoring")

st.info(
    "**Phase 0 — Setup Complete**\n\n"
    "This application will provide:\n"
    "- 🔍 Vulnerability Detection (VF: vulnerable / non-vulnerable)\n"
    "- 🏷️ CWE Classification (multi-class CWE-id)\n"
    "- 📊 Severity Scoring (CVSS-based)\n"
    "- 🔧 Code Refinement (LLM-generated fixes)\n\n"
    "Functionality will be added in Phases 1–5."
)

st.markdown("---")
st.caption("Built with CodeBERT, UnixCoder, Mistral-7B, and DeepSeek-Coder | All tools are free & open-source")
