# SecuraX: Live Demonstration Script & Plan B Protocol

**Target Duration:** 5–7 Minutes  
**Prerequisites:** Streamlit app running locally via `streamlit run app/main.py`.  
**Showcase Languages:** C (Tier 1), Python (Tier 2), PHP (Tier 2).  

---

## 1. Demo Setup & Initialization

### Terminal Setup:
```bash
cd SecuraX
source .venv/bin/activate
streamlit run app/main.py
```
Open browser to `http://localhost:8501`.

---

## 2. Step-by-Step Live Demo Walkthrough

### Act 1: The Multi-Tier Dashboard & Status Check (1 Minute)
1. **Presenter Narration:**
   > *"Welcome to SecuraX. Traditional SAST tools tell you there is a problem, but leave developers guessing how to fix it, while producing overwhelming false positives. SecuraX provides an end-to-end multi-tier pipeline from detection to actionable repair."*
2. **Visual Action:**
   - Point to the sidebar: show **Language Routing** (Auto-Detect + manifest languages), **Groq Model Winner** (`qwen/qwen3.8-27b`), and **Active API Status** (`2 keys in failover pool`).
   - Highlight the **Local Device Badge** showing PyTorch models loaded in local memory.

---

### Act 2: Showcase 1 — C Buffer Overflow (Tier 1 C/C++) (2 Minutes)
1. **Visual Action:**
   - Click on the **"💡 Curated Examples"** tab.
   - Select `"C — Buffer Overflow (strcpy into fixed stack buffer)"`.
   - Click **"Use this example"**.
   - Click **"🚀 Analyze & Refine"**.
2. **Presenter Narration:**
   > *"Notice the real-time progress indicator: Pygments identifies C syntax and routes execution to Tier 1. The AST chunker splits the code into two discrete functions: `safe_helper()` and `parse_packet()`.
   > Our fine-tuned GraphCodeBERT model with LoRA evaluates both. It flags `safe_helper` as Safe, but detects `parse_packet` with a high vulnerability probability, exceeding Tier 1's calibrated 0.70 threshold.
   > Phase 2 identifies it as CWE-119 (Buffer Overflow), Phase 3 scores the CVSS severity at 7.5 (High), and Phase 4 passes this intelligence to Groq's open-weight Qwen model."*
3. **Inspect the Output:**
   - Scroll down to the standard results table:
     `C | parse_packet() | Vulnerable | CWE-119 | ... | 8 | 7.5 / 10.0`
   - Expand the accordion view for `parse_packet()`:
   - Highlight the **Unified Diff View**: show that `strcpy` was safely replaced with length-bounded `strncpy` with null-terminator guarantees, strictly preserving the function signature.

---

### Act 3: Showcase 2 — Python SQL Injection (Tier 2 Python) (1.5 Minutes)
1. **Visual Action:**
   - Switch to the **"💡 Curated Examples"** tab.
   - Select `"Python — SQL Injection (raw f-string formatting)"`.
   - Click **"Use this example"** $\rightarrow$ **"🚀 Analyze & Refine"**.
2. **Presenter Narration:**
   > *"Now let's test Tier 2 Python. The pipeline routes to `tier2_python` using GraphCodeBERT-v2. It recognizes the vulnerable string interpolation in the SQL query, classifies it under Input-Validation (CWE-89), and scores it at CVSS 8.0."*
3. **Inspect Diff:**
   - Expand the snippet: point out how the LLM replaced the dangerous raw f-string with a parameterized query: `cursor.execute("SELECT ... WHERE username = ?", (username, password))`.

---

### Act 4: Showcase 3 — Refinement Quota Protection (1 Minute)
1. **Visual Action:**
   - In the sidebar, slide **"Max Refinements per Upload"** down to `1`.
   - Upload or paste a multi-function file with multiple vulnerabilities.
   - Click **"🚀 Analyze & Refine"**.
2. **Presenter Narration:**
   > *"In enterprise environments, developer uploads can contain dozens of functions, which would quickly exhaust free-tier quotas. Notice how SecuraX detects all vulnerabilities, refines the first function, and caps further automated calls, providing an on-demand 'Refine Now' button for developers to triage remaining snippets on demand."*
3. **Visual Action:**
   - Click the on-demand button on the skipped snippet to demonstrate that instant repair works on demand.

---

## 3. Plan B Protocol: Offline / Network Failure Fallback

If WiFi drops, Groq API is unreachable, or an external rate limit occurs during the live presentation, execute Plan B:

### Why Plan B Works 100% Seamlessly:
1. **Local Neural Models:** Phases 1–3 (detection, CWE classification, and severity scoring) run **100% locally on PyTorch**. They do not require an active internet connection.
2. **Pre-Cached Refinements:** All sample demonstration files used in the script have already been executed and their SHA-256 hashed outputs are saved on disk in `data/cache/groq/`.
3. **Demonstrating Offline Degradation Gracefully:**
   - If a live API error occurs, SecuraX's failover handler automatically switches to the backup key in `.env`.
   - If completely disconnected from the internet, the app will cleanly display:
     `Refinement unavailable: GROQ_API_KEY is offline / network unreachable`
   - Point out to the evaluator that **this is an intentional architectural feature**:
     > *"Notice our graceful degradation: even with zero network connectivity, our local models completely flag the vulnerability, classify the CWE, and calculate the CVSS score without crashing."*

