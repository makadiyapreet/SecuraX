"""
explainability.py — Phase 7 (Option C): Attention Visualization & Line Attribution.

Implements LineVul-style explainability for SecuraX:
  1. Extracts token attention weights from GraphCodeBERT AttentionPooling head.
  2. Maps subword token attention weights back to original code line numbers.
  3. Computes normalized line importance scores.
  4. Generates an interactive color-coded HTML heatmap for the Streamlit UI.
"""

import html
from typing import Dict, Any, List, Optional
import numpy as np
import torch


def compute_line_attributions(
    code: str,
    tokenizer,
    attention_weights: torch.Tensor,
    max_length: int = 256,
) -> Dict[str, Any]:
    """
    Map token attention weights back to code lines.

    Args:
        code: original source code snippet
        tokenizer: HuggingFace tokenizer used for model
        attention_weights: (L,) torch.Tensor of attention weights from AttentionPooling
        max_length: max token length used during tokenization

    Returns:
        {
          "lines": List[Dict[str, Any]], # [{"line_no": 1, "text": "...", "score": 0.42, "is_top": bool}]
          "top_lines": List[Dict[str, Any]], # top 3 lines by importance
          "html_heatmap": str, # formatted HTML ready for st.markdown
        }
    """
    raw_lines = code.splitlines()
    if not raw_lines:
        return {"lines": [], "top_lines": [], "html_heatmap": ""}

    if isinstance(attention_weights, torch.Tensor):
        attn = attention_weights.detach().cpu().numpy().flatten()
    else:
        attn = np.array(attention_weights).flatten()

    # Tokenize with offset mapping if supported
    try:
        enc = tokenizer(
            code,
            return_offsets_mapping=True,
            max_length=max_length,
            truncation=True,
            return_tensors="pt"
        )
        offsets = enc.get("offset_mapping", None)
        if offsets is not None:
            offsets = offsets[0].cpu().numpy()
    except Exception:
        offsets = None

    line_scores = np.zeros(len(raw_lines), dtype=np.float32)
    line_token_counts = np.zeros(len(raw_lines), dtype=np.int32)

    if offsets is not None:
        # Precompute character offset ranges for each line
        line_char_ranges = []
        curr_char = 0
        for l in raw_lines:
            end_char = curr_char + len(l)
            line_char_ranges.append((curr_char, end_char))
            curr_char = end_char + 1  # newline character

        # Map each token to its corresponding line
        for tok_idx, (start, end) in enumerate(offsets):
            if tok_idx >= len(attn):
                break
            if start == end:
                continue  # skip special tokens like <s>, </s>, padding
            weight = float(attn[tok_idx])

            # Find matching line
            for line_idx, (l_start, l_end) in enumerate(line_char_ranges):
                if max(start, l_start) < min(end, l_end):
                    line_scores[line_idx] += weight
                    line_token_counts[line_idx] += 1
    else:
        # Fallback keyword-weighted line attribution if offsets unavailable
        for line_idx, l in enumerate(raw_lines):
            l_clean = l.lower()
            suspicious_keywords = ["strcpy", "sprintf", "gets", "system", "exec", "eval", "free(", "malloc", "select", "where"]
            score = 0.1
            for kw in suspicious_keywords:
                if kw in l_clean:
                    score += 0.8
            line_scores[line_idx] = score

    # Normalize line scores into [0.0, 1.0]
    max_score = float(np.max(line_scores)) if len(line_scores) > 0 else 0.0
    if max_score > 1e-9:
        normalized_scores = line_scores / max_score
    else:
        normalized_scores = line_scores

    # Rank lines to find top suspicious lines (excluding empty/brace-only lines)
    eligible_indices = []
    for idx, l in enumerate(raw_lines):
        stripped = l.strip()
        if stripped and stripped not in ("{", "}", "};", "/*", "*/", "//"):
            eligible_indices.append(idx)

    ranked_indices = sorted(eligible_indices, key=lambda i: normalized_scores[i], reverse=True)
    top_3_indices = set(ranked_indices[:3])

    lines_data = []
    top_lines = []

    for idx, (text, norm_score) in enumerate(zip(raw_lines, normalized_scores)):
        is_top = idx in top_3_indices
        entry = {
            "line_no": idx + 1,
            "text": text,
            "score": round(float(norm_score), 4),
            "is_top": is_top,
        }
        lines_data.append(entry)
        if is_top:
            top_lines.append(entry)

    top_lines.sort(key=lambda x: x["score"], reverse=True)

    # Build interactive HTML Heatmap
    html_parts = [
        '<div style="font-family: monospace; font-size: 0.88rem; background-color: #0F172A; '
        'color: #F8FAFC; border-radius: 6px; padding: 12px; overflow-x: auto; line-height: 1.5;">'
    ]

    for entry in lines_data:
        score = entry["score"]
        # Background color: transparent to high-intensity red
        alpha = min(0.75, score * 0.75) if score > 0.05 else 0.0
        bg_style = f"background-color: rgba(239, 68, 68, {alpha:.2f});"
        border_style = "border-left: 3px solid #EF4444; font-weight: 600;" if entry["is_top"] and score > 0.3 else "border-left: 3px solid transparent;"
        badge = f'<span style="background-color: #EF4444; color: white; padding: 1px 4px; border-radius: 3px; font-size: 0.72rem; margin-right: 6px;">TOP ATTRIBUTION ({score:.1%})</span>' if entry["is_top"] and score > 0.3 else ""

        escaped_text = html.escape(entry["text"])
        line_html = (
            f'<div style="{bg_style} {border_style} padding: 2px 6px; border-radius: 2px; margin: 1px 0;">'
            f'<span style="color: #64748B; width: 32px; display: inline-block; user-select: none;">{entry["line_no"]:2d}</span>'
            f'{badge}<span>{escaped_text}</span>'
            f'</div>'
        )
        html_parts.append(line_html)

    html_parts.append('</div>')
    heatmap_html = "".join(html_parts)

    return {
        "lines": lines_data,
        "top_lines": top_lines,
        "html_heatmap": heatmap_html,
    }


# Convenient alias
explain_vulnerability = compute_line_attributions

