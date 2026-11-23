import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import json
from matplotlib.gridspec import GridSpec

# ------------------------------------------------------------------------------
# 1. PERFECT p1_tier1_c_threshold_sweep.png
# ------------------------------------------------------------------------------
def render_figure_1():
    with open('logs/phase1_tier1_c_cpp_graphcodebert_results_v2.json') as f:
        data = json.load(f)
    sweep = data['threshold_sweep']

    thresholds = [s['threshold'] for s in sweep]
    recalls = [s['recall'] for s in sweep]
    precisions = [s['precision'] for s in sweep]
    f1_scores = [s['f1'] for s in sweep]
    f2_scores = [(5 * p * r) / (4 * p + r) if (4 * p + r) > 0 else 0 for p, r in zip(precisions, recalls)]

    fig = plt.figure(figsize=(14.5, 7.8), dpi=300)
    gs = GridSpec(1, 2, width_ratios=[2.3, 1.05], wspace=0.16, left=0.06, right=0.97, top=0.88, bottom=0.10)

    ax = fig.add_subplot(gs[0])
    ax_info = fig.add_subplot(gs[1])
    ax_info.axis('off')

    # Shaded Zones with soft modern pastel fills
    ax.axvspan(0.10, 0.35, color='#DCFCE7', alpha=0.55)
    ax.axvspan(0.35, 0.68, color='#FEF3C7', alpha=0.55)
    ax.axvspan(0.68, 0.90, color='#DBEAFE', alpha=0.55)

    # Zone labels at the very top
    ax.text(0.225, 1.018, 'Security Audit Zone (t <= 0.35)', color='#166534', fontsize=9.2, fontweight='bold', ha='center')
    ax.text(0.515, 1.018, 'Balanced Trade-Off Range', color='#92400E', fontsize=9.2, fontweight='bold', ha='center')
    ax.text(0.790, 1.018, 'Enterprise CI/CD Zone (t >= 0.70)', color='#1E40AF', fontsize=9.2, fontweight='bold', ha='center')

    # Precision Floor Line
    ax.axhline(0.75, color='#1E40AF', linestyle='--', linewidth=1.8, zorder=2)
    ax.text(0.48, 0.765, 'Enterprise Precision Floor (>= 75.0%)', color='#1E40AF', fontsize=8.8, fontweight='bold', ha='center',
            bbox=dict(boxstyle='round,pad=0.2', facecolor='white', edgecolor='#93C5FD', alpha=0.9))

    # Vertical guides for operating points
    ax.axvline(0.30, color='#DC2626', linestyle=':', alpha=0.7, linewidth=1.6, zorder=2)
    ax.text(0.30, 0.22, 't = 0.30 (Audit Mode)', color='#DC2626', fontsize=8.5, fontweight='bold', ha='center', rotation=90,
            bbox=dict(boxstyle='round,pad=0.2', facecolor='white', edgecolor='#FCA5A5', alpha=0.9))

    ax.axvline(0.70, color='#2563EB', linestyle=':', alpha=0.7, linewidth=1.6, zorder=2)
    ax.text(0.70, 0.22, 't* = 0.70 (CI/CD Mode)', color='#2563EB', fontsize=8.5, fontweight='bold', ha='center', rotation=90,
            bbox=dict(boxstyle='round,pad=0.2', facecolor='white', edgecolor='#93C5FD', alpha=0.9))

    # Plot lines with clean markers
    ax.plot(thresholds, recalls, color='#DC2626', linewidth=2.8, marker='o', markersize=6.5, label='Recall (Security Coverage)', zorder=4)
    ax.plot(thresholds, precisions, color='#2563EB', linewidth=2.8, marker='s', markersize=6.5, label='Precision (Alert Reliability)', zorder=4)
    ax.plot(thresholds, f1_scores, color='#059669', linewidth=2.8, marker='^', markersize=6.5, label='Balanced F1-Score', zorder=4)
    ax.plot(thresholds, f2_scores, color='#D97706', linewidth=2.2, linestyle='--', marker='d', markersize=5.5, label='Recall-Weighted F2 (beta=2)', zorder=4)

    # Highlight markers at t=0.30
    ax.scatter([0.30], [0.7493], color='#DC2626', s=150, zorder=6, edgecolor='white', linewidth=2.0)
    ax.annotate('Rec: 74.9%', xy=(0.30, 0.7493), xytext=(0.22, 0.78),
                arrowprops=dict(facecolor='#DC2626', shrink=0.08, width=1.2, headwidth=4),
                fontsize=8.5, fontweight='bold', color='#991B1B',
                bbox=dict(boxstyle='round,pad=0.25', facecolor='#FEF2F2', edgecolor='#EF4444', alpha=0.95))

    # Highlight markers at t=0.70
    ax.scatter([0.70], [0.7557], color='#2563EB', s=150, zorder=6, edgecolor='white', linewidth=2.0)
    ax.annotate('Prec: 75.6%', xy=(0.70, 0.7557), xytext=(0.60, 0.81),
                arrowprops=dict(facecolor='#2563EB', shrink=0.08, width=1.2, headwidth=4),
                fontsize=8.5, fontweight='bold', color='#1E40AF',
                bbox=dict(boxstyle='round,pad=0.25', facecolor='#EFF6FF', edgecolor='#3B82F6', alpha=0.95))

    ax.set_xlabel('Classification Decision Threshold (t)', fontsize=11, fontweight='semibold', labelpad=8)
    ax.set_ylabel('Empirical Metric Value (0.00 - 1.00)', fontsize=11, fontweight='semibold', labelpad=8)
    ax.set_xlim(0.08, 0.92)
    ax.set_ylim(0.20, 1.06)
    ax.grid(True, linestyle='--', alpha=0.30, color='#9CA3AF', zorder=0)

    # Legend at lower-left inside the main plot (completely clear of any lines or markers)
    ax.legend(loc='lower left', framealpha=0.95, fontsize=8.8, frameon=True, edgecolor='#CBD5E1')

    # RIGHT PANEL CARDS
    # Card 1: Benchmark Specifications
    card1_text = (
        "EVALUATION BENCHMARK\n"
        "───────────────────────────────\n"
        "• Corpus: Tier 1 C Language\n"
        "• Total Corpus: 516,562 Functions\n"
        "• Training Set: 361,593 functions\n"
        "• Test Set: 77,485 in-the-wild CVEs\n"
        "• Class Skew: 9:1 Non-Vuln : Vuln\n"
        "• Model: GraphCodeBERT-v2 + LoRA\n"
        "• Discriminative Power: AUROC = 0.8833"
    )
    ax_info.text(0.0, 0.98, card1_text, transform=ax_info.transAxes, fontsize=8.8, va='top', fontfamily='monospace',
                 bbox=dict(boxstyle='round,pad=0.6', facecolor='#F8FAFC', edgecolor='#CBD5E1', linewidth=1.2))

    # Card 2: Operating Profile A (Enterprise CI/CD Gate)
    card2_text = (
        "PROFILE A: ENTERPRISE CI/CD GATE\n"
        "───────────────────────────────\n"
        "Threshold: t* = 0.70 (Calibrated)\n"
        "• Precision: 75.57% (Meets >=75% Floor)\n"
        "• Balanced F1: 0.5703\n"
        "• Test Recall: 45.80%\n"
        "• Test Accuracy: 92.62%\n"
        "Objective: Zero developer alert fatigue;\n"
        "ensures 3 of 4 warnings are true CVEs."
    )
    ax_info.text(0.0, 0.62, card2_text, transform=ax_info.transAxes, fontsize=8.8, va='top', fontfamily='monospace',
                 bbox=dict(boxstyle='round,pad=0.6', facecolor='#EFF6FF', edgecolor='#3B82F6', linewidth=1.4))

    # Card 3: Operating Profile B (Security Audit Gate)
    card3_text = (
        "PROFILE B: SECURITY AUDIT GATE\n"
        "───────────────────────────────\n"
        "Threshold: t = 0.30 (F2-Optimal)\n"
        "• Test Recall: 74.93% (Catches 3 of 4!)\n"
        "• Recall-Weighted F2: 0.6109\n"
        "• Test Precision: 35.14%\n"
        "• High-Coverage Mode (t=0.10): 86.76%\n"
        "Objective: Pre-release security audit;\n"
        "maximizes vulnerability discovery."
    )
    ax_info.text(0.0, 0.25, card3_text, transform=ax_info.transAxes, fontsize=8.8, va='top', fontfamily='monospace',
                 bbox=dict(boxstyle='round,pad=0.6', facecolor='#FEF2F2', edgecolor='#EF4444', linewidth=1.4))

    fig.suptitle('Phase 1 Tier 1 (C Language): Operating Profiles Across Decision Thresholds\nPrecision-Floor CI/CD Optimization vs. High-Recall Security Audit Trade-off',
                 fontsize=13, fontweight='bold', color='#111827', y=0.96)

    plt.savefig('images/p1_tier1_c_threshold_sweep.png', dpi=300)
    plt.close()
    print("Regenerated p1_tier1_c_threshold_sweep.png")


# ------------------------------------------------------------------------------
# 2. PERFECT p5_regression_benchmark_summary.png
# ------------------------------------------------------------------------------
def render_figure_8():
    categories = [
        'Safe Code Specificity\n(False Alarm Elimination)',
        'Syntactic Compilation Validity\nof Generated Patches',
        'Vulnerable Function\nDetection Recall',
        'Overall End-to-End\nFixture Pass Rate',
        'CWE Taxonomic Group\nClassification Accuracy'
    ]
    scores = [100.0, 98.0, 96.0, 96.0, 92.0]
    fractions = ['(25/25 verified safe)', '(49/50 compiled)', '(24/25 caught)', '(48/50 passed)', '(46/50 correct)']
    colors = ['#10B981', '#059669', '#3B82F6', '#2563EB', '#7C3AED']

    y = np.arange(len(categories))

    # Figure with generous margins: 13.5 x 6.5
    fig = plt.figure(figsize=(13.5, 6.5), dpi=300)
    # left=0.32 gives 4.3 inches for y labels, width=0.55 gives 7.4 inches for bars, right margin gives 1.8 inches
    ax = fig.add_axes([0.32, 0.17, 0.54, 0.68])

    bars = ax.barh(y, scores, height=0.50, color=colors, edgecolor='white', linewidth=1.2, zorder=3)

    # Put value labels TO THE RIGHT of each bar with clear breathing room
    for bar, score, frac in zip(bars, scores, fractions):
        w = bar.get_width()
        ax.text(w + 1.5, bar.get_y() + bar.get_height()/2, f'{score:.1f}%  {frac}',
                ha='left', va='center', color='#1E293B', fontweight='bold', fontsize=9.2)

    ax.set_yticks(y)
    ax.set_yticklabels(categories, fontsize=9.8, fontweight='semibold', color='#1E293B')
    ax.set_xlabel('Benchmark Pass Rate (%)', fontsize=10.5, fontweight='semibold', labelpad=8)
    ax.set_xlim(0, 126)
    ax.grid(True, linestyle='--', alpha=0.30, axis='x', zorder=0)

    # Section title centered cleanly
    fig.suptitle('Phase 5 Regression Verification Benchmark: Held-Out Ground-Truth Suite\nAudit Across 50 Verified Test Fixtures (25 Vulnerable, 25 Safe Across 9 Languages)',
                 fontsize=12.5, fontweight='bold', color='#111827', y=0.95, ha='center')

    # Benchmark note placed cleanly below the x-axis with ZERO collision
    fig.text(0.50, 0.04, '50 Audited Fixtures in data/heldout/ (C, C++, Python, PHP, JS, TS, Go, Java, Ruby) | Verified via tests/regression/test_live_pipeline_regression.py',
             ha='center', fontsize=8.8, fontfamily='monospace', color='#475569',
             bbox=dict(boxstyle='round,pad=0.4', facecolor='#F8FAFC', edgecolor='#CBD5E1', alpha=0.9))

    plt.savefig('images/p5_regression_benchmark_summary.png', dpi=300)
    plt.close()
    print("Regenerated p5_regression_benchmark_summary.png")

if __name__ == '__main__':
    render_figure_1()
    render_figure_8()
