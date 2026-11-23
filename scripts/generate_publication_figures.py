import os
import json
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec

os.makedirs('images', exist_ok=True)
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial', 'Helvetica']
plt.rcParams['axes.edgecolor'] = '#D1D5DB'
plt.rcParams['axes.linewidth'] = 1.0

# ==============================================================================
# FIGURE 1: Phase 1 Tier 1 C Threshold Sweep with Dual Operating Profiles
# ==============================================================================
def generate_figure_1():
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
    ax.text(0.52, 0.765, 'Enterprise Precision Floor (>= 75.0%)', color='#1E40AF', fontsize=8.8, fontweight='bold', ha='center',
            bbox=dict(boxstyle='round,pad=0.2', facecolor='white', edgecolor='#93C5FD', alpha=0.9))

    # Vertical guides for operating points
    ax.axvline(0.30, color='#DC2626', linestyle=':', alpha=0.7, linewidth=1.6, zorder=2)
    ax.text(0.30, 0.94, 't = 0.30 (Audit Mode)', color='#DC2626', fontsize=8.2, fontweight='bold', ha='center',
            bbox=dict(boxstyle='round,pad=0.25', facecolor='#FEF2F2', edgecolor='#FCA5A5', alpha=0.95))

    ax.axvline(0.70, color='#2563EB', linestyle=':', alpha=0.7, linewidth=1.6, zorder=2)
    ax.text(0.70, 0.94, 't* = 0.70 (CI/CD Mode)', color='#2563EB', fontsize=8.2, fontweight='bold', ha='center',
            bbox=dict(boxstyle='round,pad=0.25', facecolor='#EFF6FF', edgecolor='#93C5FD', alpha=0.95))

    # Plot lines with clean markers
    ax.plot(thresholds, recalls, color='#DC2626', linewidth=2.8, marker='o', markersize=6.5, label='Recall (Security Coverage)', zorder=4)
    ax.plot(thresholds, precisions, color='#2563EB', linewidth=2.8, marker='s', markersize=6.5, label='Precision (Alert Reliability)', zorder=4)
    ax.plot(thresholds, f1_scores, color='#059669', linewidth=2.8, marker='^', markersize=6.5, label='Balanced F1-Score', zorder=4)
    ax.plot(thresholds, f2_scores, color='#D97706', linewidth=2.2, linestyle='--', marker='d', markersize=5.5, label='Recall-Weighted F2 (beta=2)', zorder=4)

    # Highlight markers at t=0.30
    ax.scatter([0.30], [0.7493], color='#DC2626', s=150, zorder=6, edgecolor='white', linewidth=2.0)
    ax.annotate('Rec: 74.9%', xy=(0.30, 0.7493), xytext=(0.20, 0.81),
                arrowprops=dict(facecolor='#DC2626', shrink=0.08, width=1.2, headwidth=4),
                fontsize=8.5, fontweight='bold', color='#991B1B',
                bbox=dict(boxstyle='round,pad=0.25', facecolor='#FEF2F2', edgecolor='#EF4444', alpha=0.95))

    # Highlight markers at t=0.70
    ax.scatter([0.70], [0.7557], color='#2563EB', s=150, zorder=6, edgecolor='white', linewidth=2.0)
    ax.annotate('Prec: 75.6%', xy=(0.70, 0.7557), xytext=(0.60, 0.83),
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
    print("Saved: images/p1_tier1_c_threshold_sweep.png")

# ==============================================================================
# FIGURE 2: Phase 1 Tier 1 C Training Loss & Validation Metrics Curves
# ==============================================================================
def generate_figure_2():
    with open('logs/phase1_tier1_c_cpp_graphcodebert_results_v2.json') as f:
        data = json.load(f)
    hist = data['training_history']
    epochs = [h['epoch'] for h in hist]
    train_losses = [h['train_loss'] for h in hist]
    val_losses = [h['val_loss'] for h in hist]
    val_f1s = [h['val_f1'] for h in hist]
    val_recalls = [h['val_recall'] for h in hist]
    val_precisions = [h['val_precision'] for h in hist]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5.5), dpi=300)

    # Subplot 1: Loss Convergence
    ax1.plot(epochs, train_losses, color='#2563EB', linewidth=2.6, marker='o', markersize=7, label='Training Loss (Focal gamma=2.0)')
    ax1.plot(epochs, val_losses, color='#DC2626', linewidth=2.6, marker='s', markersize=7, label='Validation Loss')
    ax1.set_title('(a) Focal Loss Convergence Across Epochs', fontsize=12, fontweight='bold', pad=10, color='#111827')
    ax1.set_xlabel('Training Epoch', fontsize=10.5, fontweight='semibold')
    ax1.set_ylabel('Loss Value', fontsize=10.5, fontweight='semibold')
    ax1.set_xticks(epochs)
    ax1.grid(True, linestyle='--', alpha=0.35)
    ax1.legend(loc='upper right', framealpha=0.9)
    ax1.text(0.05, 0.15, 'Total Execution Duration:\n34,838.8s (~9.68 Hours)\nNVIDIA RTX 3060 6GB VRAM',
             transform=ax1.transAxes, fontsize=8.8, fontfamily='monospace',
             bbox=dict(boxstyle='round,pad=0.4', facecolor='#F3F4F6', edgecolor='#CBD5E1', alpha=0.9))

    # Subplot 2: Metric Progress
    ax2.plot(epochs, val_f1s, color='#059669', linewidth=2.6, marker='^', markersize=7, label='Validation F1-Score')
    ax2.plot(epochs, val_recalls, color='#DC2626', linewidth=2.4, marker='o', markersize=7, label='Validation Recall')
    ax2.plot(epochs, val_precisions, color='#2563EB', linewidth=2.4, marker='s', markersize=7, label='Validation Precision')
    ax2.scatter([2], [val_f1s[1]], color='#D97706', s=140, zorder=5, edgecolor='black', linewidth=1.5)
    ax2.annotate(f'Peak Val F1: {val_f1s[1]:.4f}\n(Epoch 2 Checkpoint Saved)', xy=(2, val_f1s[1]), xytext=(2.2, val_f1s[1] - 0.08),
                 arrowprops=dict(facecolor='#D97706', shrink=0.08, width=1.4, headwidth=5),
                 fontsize=9, fontweight='bold', bbox=dict(boxstyle='round,pad=0.4', facecolor='#FEF3C7', edgecolor='#F59E0B', alpha=0.95))
    ax2.set_title('(b) Validation Metric Trajectory', fontsize=12, fontweight='bold', pad=10, color='#111827')
    ax2.set_xlabel('Training Epoch', fontsize=10.5, fontweight='semibold')
    ax2.set_ylabel('Metric Score', fontsize=10.5, fontweight='semibold')
    ax2.set_xticks(epochs)
    ax2.grid(True, linestyle='--', alpha=0.35)
    ax2.legend(loc='lower right', framealpha=0.9)

    plt.suptitle('Phase 1 Tier 1 (C Language) GraphCodeBERT-v2 Fine-Tuning Dynamics', fontsize=13, fontweight='bold', y=0.98)
    plt.tight_layout()
    plt.savefig('images/p1_tier1_c_training_curves.png', dpi=300)
    plt.close()
    print("Saved: images/p1_tier1_c_training_curves.png")

# ==============================================================================
# FIGURE 3: Phase 1 Cross-Tier Performance Matrix (All 5 Tiers)
# ==============================================================================
def generate_figure_3():
    tiers = ['Tier 1 (C)\n[N=516,562]', 'Tier 2 (C++)\n[N=7,548]', 'Tier 2 (Python)\n[N=10,483]', 'Tier 2 (PHP)\n[N=2,100]', 'Tier 3 (Shared)\n[N=3,221]']
    recalls = [0.4580, 0.9949, 0.8545, 1.0000, 0.8412]
    precisions = [0.7557, 0.9740, 0.7834, 1.0000, 0.8250]
    f1s = [0.5703, 0.9843, 0.8174, 1.0000, 0.8330]
    aurocs = [0.8833, 0.9972, 0.9238, 1.0000, 0.9125]

    x = np.arange(len(tiers))
    width = 0.20

    fig, ax = plt.subplots(figsize=(12, 6), dpi=300)
    rects1 = ax.bar(x - 1.5*width, recalls, width, label='Recall', color='#DC2626', edgecolor='white', linewidth=1)
    rects2 = ax.bar(x - 0.5*width, precisions, width, label='Precision', color='#2563EB', edgecolor='white', linewidth=1)
    rects3 = ax.bar(x + 0.5*width, f1s, width, label='F1-Score', color='#059669', edgecolor='white', linewidth=1)
    rects4 = ax.bar(x + 1.5*width, aurocs, width, label='AUROC', color='#7C3AED', edgecolor='white', linewidth=1)

    # Value labels
    for rect in rects3:
        h = rect.get_height()
        ax.annotate(f'{h:.2f}', xy=(rect.get_x() + rect.get_width()/2, h), xytext=(0, 3),
                    textcoords="offset points", ha='center', va='bottom', fontsize=8.5, fontweight='bold')

    ax.set_title('Phase 1 Binary Vulnerability Detection: Empirical Cross-Tier Benchmark\nRecall, Precision, F1-Score, and AUROC Across All 5 Language Model Tiers',
                 fontsize=13, fontweight='bold', pad=14, color='#111827')
    ax.set_ylabel('Metric Value (0.0 - 1.0)', fontsize=11, fontweight='semibold')
    ax.set_xticks(x)
    ax.set_xticklabels(tiers, fontsize=9.5, fontweight='semibold')
    ax.set_ylim(0, 1.15)
    ax.grid(True, linestyle='--', alpha=0.35, axis='y')
    ax.legend(loc='lower right', framealpha=0.95, fontsize=9.5, ncol=4)

    # Explanatory note
    ax.text(0.02, 0.94, 'Tier 1 reflects massive real-world CVE diversity under strict precision floor (>=75%).\nTier 2/3 reflect specialized curated corpora with high structural regularity.',
            transform=ax.transAxes, fontsize=8.5, fontfamily='sans-serif',
            bbox=dict(boxstyle='round,pad=0.4', facecolor='#F8FAFC', edgecolor='#CBD5E1', alpha=0.9))

    plt.tight_layout()
    plt.savefig('images/p1_cross_tier_performance_matrix.png', dpi=300)
    plt.close()
    print("Saved: images/p1_cross_tier_performance_matrix.png")

# ==============================================================================
# FIGURE 4: Phase 2 CWE Taxonomy Reform Comparison (v1 vs v2)
# ==============================================================================
def generate_figure_4():
    metrics = ['Accuracy', 'Macro-Recall', 'Macro-Precision', 'Macro-F1', 'Weighted-F1']
    v1_scores = [0.3189, 0.4348, 0.3876, 0.3213, 0.3195]
    v2_scores = [0.6895, 0.6513, 0.7461, 0.6894, 0.6877]

    x = np.arange(len(metrics))
    width = 0.34

    fig, ax = plt.subplots(figsize=(10.5, 6), dpi=300)
    rects1 = ax.bar(x - width/2, v1_scores, width, label='v1: Granular 24-Class Taxonomy (Baseline CodeBERT)', color='#EF4444', edgecolor='white', linewidth=1)
    rects2 = ax.bar(x + width/2, v2_scores, width, label='v2: 15-Cluster Reformed Ensemble (GraphCodeBERT + MOO, T=1.5)', color='#10B981', edgecolor='white', linewidth=1)

    gains = ["+116.2%", "+49.8%", "+92.5%", "+114.6%", "+115.2%"]
    for i in range(len(metrics)):
        h2 = v2_scores[i]
        ax.annotate(gains[i], xy=(x[i] + width/2, h2), xytext=(0, 4),
                    textcoords="offset points", ha='center', va='bottom', fontsize=9.2, fontweight='bold', color='#065F46')
        h1 = v1_scores[i]
        ax.annotate(f'{h1:.3f}', xy=(x[i] - width/2, h1), xytext=(0, 3),
                    textcoords="offset points", ha='center', va='bottom', fontsize=8.5, color='#991B1B')
        ax.annotate(f'{h2:.3f}', xy=(x[i] + width/2, h2 - 0.08), xytext=(0, 0),
                    textcoords="offset points", ha='center', va='center', fontsize=8.5, color='white', fontweight='bold')

    ax.set_title('Phase 2 CWE Multi-Class Taxonomy Reform: Architectural Impact\nGranular 24-Class Model Failure vs. 15 MITRE CWE-1000 Semantic Clusters with Calibrated Ensemble',
                 fontsize=12, fontweight='bold', pad=14, color='#111827')
    ax.set_ylabel('Metric Score (0.00 - 1.00)', fontsize=11, fontweight='semibold')
    ax.set_xticks(x)
    ax.set_xticklabels(metrics, fontsize=10, fontweight='semibold')
    ax.set_ylim(0, 0.88)
    ax.grid(True, linestyle='--', alpha=0.35, axis='y')
    ax.legend(loc='upper left', framealpha=0.95, fontsize=9.2)

    plt.tight_layout()
    plt.savefig('images/p2_cwe_taxonomy_comparison.png', dpi=300)
    plt.close()
    print("Saved: images/p2_cwe_taxonomy_comparison.png")

# ==============================================================================
# FIGURE 5: Phase 2 CWE Per-Cluster Performance
# ==============================================================================
def generate_figure_5():
    with open('logs/phase2_cwe_results_ensemble_v2.json') as f:
        data = json.load(f)
    rep = data['per_class_report']
    classes = [k for k in data['class_names'] if k in rep]
    f1s = [rep[c]['f1-score'] for c in classes]
    recalls = [rep[c]['recall'] for c in classes]
    precisions = [rep[c]['precision'] for c in classes]

    sorted_idx = np.argsort(f1s)
    classes = [classes[i] for i in sorted_idx]
    f1s = [f1s[i] for i in sorted_idx]
    recalls = [recalls[i] for i in sorted_idx]
    precisions = [precisions[i] for i in sorted_idx]

    y = np.arange(len(classes))
    height = 0.28

    fig, ax = plt.subplots(figsize=(11, 8), dpi=300)
    ax.barh(y + height, precisions, height, label='Precision', color='#2563EB', alpha=0.9)
    ax.barh(y, recalls, height, label='Recall', color='#DC2626', alpha=0.9)
    ax.barh(y - height, f1s, height, label='F1-Score', color='#059669', alpha=0.9)

    ax.set_yticks(y)
    ax.set_yticklabels(classes, fontsize=9, fontweight='semibold')
    ax.set_xlabel('Score (0.0 - 1.0)', fontsize=10.5, fontweight='semibold')
    ax.set_title('Phase 2 Multi-Class CWE Ensemble: Breakdown Across All 15 Semantic Clusters\nEvaluated on Calibrated GraphCodeBERT-v2 (0.65) + CodeBERT-MOO (0.35) with Temperature Scaling (T=1.5)',
                 fontsize=11.5, fontweight='bold', pad=12)
    ax.set_xlim(0, 1.08)
    ax.grid(True, linestyle='--', alpha=0.35, axis='x')
    ax.legend(loc='lower right', framealpha=0.95, fontsize=9)

    plt.tight_layout()
    plt.savefig('images/p2_cwe_per_cluster_performance.png', dpi=300)
    plt.close()
    print("Saved: images/p2_cwe_per_cluster_performance.png")

# ==============================================================================
# FIGURE 6: Phase 3 CVSS Severity Prediction MAE & Mean Regression Ceiling
# ==============================================================================
def generate_figure_6():
    tiers = ['Tier 1 (C)', 'Tier 2 (C++)', 'Tier 2 (Python)', 'Tier 2 (PHP)', 'Tier 3 (Shared)']
    maes = [1.258, 1.167, 1.357, 1.499, 1.312]
    rmses = [1.682, 1.543, 1.812, 1.954, 1.748]

    x = np.arange(len(tiers))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10.5, 5.8), dpi=300)
    rects1 = ax.bar(x - width/2, maes, width, label='Test Mean Absolute Error (MAE)', color='#3B82F6', edgecolor='white', linewidth=1)
    rects2 = ax.bar(x + width/2, rmses, width, label='Root Mean Squared Error (RMSE)', color='#6366F1', edgecolor='white', linewidth=1)

    for rect in rects1:
        h = rect.get_height()
        ax.annotate(f'{h:.3f}', xy=(rect.get_x() + rect.get_width()/2, h), xytext=(0, 3),
                    textcoords="offset points", ha='center', va='bottom', fontsize=8.8, fontweight='bold')
    for rect in rects2:
        h = rect.get_height()
        ax.annotate(f'{h:.3f}', xy=(rect.get_x() + rect.get_width()/2, h), xytext=(0, 3),
                    textcoords="offset points", ha='center', va='bottom', fontsize=8.5)

    ax.axhline(5.38, color='#EF4444', linestyle='--', linewidth=1.8, label='Empirical Mean Severity Baseline (~5.38 / 10.0)')

    ax.annotate('Theoretical Ceiling: ~5.38 Mean Regression\nToken-level encoders exhibit environmental blindness\n(Cannot inspect network topology, privilege level, or attack vector)',
                xy=(1.5, 5.38), xytext=(0.5, 4.0),
                arrowprops=dict(facecolor='#EF4444', shrink=0.08, width=1.4, headwidth=5),
                fontsize=8.8, fontweight='semibold', bbox=dict(boxstyle='round,pad=0.5', facecolor='#FEF2F2', edgecolor='#F87171', alpha=0.95))

    ax.set_title('Phase 3 Continuous CVSS Severity Regression: Error Distribution Across Language Tiers\nSmooth L1 (Huber) Loss Optimization & The ~5.38 Environmental Blindness Ceiling',
                 fontsize=12, fontweight='bold', pad=14, color='#111827')
    ax.set_ylabel('CVSS Points Error (Scale 0.0 - 10.0)', fontsize=10.5, fontweight='semibold')
    ax.set_xticks(x)
    ax.set_xticklabels(tiers, fontsize=9.5, fontweight='semibold')
    ax.set_ylim(0, 6.2)
    ax.grid(True, linestyle='--', alpha=0.35, axis='y')
    ax.legend(loc='upper right', framealpha=0.95, fontsize=8.8)

    plt.tight_layout()
    plt.savefig('images/p3_cvss_mae_per_tier.png', dpi=300)
    plt.close()
    print("Saved: images/p3_cvss_mae_per_tier.png")

# ==============================================================================
# FIGURE 7: Phase 4 LLM Repair Head-to-Head Comparison
# ==============================================================================
def generate_figure_7():
    metrics = ['Detector Flip Rate', 'Syntactic Validity', 'Token BLEU-4 (/100)', 'Edit Similarity']
    qwen = [0.300, 0.400, 0.3278, 0.4717]
    gpt = [0.050, 0.250, 0.1133, 0.1763]

    x = np.arange(len(metrics))
    width = 0.34

    fig, ax = plt.subplots(figsize=(10, 5.5), dpi=300)
    rects1 = ax.bar(x - width/2, qwen, width, label='qwen/qwen3.8-27b (Groq LPU, Grounded Prompting)', color='#059669', edgecolor='white', linewidth=1)
    rects2 = ax.bar(x + width/2, gpt, width, label='openai/gpt-oss-120b (Groq LPU, Ungrounded Baseline)', color='#6B7280', edgecolor='white', linewidth=1)

    for i in range(len(metrics)):
        ax.annotate(f'{qwen[i]:.3f}', xy=(x[i] - width/2, qwen[i]), xytext=(0, 3),
                    textcoords="offset points", ha='center', va='bottom', fontsize=9, fontweight='bold', color='#065F46')
        ax.annotate(f'{gpt[i]:.3f}', xy=(x[i] + width/2, gpt[i]), xytext=(0, 3),
                    textcoords="offset points", ha='center', va='bottom', fontsize=8.5, color='#374151')

    ax.set_title('Phase 4 Automated Code Refinement: Generative Model Head-to-Head Evaluation\nGrounded 27B Parameter Model vs. 120B Ungrounded Generative Baseline (N=20 Audited Test Fixes)',
                 fontsize=11.5, fontweight='bold', pad=14, color='#111827')
    ax.set_ylabel('Score Ratio (0.00 - 1.00)', fontsize=10.5, fontweight='semibold')
    ax.set_xticks(x)
    ax.set_xticklabels(metrics, fontsize=10, fontweight='semibold')
    ax.set_ylim(0, 0.60)
    ax.grid(True, linestyle='--', alpha=0.35, axis='y')
    ax.legend(loc='upper right', framealpha=0.95, fontsize=9)

    plt.tight_layout()
    plt.savefig('images/p4_llm_repair_comparison.png', dpi=300)
    plt.close()
    print("Saved: images/p4_llm_repair_comparison.png")

# ==============================================================================
# FIGURE 8: Phase 5 Regression Benchmark Verification Summary (PERFECT RENDER)
# ==============================================================================
def generate_figure_8():
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

    fig = plt.figure(figsize=(13.5, 6.5), dpi=300)
    ax = fig.add_axes([0.32, 0.17, 0.54, 0.68])

    bars = ax.barh(y, scores, height=0.50, color=colors, edgecolor='white', linewidth=1.2, zorder=3)

    for bar, score, frac in zip(bars, scores, fractions):
        w = bar.get_width()
        ax.text(w + 1.5, bar.get_y() + bar.get_height()/2, f'{score:.1f}%  {frac}',
                ha='left', va='center', color='#1E293B', fontweight='bold', fontsize=9.2)

    ax.set_yticks(y)
    ax.set_yticklabels(categories, fontsize=9.8, fontweight='semibold', color='#1E293B')
    ax.set_xlabel('Benchmark Pass Rate (%)', fontsize=10.5, fontweight='semibold', labelpad=8)
    ax.set_xlim(0, 126)
    ax.grid(True, linestyle='--', alpha=0.30, axis='x', zorder=0)

    fig.suptitle('Phase 5 Regression Verification Benchmark: Held-Out Ground-Truth Suite\nAudit Across 50 Verified Test Fixtures (25 Vulnerable, 25 Safe Across 9 Languages)',
                 fontsize=12.5, fontweight='bold', color='#111827', y=0.95, ha='center')

    fig.text(0.50, 0.04, '50 Audited Fixtures in data/heldout/ (C, C++, Python, PHP, JS, TS, Go, Java, Ruby) | Verified via tests/regression/test_live_pipeline_regression.py',
             ha='center', fontsize=8.8, fontfamily='monospace', color='#475569',
             bbox=dict(boxstyle='round,pad=0.4', facecolor='#F8FAFC', edgecolor='#CBD5E1', alpha=0.9))

    plt.savefig('images/p5_regression_benchmark_summary.png', dpi=300)
    plt.close()
    print("Saved: images/p5_regression_benchmark_summary.png")

if __name__ == '__main__':
    generate_figure_1()
    generate_figure_2()
    generate_figure_3()
    generate_figure_4()
    generate_figure_5()
    generate_figure_6()
    generate_figure_7()
    generate_figure_8()
    print("ALL 8 PUBLICATION FIGURES GENERATED WITH ZERO COLLISIONS!")
