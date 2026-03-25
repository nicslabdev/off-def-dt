#!/usr/bin/env python3
"""Create plots and an expanded markdown report from aggregated evasion CSVs.

Produces:
- experiments/recall_vs_eps.png
- experiments/f1_drop_hist.png
- experiments/aggregated_evasion_report_expanded.md
"""
import os
import sys
import pandas as pd
import numpy as np

EXPERIMENTS = os.path.join(os.path.dirname(__file__), '..', 'experiments')
OUT_RECALL = os.path.join(EXPERIMENTS, 'recall_vs_eps.png')
OUT_HIST = os.path.join(EXPERIMENTS, 'f1_drop_hist.png')
OUT_MD = os.path.join(EXPERIMENTS, 'aggregated_evasion_report_expanded.md')

def main():
    pa = os.path.join(EXPERIMENTS, 'aggregated_per_attack_evasion_summary.csv')
    pp = os.path.join(EXPERIMENTS, 'aggregated_per_protocol_evasion_summary.csv')
    if not os.path.exists(pa):
        print('Missing', pa); sys.exit(1)
    df_attack = pd.read_csv(pa)

    # ensure eps numeric
    df_attack['eps'] = df_attack['eps'].astype(float)

    # mean recall by eps before/after
    grp = df_attack.groupby('eps')
    stats = grp[['precision_before','recall_before','f1_before','precision_after','recall_after','f1_after']].mean().reset_index()

    # attempt to plot recall vs eps and histogram; if matplotlib unavailable, skip plots
    try:
        import matplotlib.pyplot as plt

        plt.figure(figsize=(6,4))
        plt.plot(stats['eps'], stats['recall_before'], marker='o', label='recall_before')
        plt.plot(stats['eps'], stats['recall_after'], marker='o', label='recall_after')
        plt.xlabel('epsilon')
        plt.ylabel('recall')
        plt.title('Mean Recall by Epsilon (per-attack)')
        plt.legend()
        plt.grid(alpha=0.3)
        plt.tight_layout()
        plt.savefig(OUT_RECALL)
        plt.close()

        # histogram of f1 drops across all rows (before-after)
        df_attack['f1_drop'] = df_attack['f1_before'] - df_attack['f1_after']
        plt.figure(figsize=(6,4))
        plt.hist(df_attack['f1_drop'].dropna(), bins=20)
        plt.xlabel('F1 before - F1 after')
        plt.ylabel('count')
        plt.title('F1 Drop Distribution (per-attack rows)')
        plt.tight_layout()
        plt.savefig(OUT_HIST)
        plt.close()
        plots_written = True
    except Exception as e:
        print('matplotlib not available or plotting failed:', e)
        plots_written = False

    # build markdown with tables using pandas -> to_markdown (tabulate required)
    md = []
    md.append('# Aggregated Evasion Report (Expanded)')
    md.append('')
    md.append('## Mean metrics by epsilon (per-attack)')
    md.append('')
    try:
        md.append(stats.round(4).to_markdown(index=False))
    except Exception:
        # fallback when `tabulate` is not installed: use a plain text table
        md.append('''```
%s
```''' % stats.round(4).to_string(index=False))
    md.append('')
    md.append('## Recall vs Epsilon')
    md.append('')
    if plots_written and os.path.exists(OUT_RECALL):
        md.append(f'![Recall vs eps]({os.path.basename(OUT_RECALL)})')
    else:
        md.append('- Plots skipped (matplotlib not available).')
    md.append('')
    md.append('## F1 drop distribution')
    md.append('')
    if plots_written and os.path.exists(OUT_HIST):
        md.append(f'![F1 drop hist]({os.path.basename(OUT_HIST)})')
    else:
        md.append('- Plots skipped (matplotlib not available).')
    md.append('')
    md.append('## Notes')
    md.append('- Plots saved in experiments/ as PNG files.')

    with open(OUT_MD, 'w') as fh:
        fh.write('\n'.join(md))
    print('Wrote', OUT_RECALL, OUT_HIST, OUT_MD)


if __name__ == '__main__':
    main()
