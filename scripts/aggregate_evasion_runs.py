#!/usr/bin/env python3
"""Aggregate per-run evasion summaries into master CSVs and a markdown report.

Writes:
- experiments/aggregated_per_attack_evasion_summary.csv
- experiments/aggregated_per_protocol_evasion_summary.csv
- experiments/aggregated_evasion_report.md
"""
import os
import sys
import glob
import pandas as pd

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
EXPERIMENTS = os.path.join(ROOT, 'experiments')


def find_runs(prefix='run_live_evasion_v'):
    paths = sorted(glob.glob(os.path.join(EXPERIMENTS, prefix + '*')))
    return [p for p in paths if os.path.isdir(p)]


def aggregate():
    runs = find_runs()
    attack_rows = []
    proto_rows = []
    for r in runs:
        run_id = os.path.basename(r)
        pa = os.path.join(r, 'per_attack_evasion_summary.csv')
        pp = os.path.join(r, 'per_protocol_evasion_summary.csv')
        if os.path.exists(pa):
            df = pd.read_csv(pa)
            df['run_id'] = run_id
            attack_rows.append(df)
        if os.path.exists(pp):
            df = pd.read_csv(pp)
            df['run_id'] = run_id
            proto_rows.append(df)

    if attack_rows:
        df_attack = pd.concat(attack_rows, ignore_index=True)
        out_attack = os.path.join(EXPERIMENTS, 'aggregated_per_attack_evasion_summary.csv')
        df_attack.to_csv(out_attack, index=False)
    else:
        df_attack = None
        out_attack = None

    if proto_rows:
        df_proto = pd.concat(proto_rows, ignore_index=True)
        out_proto = os.path.join(EXPERIMENTS, 'aggregated_per_protocol_evasion_summary.csv')
        df_proto.to_csv(out_proto, index=False)
    else:
        df_proto = None
        out_proto = None

    # write a short markdown report
    md = []
    md.append('# Aggregated Evasion Summary')
    md.append('')
    if out_attack:
        md.append(f'- Per-attack aggregated CSV: {os.path.relpath(out_attack)}')
        md.append('')
        # compute simple stats by eps
        try:
            grp = df_attack.groupby('eps')
            cols = ['precision_before','recall_before','f1_before','precision_after','recall_after','f1_after']
            # include countermeasure columns if present
            for c in ('precision_after_cm','recall_after_cm','f1_after_cm'):
                if c in df_attack.columns:
                    cols.append(c)
            stats = grp[cols].mean()
            md.append('## Mean metrics by epsilon (per-attack)')
            md.append('')
            md.append(stats.round(4).to_markdown())
            md.append('')
        except Exception:
            pass
    if out_proto:
        md.append(f'- Per-protocol aggregated CSV: {os.path.relpath(out_proto)}')
        md.append('')
        try:
            grp = df_proto.groupby('eps')
            cols = ['precision_before','recall_before','f1_before','precision_after','recall_after','f1_after']
            for c in ('precision_after_cm','recall_after_cm','f1_after_cm'):
                if c in df_proto.columns:
                    cols.append(c)
            stats = grp[cols].mean()
            md.append('## Mean metrics by epsilon (per-protocol)')
            md.append('')
            md.append(stats.round(4).to_markdown())
            md.append('')
        except Exception:
            pass

    md_path = os.path.join(EXPERIMENTS, 'aggregated_evasion_report.md')
    with open(md_path, 'w') as fh:
        fh.write('\n'.join(md))
    print('Wrote', out_attack, out_proto, md_path)


if __name__ == '__main__':
    aggregate()
