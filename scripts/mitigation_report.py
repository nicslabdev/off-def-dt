#!/usr/bin/env python3
"""Produce a per-attack-window mitigation report CSV.

Output columns:
- run: run directory
- attack_file: filename
- window_index: index (0-based) within that attack file
- start_ts, end_ts: float epoch seconds
- mitigated: bool (was a mitigation found within window or within max_delay)
- mitigation_id: id from mitigation log (or empty)
- mitigation_ts: ISO ts of mitigation (or empty)
- latency_seconds: mitigation_ts - start_ts (or empty)
- dry_run: bool|null
- action: mitigation action|null

Usage:
  python scripts/mitigation_report.py --run experiments/run_live_v1

"""
import argparse
import os
import glob
import json
import csv
from datetime import datetime, timezone


def parse_iso_to_epoch(s):
    try:
        # Python 3.11+: fromisoformat handles offset; but be robust
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        try:
            # fallback: parse as float
            return float(s)
        except Exception:
            return None


def load_mitigations(path):
    res = []
    if not os.path.exists(path):
        return res
    with open(path, 'r') as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                j = json.loads(ln)
            except Exception:
                continue
            ts = j.get('ts')
            if ts is None:
                # maybe event has numeric ts
                ts_epoch = None
            else:
                ts_epoch = parse_iso_to_epoch(ts)
            j['_ts_epoch'] = ts_epoch
            res.append(j)
    # sort by ts
    res.sort(key=lambda x: x.get('_ts_epoch') if x.get('_ts_epoch') is not None else 0)
    return res


def read_attack_windows(attack_csv_path):
    windows = []
    if not os.path.exists(attack_csv_path):
        return windows
    with open(attack_csv_path, 'r') as fh:
        reader = csv.DictReader(fh)
        for i, row in enumerate(reader):
            try:
                start_ts = float(row.get('start_ts') or row.get('start') or '')
                end_ts = float(row.get('end_ts') or row.get('end') or '')
            except Exception:
                continue
            windows.append({'index': i, 'start_ts': start_ts, 'end_ts': end_ts, 'row': row})
    return windows


def find_first_mitigation_in_window(mitigations, start_ts, end_ts, max_delay=None, ignore_dry_run=False):
    # Find earliest mitigation with _ts_epoch in [start_ts, end_ts + max_delay]
    best = None
    limit_end = end_ts + (max_delay or 0)
    for m in mitigations:
        t = m.get('_ts_epoch')
        if t is None:
            continue
        if ignore_dry_run and m.get('dry_run'):
            continue
        if t >= start_ts and t <= limit_end:
            best = m
            break
    return best


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', required=True, help='run directory (e.g. experiments/run_live_v1)')
    parser.add_argument('--mitigation-log', default=None, help='path to mitigation_log.jsonl (defaults to <run>/mitigation_log.jsonl)')
    parser.add_argument('--out', default=None, help='output CSV path (defaults to <run>/mitigation_report.csv)')
    parser.add_argument('--max-delay', type=float, default=0.0, help='allow matching mitigations up to N seconds after window end')
    parser.add_argument('--ignore-dry-run', action='store_true', help='ignore dry_run events when matching mitigations')
    args = parser.parse_args()

    run_dir = args.run
    mitigation_log = args.mitigation_log or os.path.join(run_dir, 'mitigation_log.jsonl')
    out_csv = args.out or os.path.join(run_dir, 'mitigation_report.csv')

    mitigations = load_mitigations(mitigation_log)
    attack_pattern = os.path.join(run_dir, 'attack_*.csv')
    attack_files = sorted(glob.glob(attack_pattern))

    rows = []
    for af in attack_files:
        windows = read_attack_windows(af)
        for w in windows:
            start_ts = w['start_ts']
            end_ts = w['end_ts']
            m = find_first_mitigation_in_window(mitigations, start_ts, end_ts, max_delay=args.max_delay, ignore_dry_run=args.ignore_dry_run)
            if m:
                mid = m.get('id') or ''
                mts = m.get('ts') or ''
                latency = None
                if m.get('_ts_epoch') is not None:
                    latency = m.get('_ts_epoch') - start_ts
                dry_run = m.get('dry_run') if 'dry_run' in m else ''
                action = m.get('action') if 'action' in m else ''
                mitigated = True
            else:
                mid = ''
                mts = ''
                latency = ''
                dry_run = ''
                action = ''
                mitigated = False
            rows.append({
                'run': run_dir,
                'attack_file': os.path.basename(af),
                'window_index': int(w['index']),
                'start_ts': float(start_ts),
                'end_ts': float(end_ts),
                'mitigated': mitigated,
                'mitigation_id': mid,
                'mitigation_ts': mts,
                'latency_seconds': latency,
                'dry_run': dry_run,
                'action': action,
            })

    # write CSV
    fieldnames = ['run','attack_file','window_index','start_ts','end_ts','mitigated','mitigation_id','mitigation_ts','latency_seconds','dry_run','action']
    os.makedirs(os.path.dirname(out_csv), exist_ok=True)
    with open(out_csv, 'w', newline='') as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

    print(f'Wrote report with {len(rows)} rows to {out_csv}')


if __name__ == '__main__':
    main()
