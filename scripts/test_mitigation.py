#!/usr/bin/env python3
"""Test harness for mitigator / infer and /mitigate endpoints.

This script runs the mitigator app in-process (TestClient) and exercises
`/infer_from_pcap` across windows (using the repo extractor), triggers
mitigation when `is_alert` is returned, and writes a JSONL + CSV summary of
the mitigation attempts and per-pcap metrics.

By default this runs in dry-run mode (no real docker commands executed).
"""
import argparse
import csv
import json
import os
from collections import defaultdict

from fastapi.testclient import TestClient

from services.mitigator import app


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pcaps', nargs='+', default=['pcaps/attack_ddos.pcap', 'pcaps/baseline_industrial.pcap'])
    ap.add_argument('--dry-run', dest='dry_run', action='store_true', default=True)
    ap.add_argument('--out-jsonl', default='experiments/run_live_v1/mitigation_test_results.jsonl')
    ap.add_argument('--out-csv', default='experiments/run_live_v1/mitigation_test_results.csv')
    ap.add_argument('--max-windows-per-pcap', type=int, default=50)
    args = ap.parse_args()

    client = TestClient(app)

    os.makedirs(os.path.dirname(args.out_jsonl), exist_ok=True)

    summary = []
    per_pcap_stats = defaultdict(lambda: {'n_windows': 0, 'n_alerts': 0, 'n_mitigations': 0, 'unique_streams': set()})

    for pcap in args.pcaps:
        if not os.path.exists(pcap):
            print(f"pcap not found: {pcap}; skipping")
            continue
        # extract windows in-process
        try:
            from tools.pcap_to_features import extract_windows
        except Exception as e:
            print('extractor import failed:', e)
            return

        windows = extract_windows(pcap, window_size=10.0)
        if not windows:
            print('no windows for', pcap)
            continue

        n = min(len(windows), args.max_windows_per_pcap)
        for i in range(n):
            features = windows[i]
            features = {k: v for k, v in features.items() if k not in ('start_ts', 'end_ts')}
            resp = client.post('/infer', json={'features': features})
            if resp.status_code != 200:
                print('infer failed', resp.status_code, resp.text)
                continue
            data = resp.json()
            per_pcap_stats[pcap]['n_windows'] += 1
            entry = {
                'pcap': pcap,
                'window_index': i,
                'stream_key': data.get('stream_key'),
                'anomaly_score': data.get('anomaly_score'),
                'is_alert': data.get('is_alert'),
                'raw_is_anomaly': data.get('raw_is_anomaly'),
                'consecutive_anomaly_count': data.get('consecutive_anomaly_count'),
            }
            if data.get('is_alert'):
                per_pcap_stats[pcap]['n_alerts'] += 1
                per_pcap_stats[pcap]['unique_streams'].add(data.get('stream_key'))
                # call mitigate (dry_run default)
                mit_req = {
                    'stream_key': data.get('stream_key') or 'unknown',
                    'action': 'stop_service',
                    'target': {'pcap': pcap, 'window_index': i},
                    'duration_seconds': 60,
                    'reason': 'automated-test',
                    'dry_run': bool(args.dry_run),
                }
                mresp = client.post('/mitigate', json=mit_req)
                if mresp.status_code == 200:
                    entry['mitigation'] = mresp.json().get('event')
                    per_pcap_stats[pcap]['n_mitigations'] += 1
                else:
                    entry['mitigation_error'] = mresp.text

            summary.append(entry)

    # write JSONL and CSV
    with open(args.out_jsonl, 'w') as fh:
        for r in summary:
            fh.write(json.dumps(r) + '\n')

    # CSV header
    if summary:
        keys = ['pcap', 'window_index', 'stream_key', 'anomaly_score', 'is_alert', 'raw_is_anomaly', 'consecutive_anomaly_count', 'mitigation']
        with open(args.out_csv, 'w', newline='') as fh:
            writer = csv.DictWriter(fh, fieldnames=keys)
            writer.writeheader()
            for r in summary:
                row = {k: r.get(k) for k in keys}
                # flatten mitigation into a short status
                mit = r.get('mitigation')
                if mit:
                    row['mitigation'] = 'dry_run' if mit.get('dry_run') else 'executed'
                writer.writerow(row)

    # print per-pcap summary
    print('\nMitigation test summary:')
    for pcap, stats in per_pcap_stats.items():
        print(f"{pcap}: windows={stats['n_windows']}, alerts={stats['n_alerts']}, mitigations={stats['n_mitigations']}, unique_streams={len(stats['unique_streams'])}")


if __name__ == '__main__':
    main()
