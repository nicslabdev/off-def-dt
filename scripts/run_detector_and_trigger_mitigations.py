#!/usr/bin/env python3
"""Run detector against attack pcaps and call /mitigate for alerted windows.

Usage:
  python scripts/run_detector_and_trigger_mitigations.py --run experiments/run_live_v1 --mitigator http://127.0.0.1:8080 --dry-run

This script will:
 - iterate attack_*.pcap files in the run dir
 - for each window (based on attack_*.csv) call POST /infer_from_pcap
 - if response indicates is_alert (or is_anomaly), call POST /mitigate with action stop_service (dry_run by default)
 - append mitigation events will be logged by the mitigator service

Note: mitigator service must be running (uvicorn) at --mitigator
"""
import argparse
import os
import requests
import time
import json
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--run', required=True)
    p.add_argument('--mitigator', default='http://127.0.0.1:8080')
    p.add_argument('--dry-run', action='store_true', default=True, dest='dry_run', help='send dry-run mitigations (default)')
    p.add_argument('--max-windows-per-file', type=int, default=None)
    args = p.parse_args()

    runp = Path(args.run)
    mit = args.mitigator.rstrip('/')

    attack_csvs = sorted(runp.glob('attack_*.csv'))
    attack_pcaps = {p.stem.replace('attack_',''): runp / (p.stem + '.pcap') for p in sorted(runp.glob('attack_*.csv'))}

    for name, csvp in [(p.stem.replace('attack_',''), p) for p in sorted(runp.glob('attack_*.csv'))]:
        pcap = runp / f'attack_{name}.pcap'
        if not pcap.exists():
            print('missing pcap for', name, pcap)
            continue
        # count windows from csv
        n_windows = 0
        try:
            with open(runp / f'attack_{name}.csv','r') as fh:
                for ln in fh:
                    if ln.strip():
                        n_windows += 1
        except Exception:
            n_windows = 50
        if args.max_windows_per_file:
            n_windows = min(n_windows, args.max_windows_per_file)
        print(f'Checking {name}: pcap={pcap}, windows={n_windows}')
        for i in range(n_windows):
            try:
                r = requests.post(mit + '/infer_from_pcap', json={'pcap_path': str(pcap), 'window_index': i, 'window_size': 3.0}, timeout=10)
                if r.status_code != 200:
                    print('infer error', r.status_code, r.text)
                    continue
                j = r.json()
            except Exception as e:
                print('request failed', e)
                continue
            # consider is_alert first, else is_anomaly
            if j.get('is_alert') or j.get('is_anomaly'):
                # prepare stream_key if present
                sk = j.get('stream_key') or f'{name}:{i}'
                payload = {
                    'stream_key': sk,
                    'action': 'stop_service',
                    'target': {'pcap': str(pcap), 'window_index': i},
                    'reason': 'detector-alert',
                    'dry_run': bool(args.dry_run),
                }
                try:
                    mr = requests.post(mit + '/mitigate', json=payload, timeout=5)
                    if mr.status_code == 200:
                        print('mitigation logged for', sk, 'window', i)
                    else:
                        print('mitigate error', mr.status_code, mr.text)
                except Exception as e:
                    print('mitigate request failed', e)
            time.sleep(0.05)

if __name__ == '__main__':
    main()
