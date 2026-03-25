#!/usr/bin/env python3
"""Run detector in-process by importing the mitigator module and call mitigate for alerted windows.

This avoids HTTP and runs inference/mitigation handlers directly in-process.
"""
import os
import importlib.util
import sys
import time
import json
from pathlib import Path

MITIGATOR_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'services', 'mitigator', 'app.py'))
spec = importlib.util.spec_from_file_location('mitigator_app', MITIGATOR_PATH)
mitigator_mod = importlib.util.module_from_spec(spec)
# Ensure repo root is on sys.path so `tools` imports resolve during lazy imports
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
spec.loader.exec_module(mitigator_mod)

PcapRequest = mitigator_mod.PcapRequest
MitigateRequest = mitigator_mod.MitigateRequest

RUN_DIR = 'experiments/run_live_v1'
MIT_LOG = os.getenv('MITIGATION_LOG', os.path.join(RUN_DIR, 'mitigation_log.jsonl'))


def read_csv_windows(csvpath):
    rows = []
    if not os.path.exists(csvpath):
        return rows
    with open(csvpath,'r') as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            parts = ln.split(',')
            try:
                s = float(parts[0]); e = float(parts[1])
                rows.append((s,e))
            except Exception:
                continue
    return rows


def main():
    runp = Path(RUN_DIR)
    attack_csvs = sorted(runp.glob('attack_*.csv'))
    count_mit = 0
    for af in attack_csvs:
        name = af.stem.replace('attack_', '')
        pcap = runp / f'attack_{name}.pcap'
        windows = read_csv_windows(str(af))
        print('Processing', name, 'pcap', pcap, 'windows=', len(windows))
        for idx in range(len(windows)):
            req = PcapRequest(pcap_path=str(pcap), window_index=idx, window_size=3.0)
            try:
                resp = mitigator_mod.infer_from_pcap(req)
            except Exception as e:
                print('infer failed for', name, idx, e)
                continue
            if resp.get('is_alert') or resp.get('is_anomaly'):
                sk = resp.get('stream_key') or f'{name}:{idx}'
                mreq = MitigateRequest(stream_key=sk, action='stop_service', target={'pcap': str(pcap), 'window_index': idx}, reason='inprocess-detector', dry_run=True)
                try:
                    out = mitigator_mod.mitigate(mreq)
                    count_mit += 1
                    print('mitigated (dry-run) for', sk)
                except Exception as e:
                    print('mitigate failed', e)
            time.sleep(0.01)
    print('done. total mitigations (dry-run) logged:', count_mit)
    # show last few log lines
    if os.path.exists(MIT_LOG):
        with open(MIT_LOG,'r') as fh:
            lines = fh.readlines()[-10:]
            print('--- tail of mitigation log ---')
            for ln in lines:
                print(ln.strip())

if __name__ == '__main__':
    main()
