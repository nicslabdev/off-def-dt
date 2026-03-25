#!/usr/bin/env python3
import requests, json, statistics
from pathlib import Path

OUTDIR = Path('experiments/run_live_v1')
MIT = 'http://127.0.0.1:8080'
pcaps = {
  'baseline': OUTDIR / 'baseline_replica.pcap'
}
# add attack pcaps discovered
for p in sorted(OUTDIR.glob('attack_*.pcap')):
    pcaps[p.stem.replace('attack_','')] = p

summary = {}
for name, p in pcaps.items():
    if not p.exists():
        print('missing pcap', p)
        continue
    # guess number of windows from the csv rows if available (fast)
    csv = OUTDIR / f'{p.stem}.csv'
    n_windows = None
    if csv.exists():
        import pandas as pd
        n_windows = len(pd.read_csv(csv))
    # otherwise try 50 windows max
    if n_windows is None:
        n_windows = 50
    print('scoring', name, p, 'windows=', n_windows)
    scores = []
    anoms = 0
    for i in range(n_windows):
        try:
            r = requests.post(MIT + '/infer_from_pcap', json={'pcap_path': str(p), 'window_index': i, 'window_size': 3.0}, timeout=5)
            if r.status_code != 200:
                print('  window', i, 'error', r.status_code, r.text)
                continue
            j = r.json()
            if 'anomaly_score' in j:
                scores.append(float(j['anomaly_score']))
                if j.get('is_anomaly'):
                    anoms += 1
        except Exception as e:
            print('  request failed', e)
    if scores:
        summary[name] = {
            'n_windows': len(scores),
            'n_anomalies': anoms,
            'pct_anom': anoms / len(scores) * 100.0,
            'min': float(min(scores)),
            'max': float(max(scores)),
            'mean': float(statistics.mean(scores)),
            'median': float(statistics.median(scores)),
            'p95': float(sorted(scores)[int(0.95*len(scores))-1]) if len(scores)>1 else float(scores[0]),
            'p99': float(sorted(scores)[int(0.99*len(scores))-1]) if len(scores)>1 else float(scores[0]),
        }
    else:
        summary[name] = {'n_windows': 0}
print(json.dumps(summary, indent=2))
