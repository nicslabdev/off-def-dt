#!/usr/bin/env python3
"""Batch-test the mitigator `/infer` endpoint with baseline and adversarial samples.

Saves a JSON summary to `experiments/run_live_v1/defensive_live_eval.json`.
"""
import os
import json
import argparse
from random import shuffle, seed

try:
    import requests
except Exception:
    requests = None
    import urllib.request
    from urllib.error import URLError

import csv


def post_json(url, payload, timeout=10.0):
    if requests is not None:
        r = requests.post(url, json=payload, timeout=timeout)
        r.raise_for_status()
        return r.json()
    else:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=timeout) as fh:
            return json.load(fh)


def load_baseline(path, max_samples=50, seed_val=1):
    rows = []
    with open(path, newline='') as fh:
        rdr = csv.DictReader(fh)
        for r in rdr:
            # drop start_ts/end_ts if present
            for k in list(r.keys()):
                if k in ('start_ts', 'end_ts'):
                    del r[k]
            # convert to floats
            feat = {k: float(v) for k, v in r.items()}
            rows.append(feat)
    seed(seed_val)
    shuffle(rows)
    return rows[:max_samples]


def load_adversarial_jsonl(path, max_samples=200, seed_val=1):
    rows = []
    with open(path, 'r') as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                j = json.loads(ln)
            except Exception:
                continue
            if 'adv_features' in j and isinstance(j['adv_features'], dict):
                # ensure floats
                feat = {k: float(v) for k, v in j['adv_features'].items()}
                rows.append({'features': feat, 'meta': {k: v for k, v in j.items() if k != 'adv_features'}})
    seed(seed_val)
    shuffle(rows)
    return rows[:max_samples]


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--adv-jsonl', default='experiments/run_live_v1/forced_offensive_eps0p018_adversarial_log.jsonl')
    p.add_argument('--baseline-csv', default='experiments/run_live_v1/baseline_replica.csv')
    p.add_argument('--host', default='http://127.0.0.1:8080')
    p.add_argument('--n-adv', type=int, default=200)
    p.add_argument('--n-baseline', type=int, default=100)
    p.add_argument('--out', default='experiments/run_live_v1/defensive_live_eval.json')
    args = p.parse_args()

    infer_url = args.host.rstrip('/') + '/infer'

    adv_samples = load_adversarial_jsonl(args.adv_jsonl, max_samples=args.n_adv)
    baseline_samples = load_baseline(args.baseline_csv, max_samples=args.n_baseline)

    results = {'adv': [], 'baseline': []}

    # POST adv samples
    for s in adv_samples:
        payload = {'features': s['features']}
        try:
            r = post_json(infer_url, payload)
        except Exception as e:
            r = {'error': str(e)}
        results['adv'].append({'meta': s.get('meta'), 'features': s['features'], 'resp': r})

    # POST baseline samples
    for feat in baseline_samples:
        payload = {'features': feat}
        try:
            r = post_json(infer_url, payload)
        except Exception as e:
            r = {'error': str(e)}
        results['baseline'].append({'features': feat, 'resp': r})

    # compute simple metrics
    def safe_get_bool(d, key):
        try:
            return bool(d.get(key))
        except Exception:
            return False

    adv_total = 0
    adv_detected = 0
    adv_flipped = 0
    adv_raw_anomaly = 0
    for it in results['adv']:
        resp = it['resp']
        if 'error' in resp:
            continue
        adv_total += 1
        if safe_get_bool(resp, 'defensive_detected'):
            adv_detected += 1
            if resp.get('raw_is_anomaly') != resp.get('is_anomaly'):
                adv_flipped += 1
        if safe_get_bool(resp, 'raw_is_anomaly'):
            adv_raw_anomaly += 1

    base_total = 0
    base_false_alerts = 0
    for it in results['baseline']:
        resp = it['resp']
        if 'error' in resp:
            continue
        base_total += 1
        if safe_get_bool(resp, 'defensive_detected'):
            base_false_alerts += 1

    summary = {
        'adv_total': adv_total,
        'adv_detected': adv_detected,
        'adv_flipped': adv_flipped,
        'adv_raw_anomaly': adv_raw_anomaly,
        'baseline_total': base_total,
        'baseline_defensive_false_alerts': base_false_alerts,
    }

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, 'w') as fh:
        json.dump({'summary': summary, 'results': results}, fh, indent=2)

    print('Wrote', args.out)
    print('Summary:', json.dumps(summary))


if __name__ == '__main__':
    main()
