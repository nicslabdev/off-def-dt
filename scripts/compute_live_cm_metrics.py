#!/usr/bin/env python3
"""Compute before/after/after-CM metrics for specified runs using live mitigator.

For each run dir, uses `baseline_replica.csv` as negatives and all `*adversarial_log.jsonl`
files as positives. Posts features to `/infer` on provided host and computes metrics
for raw detector output (`raw_is_anomaly`) and post-countermeasure (`is_anomaly`).
"""
import os, json, argparse
from glob import glob
import csv
try:
    import requests
except Exception:
    requests = None

from sklearn.metrics import precision_recall_fscore_support


def post(url, payload):
    if requests is not None:
        r = requests.post(url, json=payload, timeout=10)
        r.raise_for_status()
        return r.json()
    else:
        import urllib.request
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=10) as fh:
            return json.load(fh)


def load_baseline(path):
    rows = []
    with open(path, newline='') as fh:
        rdr = csv.DictReader(fh)
        for r in rdr:
            for k in list(r.keys()):
                if k in ('start_ts','end_ts'):
                    del r[k]
            rows.append({k: float(v) for k,v in r.items()})
    return rows


def load_advs(path):
    out = []
    with open(path) as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln: continue
            try:
                j = json.loads(ln)
            except Exception:
                continue
            if 'adv_features' in j and isinstance(j['adv_features'], dict):
                out.append({k: float(v) for k,v in j['adv_features'].items()})
    return out


def eval_run(run_dir, host):
    infer = host.rstrip('/') + '/infer'
    baseline_csv = os.path.join(run_dir, 'baseline_replica.csv')
    if not os.path.exists(baseline_csv):
        print('no baseline for', run_dir)
        return None
    baselines = load_baseline(baseline_csv)

    # collect all adversarial logs in run_dir
    adv_paths = glob(os.path.join(run_dir, '*adversarial_log.jsonl'))
    adv_samples = []
    for p in adv_paths:
        adv_samples.extend(load_advs(p))

    # query baseline
    y_true = []
    raw_preds = []
    cm_preds = []
    for feat in baselines:
        try:
            r = post(infer, {'features': feat})
        except Exception as e:
            print('infer error baseline', e)
            continue
        y_true.append(0)
        raw_preds.append(1 if r.get('raw_is_anomaly') else 0)
        cm_preds.append(1 if r.get('is_anomaly') else 0)

    # query advs
    for feat in adv_samples:
        try:
            r = post(infer, {'features': feat})
        except Exception as e:
            print('infer error adv', e)
            continue
        y_true.append(1)
        raw_preds.append(1 if r.get('raw_is_anomaly') else 0)
        cm_preds.append(1 if r.get('is_anomaly') else 0)

    # compute metrics for raw_preds (this is 'before/after attack' perspective - raw on baseline vs adv)
    p_raw, r_raw, f_raw, _ = precision_recall_fscore_support(y_true, raw_preds, average='binary', zero_division=0)
    p_cm, r_cm, f_cm, _ = precision_recall_fscore_support(y_true, cm_preds, average='binary', zero_division=0)

    return {
        'n_baseline': len(baselines),
        'n_adv': len(adv_samples),
        'precision_raw': float(p_raw), 'recall_raw': float(r_raw), 'f1_raw': float(f_raw),
        'precision_cm': float(p_cm), 'recall_cm': float(r_cm), 'f1_cm': float(f_cm),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--runs', nargs='*', default=['experiments/run_live_evasion_v1','experiments/run_live_evasion_v5','experiments/run_live_evasion_v9'])
    p.add_argument('--host', default='http://127.0.0.1:8081')
    args = p.parse_args()

    out = {}
    for rdir in args.runs:
        if not os.path.isdir(rdir):
            print('skip missing', rdir)
            continue
        print('eval', rdir)
        res = eval_run(rdir, args.host)
        out[rdir] = res

    print(json.dumps(out, indent=2))
    with open('experiments/live_cm_metrics_summary.json','w') as fh:
        json.dump(out, fh, indent=2)


if __name__ == '__main__':
    main()
