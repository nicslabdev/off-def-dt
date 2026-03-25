#!/usr/bin/env python3
"""Retrain a defensive classifier from available adversarial JSONL logs
and baseline CSV, save artifacts to `services/defensive_dt/`, and call
the mitigator `/reload` endpoint to pick up the new model.

Writes evaluation output to `experiments/run_live_v1/defensive_retrain_train_eval.json`.
"""
import os
import json
import argparse
from glob import glob
from random import shuffle, seed

import joblib
import numpy as np

try:
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import precision_recall_fscore_support
except Exception:
    raise

import csv

try:
    import requests
except Exception:
    requests = None
    import urllib.request


def load_adv_from_files(paths):
    out = []
    for p in paths:
        if not os.path.exists(p):
            continue
        with open(p, 'r') as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    j = json.loads(ln)
                except Exception:
                    continue
                if 'adv_features' in j and isinstance(j['adv_features'], dict):
                    out.append({k: float(v) for k, v in j['adv_features'].items()})
    return out


def load_baseline(path):
    rows = []
    with open(path, newline='') as fh:
        rdr = csv.DictReader(fh)
        for r in rdr:
            for k in list(r.keys()):
                if k in ('start_ts', 'end_ts'):
                    del r[k]
            feat = {k: float(v) for k, v in r.items()}
            rows.append(feat)
    return rows


def http_post(url, data, timeout=10.0):
    if requests is not None:
        r = requests.post(url, json=data, timeout=timeout)
        try:
            return r.json()
        except Exception:
            return {'status_code': r.status_code, 'text': r.text}
    else:
        data_b = json.dumps(data).encode('utf-8')
        req = urllib.request.Request(url, data=data_b, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=timeout) as fh:
            return json.load(fh)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--adv-patterns', nargs='*', default=[
        'experiments/run_live_v1/*adversarial_log.jsonl',
        'experiments/run_live_v1/forced*_adversarial_log.jsonl',
        'experiments/*/*adversarial_log.jsonl',
    ])
    p.add_argument('--baseline-csv', default='experiments/run_live_v1/baseline_replica.csv')
    p.add_argument('--out-eval', default='experiments/run_live_v1/defensive_retrain_train_eval.json')
    p.add_argument('--model-dir', default='services/defensive_dt')
    p.add_argument('--host', default='http://127.0.0.1:8080')
    p.add_argument('--random-state', type=int, default=1)
    args = p.parse_args()

    seed(args.random_state)

    adv_paths = []
    for pat in args.adv_patterns:
        # expand glob if needed
        if '*' in pat:
            adv_paths.extend(glob(pat))
        else:
            adv_paths.append(pat)

    adv_paths = [p for p in adv_paths if os.path.exists(p)]

    adv_samples = load_adv_from_files(adv_paths)
    baseline_samples = load_baseline(args.baseline_csv)

    if len(adv_samples) == 0:
        print('No adversarial samples found in:', adv_paths)
        return 1

    # determine feature columns (use baseline header if available, else union of adv keys)
    if baseline_samples:
        feature_cols = list(baseline_samples[0].keys())
    else:
        # union adv keys
        keys = set()
        for a in adv_samples:
            keys.update(a.keys())
        feature_cols = sorted(keys)

    # build X,y
    X = []
    y = []
    for b in baseline_samples:
        X.append([b.get(c, 0.0) for c in feature_cols])
        y.append(0)
    for a in adv_samples:
        X.append([a.get(c, 0.0) for c in feature_cols])
        y.append(1)

    X = np.array(X)
    y = np.array(y)

    # small shuffle
    idx = np.arange(len(y))
    np.random.RandomState(args.random_state).shuffle(idx)
    X = X[idx]
    y = y[idx]

    test_size = 0.2 if len(y) >= 10 else 0.3
    try:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=args.random_state, stratify=y)
    except Exception:
        # fallback without stratify
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=args.random_state)

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    # simple hyperparameter grid search (small grid to limit runtime)
    param_grid = {
        'max_iter': [100, 200],
        'learning_rate': [0.1, 0.05],
        'max_leaf_nodes': [31, 63],
    }
    best = None
    best_score = -1.0
    for mi in param_grid['max_iter']:
        for lr in param_grid['learning_rate']:
            for mln in param_grid['max_leaf_nodes']:
                try:
                    clf_try = HistGradientBoostingClassifier(random_state=args.random_state, max_iter=mi, learning_rate=lr, max_leaf_nodes=mln)
                    clf_try.fit(X_train_s, y_train)
                    yp_try = clf_try.predict(X_test_s)
                    ptry, rtry, ftry, _ = precision_recall_fscore_support(y_test, yp_try, average='binary', zero_division=0)
                    if ftry > best_score:
                        best_score = ftry
                        best = (clf_try, {'max_iter': mi, 'learning_rate': lr, 'max_leaf_nodes': mln}, (ptry, rtry, ftry))
                except Exception:
                    continue

    if best is None:
        # fallback to default
        clf = HistGradientBoostingClassifier(random_state=args.random_state)
        clf.fit(X_train_s, y_train)
        yp = clf.predict(X_test_s)
        pscore, rscore, fscore, _ = precision_recall_fscore_support(y_test, yp, average='binary', zero_division=0)
        best_params = {}
    else:
        clf, best_params, (pscore, rscore, fscore) = best

    # try to pick an optimal probability threshold (if predict_proba available)
    best_thresh = 0.5
    try:
        if hasattr(clf, 'predict_proba'):
            probs = clf.predict_proba(X_test_s)[:, 1]
            thr_best = 0.5
            thr_best_score = -1.0
            for thr in [i * 0.05 for i in range(1, 20)]:
                yp_thr = (probs >= thr).astype(int)
                _, _, fthr, _ = precision_recall_fscore_support(y_test, yp_thr, average='binary', zero_division=0)
                if fthr > thr_best_score:
                    thr_best_score = fthr
                    thr_best = thr
            best_thresh = thr_best
    except Exception:
        best_thresh = 0.5

    # save artifacts
    os.makedirs(args.model_dir, exist_ok=True)
    joblib.dump(clf, os.path.join(args.model_dir, 'model.joblib'))
    joblib.dump(scaler, os.path.join(args.model_dir, 'scaler.joblib'))
    joblib.dump(feature_cols, os.path.join(args.model_dir, 'feature_columns.joblib'))
    # save defensive metadata (threshold)
    try:
        with open(os.path.join(args.model_dir, 'model_metadata.json'), 'w') as fh:
            json.dump({'threshold': float(best_thresh), 'best_params': best_params}, fh)
    except Exception:
        pass

    eval_out = {
        'n_baseline': len(baseline_samples),
        'n_adv': len(adv_samples),
        'n_total': len(y),
        'test_size': len(y_test),
        'precision': float(pscore),
        'recall': float(rscore),
        'f1': float(fscore),
        'feature_columns': feature_cols,
        'adv_paths_used': adv_paths,
    }
    eval_out['best_params'] = best_params
    eval_out['best_threshold'] = float(best_thresh)

    with open(args.out_eval, 'w') as fh:
        json.dump(eval_out, fh, indent=2)

    print('Saved model artifacts to', args.model_dir)
    print('Eval:', eval_out)

    # ask mitigator to reload
    try:
        reload_url = args.host.rstrip('/') + '/reload'
        print('Calling', reload_url)
        resp = http_post(reload_url, {})
        print('Reload response:', resp)
        eval_out['reload_response'] = resp
        with open(args.out_eval, 'w') as fh:
            json.dump(eval_out, fh, indent=2)
    except Exception as e:
        print('Reload failed:', e)
        eval_out['reload_error'] = str(e)
        with open(args.out_eval, 'w') as fh:
            json.dump(eval_out, fh, indent=2)

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
