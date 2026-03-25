#!/usr/bin/env python3
"""Train an auxiliary 'defensor' detector (sklearn) to detect adversarial examples.

Saves artifacts to `services/defensor_dt/` (model.joblib, scaler.joblib, feature_columns.joblib)
and writes evaluation to `experiments/defensor_retrain_eval.json`.

This is intentionally separate from the mitigator; it does NOT trigger `/reload`.
"""
import os
import json
from glob import glob
from random import shuffle, seed

import joblib
import numpy as np
import csv

try:
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import precision_recall_fscore_support
except Exception as e:
    raise


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


def load_baseline_paths(root_patterns):
    rows = []
    for pat in root_patterns:
        for p in glob(pat):
            if os.path.exists(p):
                with open(p, newline='') as fh:
                    rdr = csv.DictReader(fh)
                    for r in rdr:
                        for k in list(r.keys()):
                            if k in ('start_ts', 'end_ts'):
                                del r[k]
                        rows.append({k: float(v) for k, v in r.items()})
    return rows


def main():
    seed(1)

    # discover adversarial logs across experiments (include forced logs)
    adv_patterns = [
        'experiments/*/*adversarial_log.jsonl',
        'experiments/*/forced*_adversarial_log.jsonl',
        'experiments/run_live_v1/*adversarial_log.jsonl',
        'experiments/run_live_v2/*adversarial_log.jsonl',
    ]
    adv_paths = []
    for pat in adv_patterns:
        adv_paths.extend(glob(pat))
    adv_paths = sorted(set(adv_paths))

    adv_samples = load_adv_from_files(adv_paths)

    # collect baseline negatives from specific run to increase negatives
    baselines = load_baseline_paths(['experiments/run_live_v1/baseline_replica.csv', 'experiments/run_live_evasion_v1/baseline_replica.csv'])
    # fallback if empty
    if not baselines and os.path.exists('experiments/run_live_v1/baseline_replica.csv'):
        baselines = load_baseline_paths(['experiments/run_live_v1/baseline_replica.csv'])

    if len(adv_samples) == 0:
        print('No adversarial samples found; aborting')
        return 1
    if len(baselines) == 0:
        print('No baseline samples found; aborting')
        return 1

    # infer feature columns from baseline first
    feature_cols = list(baselines[0].keys())

    # assemble dataset
    X = []
    y = []
    for b in baselines:
        X.append([b.get(c, 0.0) for c in feature_cols])
        y.append(0)
    for a in adv_samples:
        X.append([a.get(c, 0.0) for c in feature_cols])
        y.append(1)

    X = np.array(X)
    y = np.array(y)

    # shuffle
    idx = np.arange(len(y))
    np.random.RandomState(1).shuffle(idx)
    X = X[idx]
    y = y[idx]

    # split
    test_size = 0.2 if len(y) >= 10 else 0.3
    try:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=1, stratify=y)
    except Exception:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=1)

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    clf = HistGradientBoostingClassifier(random_state=1)
    clf.fit(X_train_s, y_train)

    yp = clf.predict(X_test_s)
    pscore, rscore, fscore, _ = precision_recall_fscore_support(y_test, yp, average='binary', zero_division=0)

    # save artifacts to separate folder
    model_dir = 'services/defensor_dt'
    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(clf, os.path.join(model_dir, 'model.joblib'))
    joblib.dump(scaler, os.path.join(model_dir, 'scaler.joblib'))
    joblib.dump(feature_cols, os.path.join(model_dir, 'feature_columns.joblib'))

    eval_out = {
        'n_baseline': len(baselines),
        'n_adv': len(adv_samples),
        'precision': float(pscore),
        'recall': float(rscore),
        'f1': float(fscore),
        'feature_columns': feature_cols,
    }

    with open('experiments/defensor_retrain_eval.json', 'w') as fh:
        json.dump(eval_out, fh, indent=2)

    print('Saved defensor model to', model_dir)
    print('Eval:', eval_out)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
