#!/usr/bin/env python3
"""Retrain the auxiliar defensor with augmented negatives and sample-weighting.

Saves artifacts to `services/defensor_dt/` and writes evaluation to
`experiments/defensor_retrain_fourth_iter_eval.json`.
"""
import os, json
from glob import glob
import joblib
import numpy as np
import csv
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import precision_recall_fscore_support


def load_baseline_paths(paths):
    rows = []
    for p in paths:
        if not os.path.exists(p):
            continue
        with open(p, newline='') as fh:
            rdr = csv.DictReader(fh)
            for r in rdr:
                r.pop('start_ts', None)
                r.pop('end_ts', None)
                rows.append({k: float(v) for k, v in r.items()})
    return rows


def load_advs(patterns):
    out = []
    for pat in patterns:
        for p in glob(pat):
            with open(p) as fh:
                for ln in fh:
                    ln = ln.strip()
                    if not ln: continue
                    try:
                        j = json.loads(ln)
                    except Exception:
                        continue
                    if 'adv_features' in j and isinstance(j['adv_features'], dict):
                        out.append({k: float(v) for k, v in j['adv_features'].items()})
    return out


def make_X(dicts, cols):
    return np.array([[d.get(c, 0.0) for c in cols] for d in dicts])


def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--w-pos', type=float, default=5.0, help='sample weight for positive (adv) examples')
    args = p.parse_args()

    w_pos = args.w_pos

    # collect advs
    adv_patterns = [
        'experiments/*adversarial_log.jsonl',
        'experiments/**/*adversarial_log.jsonl'
    ]
    advs = load_advs(adv_patterns)

    # collect baselines from several runs
    baseline_paths = glob('experiments/run_live_*/baseline_replica.csv') + glob('experiments/run_live_evasion_*/baseline_replica.csv')
    baselines = load_baseline_paths(baseline_paths)

    if len(advs) == 0 or len(baselines) == 0:
        print('Not enough data: advs', len(advs), 'baselines', len(baselines))
        return

    # choose feature columns as intersection of keys from advs[0] and baselines[0]
    feat_cols = sorted(list(set(advs[0].keys()) | set(baselines[0].keys())))

    X_adv = make_X(advs, feat_cols)
    X_bas = make_X(baselines, feat_cols)
    y_adv = np.ones(X_adv.shape[0], dtype=int)
    y_bas = np.zeros(X_bas.shape[0], dtype=int)

    # augment negatives by bootstrapping to increase diversity (max 3x)
    n_target_neg = max(len(y_adv)*3, len(y_bas))
    if len(y_bas) < n_target_neg:
        idx = np.random.choice(len(y_bas), size=(n_target_neg - len(y_bas)), replace=True)
        X_bas_aug = np.vstack([X_bas, X_bas[idx]])
        y_bas_aug = np.concatenate([y_bas, np.zeros(len(idx), dtype=int)])
    else:
        X_bas_aug = X_bas
        y_bas_aug = y_bas

    X = np.vstack([X_bas_aug, X_adv])
    y = np.concatenate([y_bas_aug, y_adv])

    # split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=0, stratify=y)

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    # set sample weights to emphasize positives
    sample_weight = np.where(y_train==1, w_pos, 1.0)

    clf = HistGradientBoostingClassifier(random_state=0)
    clf.fit(X_train_s, y_train, sample_weight=sample_weight)

    # evaluate
    if hasattr(clf, 'predict_proba'):
        prob_test = clf.predict_proba(X_test_s)[:,1]
        pred_test = (prob_test >= 0.5).astype(int)
    else:
        pred_test = clf.predict(X_test_s)

    p, r, f, _ = precision_recall_fscore_support(y_test, pred_test, average='binary', zero_division=0)

    os.makedirs('services/defensor_dt', exist_ok=True)
    joblib.dump(clf, 'services/defensor_dt/model.joblib')
    joblib.dump(scaler, 'services/defensor_dt/scaler.joblib')
    joblib.dump(feat_cols, 'services/defensor_dt/feature_columns.joblib')

    out = {'n_train': int(len(y_train)), 'n_test': int(len(y_test)), 'precision':float(p), 'recall':float(r), 'f1':float(f), 'w_pos':float(w_pos)}
    os.makedirs('experiments', exist_ok=True)
    with open('experiments/defensor_retrain_fourth_iter_eval.json','w') as fh:
        json.dump(out, fh, indent=2)

    print('Saved defender artifacts and wrote experiments/defensor_retrain_fourth_iter_eval.json')


if __name__ == '__main__':
    main()
