#!/usr/bin/env python3
"""Tune `services/defensor_dt` threshold to improve post-CM F1 while limiting baseline FP increase.

Writes a small report `experiments/defensor_threshold_tuning.json` with candidate thresholds and metrics.
"""
import os, json
from glob import glob
import joblib
import numpy as np
import csv
from sklearn.metrics import precision_recall_fscore_support


def load_baseline(path):
    rows = []
    with open(path, newline='') as fh:
        rdr = csv.DictReader(fh)
        for r in rdr:
            for k in list(r.keys()):
                if k in ('start_ts', 'end_ts'):
                    r.pop(k, None)
            rows.append({k: float(v) for k, v in r.items()})
    return rows


def load_advs_from_glob(patterns):
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


def make_X(feat_dicts, cols):
    return np.array([[d.get(c, 0.0) for c in cols] for d in feat_dicts])


def main():
    # artifacts
    rf_model = joblib.load('services/mitigator/model.joblib')
    rf_scaler = joblib.load('services/mitigator/scaler.joblib')
    rf_cols = joblib.load('services/mitigator/feature_columns.joblib')

    def_model = joblib.load('services/defensor_dt/model.joblib')
    def_scaler = joblib.load('services/defensor_dt/scaler.joblib')
    def_cols = joblib.load('services/defensor_dt/feature_columns.joblib')

    # collect baseline from run_live_v1 (preferred) + others
    bas_paths = ['experiments/run_live_v1/baseline_replica.csv']
    baselines = []
    for p in bas_paths:
        if os.path.exists(p):
            baselines.extend(load_baseline(p))

    # collect advs from experiments forced advs + standard adv logs
    adv_patterns = [
        'experiments/run_live_v1/*adversarial_log.jsonl',
        'experiments/run_live_evasion_v*/**/*adversarial_log.jsonl'
    ]
    advs = load_advs_from_glob(adv_patterns)

    X_bas_rf = make_X(baselines, rf_cols)
    X_adv_rf = make_X(advs, rf_cols)
    X_comb_rf = np.vstack([X_bas_rf, X_adv_rf]) if X_adv_rf.size or X_bas_rf.size else np.zeros((0, len(rf_cols)))

    X_bas_rf_s = rf_scaler.transform(X_bas_rf) if X_bas_rf.size else np.zeros((0, len(rf_cols)))
    X_adv_rf_s = rf_scaler.transform(X_adv_rf) if X_adv_rf.size else np.zeros((0, len(rf_cols)))

    rf_pred_bas = rf_model.predict(X_bas_rf_s).astype(int) if X_bas_rf.size else np.array([])
    rf_pred_adv = rf_model.predict(X_adv_rf_s).astype(int) if X_adv_rf.size else np.array([])

    # defensor features
    X_bas_def = make_X(baselines, def_cols)
    X_adv_def = make_X(advs, def_cols)
    X_bas_def_s = def_scaler.transform(X_bas_def) if X_bas_def.size else np.zeros((0, len(def_cols)))
    X_adv_def_s = def_scaler.transform(X_adv_def) if X_adv_def.size else np.zeros((0, len(def_cols)))

    # defensor probabilities
    if hasattr(def_model, 'predict_proba'):
        proba_bas = def_model.predict_proba(X_bas_def_s)[:,1] if X_bas_def.size else np.array([])
        proba_adv = def_model.predict_proba(X_adv_def_s)[:,1] if X_adv_def.size else np.array([])
    else:
        proba_bas = def_model.predict(X_bas_def_s) if X_bas_def.size else np.array([])
        proba_adv = def_model.predict(X_adv_def_s) if X_adv_def.size else np.array([])

    # ground truth and RF raw preds
    y_true = np.concatenate([np.zeros(len(proba_bas), dtype=int), np.ones(len(proba_adv), dtype=int)])
    rf_raw = np.concatenate([rf_pred_bas, rf_pred_adv]) if (len(rf_pred_bas)+len(rf_pred_adv))>0 else np.array([])

    results = []
    best = None
    # baseline FP before
    baseline_n = len(proba_bas)
    baseline_rf_fp = int((rf_pred_bas==1).sum()) if baseline_n>0 else 0

    for t in np.linspace(0,1,101):
        d_bas = (proba_bas >= t).astype(int) if proba_bas.size else np.array([])
        d_adv = (proba_adv >= t).astype(int) if proba_adv.size else np.array([])
        d_all = np.concatenate([d_bas, d_adv])

        # apply countermeasure: if defensor predicts 1 and rf_raw==0 -> flip to 1
        cm = rf_raw.copy()
        flip_idx = np.where((d_all==1) & (rf_raw==0))[0]
        cm[flip_idx] = 1

        p, r, f, _ = precision_recall_fscore_support(y_true, cm, average='binary', zero_division=0)

        baseline_fp_after = int(((cm[:baseline_n])==1).sum()) if baseline_n>0 else 0
        extra_fp = baseline_fp_after - baseline_rf_fp

        results.append({'threshold': float(t), 'precision':float(p), 'recall':float(r), 'f1':float(f), 'baseline_rf_fp':int(baseline_rf_fp), 'baseline_fp_after':int(baseline_fp_after), 'extra_fp':int(extra_fp)})

        # choose best: max f1 with extra_fp <= 5% of baseline_n (or minimal extra_fp if none)
        allowed_extra = max(1, int(0.05 * baseline_n))
        if extra_fp <= allowed_extra:
            if best is None or f > best['f1']:
                best = {'threshold':float(t), 'precision':float(p), 'recall':float(r), 'f1':float(f), 'extra_fp':int(extra_fp)}

    if best is None:
        # pick threshold with max f1 and minimal extra_fp
        sorted_by_f = sorted(results, key=lambda x: (-x['f1'], x['extra_fp']))
        best = sorted_by_f[0]

    out = {'baseline_n': baseline_n, 'baseline_rf_fp': baseline_rf_fp, 'best': best, 'results': results}
    os.makedirs('experiments', exist_ok=True)
    with open('experiments/defensor_threshold_tuning.json','w') as fh:
        json.dump(out, fh, indent=2)

    print('Wrote experiments/defensor_threshold_tuning.json')


if __name__ == '__main__':
    main()
