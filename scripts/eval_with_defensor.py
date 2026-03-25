#!/usr/bin/env python3
"""Evaluate RandomForest detector before and after applying the auxiliar defensor.

Loads artifacts from `services/mitigator/` (RF) and `services/defensor_dt/` (defensor),
then for each specified run directory computes:
- RF raw predictions on baseline and adversarial samples
- RF predictions after applying defensor: when defensor predicts adversarial and RF predicted 0 -> flip to 1

Writes `experiments/defensor_applied_metrics.json` and prints a table.
"""
import os, json, argparse
from glob import glob
import csv
import joblib
import numpy as np
from sklearn.metrics import precision_recall_fscore_support


def load_baseline(path):
    rows = []
    with open(path, newline='') as fh:
        rdr = csv.DictReader(fh)
        for r in rdr:
            for k in list(r.keys()):
                if k in ('start_ts', 'end_ts'):
                    del r[k]
            rows.append({k: float(v) for k, v in r.items()})
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
                out.append({k: float(v) for k, v in j['adv_features'].items()})
    return out


def get_features_array(feat_dicts, cols):
    X = np.array([[d.get(c, 0.0) for c in cols] for d in feat_dicts])
    return X


def eval_run(run_dir, rf_model, rf_scaler, rf_cols, def_model, def_scaler, def_cols):
    baseline_csv = os.path.join(run_dir, 'baseline_replica.csv')
    if not os.path.exists(baseline_csv):
        return None
    baselines = load_baseline(baseline_csv)
    # collect adversarial logs
    adv_paths = glob(os.path.join(run_dir, '*adversarial_log.jsonl'))
    adv_samples = []
    for p in adv_paths:
        adv_samples.extend(load_advs(p))

    # combine
    X_bas = get_features_array(baselines, rf_cols)
    X_adv = get_features_array(adv_samples, rf_cols)
    if X_bas.size == 0 and X_adv.size == 0:
        return None

    # scale for RF
    X_bas_s = rf_scaler.transform(X_bas) if X_bas.size else np.zeros((0, len(rf_cols)))
    X_adv_s = rf_scaler.transform(X_adv) if X_adv.size else np.zeros((0, len(rf_cols)))

    # RF raw preds
    y_true = []
    y_pred_raw = []
    y_pred_cm = []

    pr_bas = []
    pr_adv = []
    if X_bas.shape[0] > 0:
        pr_bas = rf_model.predict(X_bas_s).astype(int).tolist()
        y_true.extend([0] * X_bas.shape[0])
        y_pred_raw.extend(pr_bas)
    if X_adv.shape[0] > 0:
        pr_adv = rf_model.predict(X_adv_s).astype(int).tolist()
        y_true.extend([1] * X_adv.shape[0])
        y_pred_raw.extend(pr_adv)

    # defensor predictions (use defensor cols and scaler)
    # build defensor feature arrays for baselines and advs
    Xd_bas = get_features_array(baselines, def_cols)
    Xd_adv = get_features_array(adv_samples, def_cols)
    Xd_bas_s = def_scaler.transform(Xd_bas) if Xd_bas.size else np.zeros((0, len(def_cols)))
    Xd_adv_s = def_scaler.transform(Xd_adv) if Xd_adv.size else np.zeros((0, len(def_cols)))

    dpred_bas = def_model.predict(Xd_bas_s).astype(int).tolist() if Xd_bas.shape[0] > 0 else []
    dpred_adv = def_model.predict(Xd_adv_s).astype(int).tolist() if Xd_adv.shape[0] > 0 else []

    # build cm preds: apply flip when defensor predicts 1 and RF predicted 0
    # iterate in same order as y_pred_raw
    idx = 0
    # baselines
    for i in range(len(pr_bas) if X_bas.shape[0]>0 else 0):
        rf_p = y_pred_raw[idx]
        d_p = dpred_bas[i]
        final = rf_p
        if d_p == 1 and rf_p == 0:
            final = 1
        y_pred_cm.append(final)
        idx += 1
    # advs
    for i in range(len(pr_adv) if X_adv.shape[0]>0 else 0):
        rf_p = y_pred_raw[idx]
        d_p = dpred_adv[i]
        final = rf_p
        if d_p == 1 and rf_p == 0:
            final = 1
        y_pred_cm.append(final)
        idx += 1

    # compute metrics
    p_raw, r_raw, f_raw, _ = precision_recall_fscore_support(y_true, y_pred_raw, average='binary', zero_division=0)
    p_cm, r_cm, f_cm, _ = precision_recall_fscore_support(y_true, y_pred_cm, average='binary', zero_division=0)

    return {
        'n_baseline': X_bas.shape[0],
        'n_adv': X_adv.shape[0],
        'precision_raw': float(p_raw), 'recall_raw': float(r_raw), 'f1_raw': float(f_raw),
        'precision_cm': float(p_cm), 'recall_cm': float(r_cm), 'f1_cm': float(f_cm),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--runs', nargs='*', default=['experiments/run_live_v1','experiments/run_live_v5','experiments/run_live_v9'])
    p.add_argument('--rf-model', default='services/mitigator/model.joblib')
    p.add_argument('--rf-scaler', default='services/mitigator/scaler.joblib')
    p.add_argument('--rf-cols', default='services/mitigator/feature_columns.joblib')
    p.add_argument('--def-model', default='services/defensor_dt/model.joblib')
    p.add_argument('--def-scaler', default='services/defensor_dt/scaler.joblib')
    p.add_argument('--def-cols', default='services/defensor_dt/feature_columns.joblib')
    args = p.parse_args()

    rf_model = joblib.load(args.rf_model)
    rf_scaler = joblib.load(args.rf-scaler) if False else joblib.load(args.rf_scaler)
    rf_cols = joblib.load(args.rf_cols)
    def_model = joblib.load(args.def_model)
    def_scaler = joblib.load(args.def_scaler)
    def_cols = joblib.load(args.def_cols)

    out = {}
    for rdir in args.runs:
        if not os.path.isdir(rdir):
            print('skip', rdir)
            continue
        print('evaluating', rdir)
        res = eval_run(rdir, rf_model, rf_scaler, rf_cols, def_model, def_scaler, def_cols)
        out[rdir] = res

    os.makedirs('experiments', exist_ok=True)
    with open('experiments/defensor_applied_metrics.json', 'w') as fh:
        json.dump(out, fh, indent=2)

    print(json.dumps(out, indent=2))


if __name__ == '__main__':
    main()
