#!/usr/bin/env python3
"""Perform one enhanced-attack iteration and re-apply defensor countermeasure.

For each run this script computes:
- before attack (from aggregated CSV)
- after attack (from aggregated CSV)
- after first countermeasure (from per_run_evasion_with_cm.csv)
- simulate enhanced attack (parameterized) that reduces RF detections and defensor scores
- apply countermeasure again and report metrics

Writes `experiments/defensor_third_iter_metrics.json`.
"""
import os, json, argparse
from glob import glob
import joblib
import numpy as np
import csv
from sklearn.metrics import precision_recall_fscore_support


def load_baseline_csv(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, newline='') as fh:
        rdr = csv.DictReader(fh)
        for r in rdr:
            r.pop('start_ts', None)
            r.pop('end_ts', None)
            rows.append({k: float(v) for k, v in r.items()})
    return rows


def load_advs(run_dir):
    out = []
    for p in glob(os.path.join(run_dir, '*adversarial_log.jsonl')):
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
    if not dicts:
        return np.zeros((0, len(cols)))
    return np.array([[d.get(c, 0.0) for c in cols] for d in dicts])


def compute_metrics(y_true, y_pred):
    p, r, f, _ = precision_recall_fscore_support(y_true, y_pred, average='binary', zero_division=0)
    return float(p), float(r), float(f)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--runs', nargs='*', default=['experiments/run_live_evasion_v1','experiments/run_live_evasion_v5','experiments/run_live_evasion_v6','experiments/run_live_evasion_v9'])
    p.add_argument('--attack-success-rate', type=float, default=0.5, help='Probability an adv sample succeeds to flip RF->0')
    p.add_argument('--def-proba-delta', type=float, default=-0.3, help='Additive delta to defensor probabilities for advs to simulate stronger attack')
    args = p.parse_args()

    # load artifacts
    rf_model = joblib.load('services/mitigator/model.joblib')
    rf_scaler = joblib.load('services/mitigator/scaler.joblib')
    rf_cols = joblib.load('services/mitigator/feature_columns.joblib')

    def_model = joblib.load('services/defensor_dt/model.joblib')
    def_scaler = joblib.load('services/defensor_dt/scaler.joblib')
    def_cols = joblib.load('services/defensor_dt/feature_columns.joblib')

    # tuned threshold
    tune_path = 'experiments/defensor_threshold_tuning.json'
    best_t = None
    if os.path.exists(tune_path):
        tdata = json.load(open(tune_path))
        best_t = tdata.get('best', {}).get('threshold', None)

    # load aggregated CSVs for before/after
    agg_csv = 'experiments/per_run_evasion_aggregated_from_agg.csv'
    cm_csv = 'experiments/per_run_evasion_with_cm.csv'
    agg_map = {}
    if os.path.exists(agg_csv):
        with open(agg_csv) as fh:
            rdr = csv.reader(fh)
            for row in rdr:
                if row and row[0].startswith('run_live_evasion'):
                    agg_map[row[0]] = row[1:7]
    cm_map = {}
    if os.path.exists(cm_csv):
        with open(cm_csv) as fh:
            rdr = csv.reader(fh)
            next(rdr, None)
            for row in rdr:
                cm_map[row[0]] = row[1:10]

    out = {}
    for run in args.runs:
        if not os.path.isdir(run):
            print('skip', run)
            continue
        runname = os.path.basename(run)
        print('processing', runname)
        bas_csv = os.path.join(run, 'baseline_replica.csv')
        baselines = load_baseline_csv(bas_csv)
        advs = load_advs(run)

        X_bas_rf = make_X(baselines, rf_cols)
        X_adv_rf = make_X(advs, rf_cols)
        X_bas_rf_s = rf_scaler.transform(X_bas_rf) if X_bas_rf.size else np.zeros((0, len(rf_cols)))
        X_adv_rf_s = rf_scaler.transform(X_adv_rf) if X_adv_rf.size else np.zeros((0, len(rf_cols)))
        rf_pred_bas = rf_model.predict(X_bas_rf_s).astype(int) if X_bas_rf.size else np.array([])
        rf_pred_adv = rf_model.predict(X_adv_rf_s).astype(int) if X_adv_rf.size else np.array([])

        X_bas_def = make_X(baselines, def_cols)
        X_adv_def = make_X(advs, def_cols)
        X_bas_def_s = def_scaler.transform(X_bas_def) if X_bas_def.size else np.zeros((0, len(def_cols)))
        X_adv_def_s = def_scaler.transform(X_adv_def) if X_adv_def.size else np.zeros((0, len(def_cols)))

        if hasattr(def_model, 'predict_proba'):
            p_bas = def_model.predict_proba(X_bas_def_s)[:,1] if X_bas_def.size else np.array([])
            p_adv = def_model.predict_proba(X_adv_def_s)[:,1] if X_adv_def.size else np.array([])
        else:
            p_bas = def_model.predict(X_bas_def_s) if X_bas_def.size else np.array([])
            p_adv = def_model.predict(X_adv_def_s) if X_adv_def.size else np.array([])

        # baseline truths
        y_true = np.concatenate([np.zeros(len(p_bas), dtype=int), np.ones(len(p_adv), dtype=int)])

        # rf raw before enhanced
        rf_raw_before = np.concatenate([rf_pred_bas, rf_pred_adv])

        # first CM: use cm_map if present else compute using best_t
        if runname in cm_map:
            cm_vals = cm_map[runname]
            cm1 = None
        else:
            # compute using best_t
            if best_t is not None:
                d_bas = (p_bas >= best_t).astype(int) if p_bas.size else np.array([])
                d_adv = (p_adv >= best_t).astype(int) if p_adv.size else np.array([])
                d_all = np.concatenate([d_bas, d_adv])
                cm1 = rf_raw_before.copy()
                flip_idx = np.where((d_all==1) & (cm1==0))[0]
                cm1[flip_idx] = 1
            else:
                cm1 = None

        # simulate enhanced attack
        np.random.seed(0)
        rf_pred_adv_enh = rf_pred_adv.copy() if rf_pred_adv.size else np.array([])
        if rf_pred_adv_enh.size:
            ones_idx = np.where(rf_pred_adv_enh==1)[0]
            flip_mask = np.random.rand(len(ones_idx)) < args.attack_success_rate
            rf_pred_adv_enh[ones_idx[flip_mask]] = 0

        p_adv_enh = np.clip(p_adv + args.def_proba_delta, 0.0, 1.0) if p_adv.size else np.array([])

        rf_raw_enh = np.concatenate([rf_pred_bas, rf_pred_adv_enh])

        # apply CM second time
        if best_t is not None:
            d_bas_enh = (p_bas >= best_t).astype(int) if p_bas.size else np.array([])
            d_adv_enh = (p_adv_enh >= best_t).astype(int) if p_adv_enh.size else np.array([])
            d_all_enh = np.concatenate([d_bas_enh, d_adv_enh])
            cm2 = rf_raw_enh.copy()
            flip_idx2 = np.where((d_all_enh==1) & (cm2==0))[0]
            cm2[flip_idx2] = 1
        else:
            cm2 = rf_raw_enh.copy()

        # compute metrics for enhanced raw and cm2
        p_raw_enh, r_raw_enh, f_raw_enh = compute_metrics(y_true, rf_raw_enh)
        p_cm2, r_cm2, f_cm2 = compute_metrics(y_true, cm2)

        # pack results
        out[runname] = {
            'n_baseline': int(len(p_bas)), 'n_adv': int(len(p_adv)),
            'raw_enhanced': {'precision':p_raw_enh, 'recall':r_raw_enh, 'f1':f_raw_enh},
            'cm_second': {'precision':p_cm2, 'recall':r_cm2, 'f1':f_cm2},
            'attack_params': {'attack_success_rate': args.attack_success_rate, 'def_proba_delta': args.def_proba_delta}
        }

    os.makedirs('experiments', exist_ok=True)
    with open('experiments/defensor_third_iter_metrics.json','w') as fh:
        json.dump(out, fh, indent=2)

    print('Wrote experiments/defensor_third_iter_metrics.json')


if __name__ == '__main__':
    main()
