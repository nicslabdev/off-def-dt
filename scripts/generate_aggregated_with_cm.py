#!/usr/bin/env python3
"""Generate an aggregated per-run CSV like `per_run_evasion_aggregated_from_agg.csv`
but with 'After countermeasure' columns computed by applying the trained defensor
using the tuned threshold from `experiments/defensor_threshold_tuning.json`.

Writes `experiments/per_run_evasion_with_cm.csv`.
"""
import csv, json, os
import joblib
import numpy as np
from glob import glob
from sklearn.metrics import precision_recall_fscore_support


def load_adv_samples(run_dir):
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


def load_baseline_csv(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, newline='') as fh:
        rdr = csv.DictReader(fh)
        for r in rdr:
            # drop timestamp columns if present
            r.pop('start_ts', None)
            r.pop('end_ts', None)
            rows.append({k: float(v) for k, v in r.items()})
    return rows


def make_X(dicts, cols):
    if not dicts:
        return np.zeros((0, len(cols)))
    return np.array([[d.get(c, 0.0) for c in cols] for d in dicts])


def main():
    base_csv = 'experiments/per_run_evasion_aggregated_from_agg.csv'
    if not os.path.exists(base_csv):
        print('Missing', base_csv)
        return

    # load defensor tuning to get threshold
    tune_path = 'experiments/defensor_threshold_tuning.json'
    if os.path.exists(tune_path):
        tdata = json.load(open(tune_path))
        best_t = tdata.get('best', {}).get('threshold', None)
    else:
        best_t = None

    # load defensor artifacts
    def_model = joblib.load('services/defensor_dt/model.joblib')
    def_scaler = joblib.load('services/defensor_dt/scaler.joblib')
    def_cols = joblib.load('services/defensor_dt/feature_columns.joblib')

    out_rows = []
    with open(base_csv) as fh:
        rdr = csv.reader(fh)
        for row in rdr:
            # header or data
            if row[0].startswith('run_live_evasion'):
                run = row[0]
                before_p = row[1]
                before_r = row[2]
                before_f = row[3]
                after_p = row[4]
                after_r = row[5]
                after_f = row[6]

                run_dir = os.path.join('experiments', run)

                # load baseline and adv samples
                baseline_csv = os.path.join(run_dir, 'baseline_replica.csv')
                baselines = load_baseline_csv(baseline_csv)
                advs = load_adv_samples(run_dir)

                if len(advs) == 0:
                    cm_p = cm_r = cm_f = 'N/A'
                else:
                    X_bas = make_X(baselines, def_cols)
                    X_adv = make_X(advs, def_cols)
                    X_bas_s = def_scaler.transform(X_bas) if X_bas.size else np.zeros((0, len(def_cols)))
                    X_adv_s = def_scaler.transform(X_adv) if X_adv.size else np.zeros((0, len(def_cols)))

                    if hasattr(def_model, 'predict_proba'):
                        p_bas = def_model.predict_proba(X_bas_s)[:,1] if X_bas.size else np.array([])
                        p_adv = def_model.predict_proba(X_adv_s)[:,1] if X_adv.size else np.array([])
                    else:
                        p_bas = def_model.predict(X_bas_s) if X_bas.size else np.array([])
                        p_adv = def_model.predict(X_adv_s) if X_adv.size else np.array([])

                    # load RF artifacts to build raw preds
                    rf_model = joblib.load('services/mitigator/model.joblib')
                    rf_scaler = joblib.load('services/mitigator/scaler.joblib')
                    rf_cols = joblib.load('services/mitigator/feature_columns.joblib')
                    X_bas_rf = make_X(baselines, rf_cols)
                    X_adv_rf = make_X(advs, rf_cols)
                    X_bas_rf_s = rf_scaler.transform(X_bas_rf) if X_bas_rf.size else np.zeros((0, len(rf_cols)))
                    X_adv_rf_s = rf_scaler.transform(X_adv_rf) if X_adv_rf.size else np.zeros((0, len(rf_cols)))
                    rf_pred_bas = rf_model.predict(X_bas_rf_s).astype(int) if X_bas_rf.size else np.array([])
                    rf_pred_adv = rf_model.predict(X_adv_rf_s).astype(int) if X_adv_rf.size else np.array([])

                    y_true = np.concatenate([np.zeros(len(p_bas), dtype=int), np.ones(len(p_adv), dtype=int)])
                    rf_raw = np.concatenate([rf_pred_bas, rf_pred_adv])

                    # decide defensor predictions using best_t if available, else model.predict
                    if best_t is not None:
                        d_bas = (p_bas >= best_t).astype(int) if p_bas.size else np.array([])
                        d_adv = (p_adv >= best_t).astype(int) if p_adv.size else np.array([])
                    else:
                        d_bas = def_model.predict(X_bas_s) if X_bas_s.size else np.array([])
                        d_adv = def_model.predict(X_adv_s) if X_adv_s.size else np.array([])

                    d_all = np.concatenate([d_bas, d_adv])

                    cm = rf_raw.copy()
                    flip_idx = np.where((d_all==1) & (rf_raw==0))[0]
                    cm[flip_idx] = 1

                    p_cm, r_cm, f_cm, _ = precision_recall_fscore_support(y_true, cm, average='binary', zero_division=0)
                    cm_p = '{:.6f}'.format(float(p_cm))
                    cm_r = '{:.6f}'.format(float(r_cm))
                    cm_f = '{:.6f}'.format(float(f_cm))

                out_rows.append([run, before_p, before_r, before_f, after_p, after_r, after_f, cm_p, cm_r, cm_f])

    os.makedirs('experiments', exist_ok=True)
    outpath = 'experiments/per_run_evasion_with_cm.csv'
    with open(outpath, 'w', newline='') as fh:
        wr = csv.writer(fh)
        wr.writerow(['run','before_precision','before_recall','before_f1','after_precision','after_recall','after_f1','cm_precision','cm_recall','cm_f1'])
        for r in out_rows:
            wr.writerow(r)

    print('Wrote', outpath)


if __name__ == '__main__':
    main()
