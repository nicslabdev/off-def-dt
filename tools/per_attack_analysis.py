#!/usr/bin/env python3
"""Per-attack analysis: load saved artifacts and attack CSVs and report per-attack AUC and best-F1 threshold.

Usage: python tools/per_attack_analysis.py --outdir experiments/run_live_v1
"""
import argparse
import joblib
import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score, precision_recall_fscore_support, confusion_matrix


def load_numeric(csv_path):
    df = pd.read_csv(csv_path)
    num = df.select_dtypes(include=['number']).fillna(0)
    return df, num


def score_with_model(model, scaler, X):
    Xs = scaler.transform(X)
    # Use model decision_function or score_samples directly so higher => more anomalous
    try:
        scores = model.decision_function(Xs)
    except Exception:
        # try LOF-style
        try:
            scores = model.score_samples(Xs)
        except Exception:
            raise
    return scores


def sweep_best_threshold(scores, y_true):
    # candidate thresholds are quantiles of scores
    qs = np.linspace(0.0, 1.0, 201)
    best = {'f1': -1, 'thr': None, 'prec': 0, 'rec': 0, 'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0}
    for q in qs:
        thr = float(np.quantile(scores, q))
        y_pred = (scores >= thr).astype(int)
        prec, rec, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary', zero_division=0)
        if f1 > best['f1']:
            tn = fp = fn = tp = 0
            if len(np.unique(y_true)) > 1:
                tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0,1]).ravel()
            best = {'f1': f1, 'thr': thr, 'prec': prec, 'rec': rec, 'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn}
    return best


def analyze(outdir: Path):
    mit_dir = outdir / 'mitigator'
    model_path = mit_dir / 'model.joblib'
    scaler_path = mit_dir / 'scaler.joblib'
    featcols_path = mit_dir / 'feature_columns.joblib'

    if not model_path.exists() or not scaler_path.exists():
        print('Model/scaler artifacts not found in', mit_dir)
        return 1

    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    featcols = None
    if featcols_path.exists():
        featcols = joblib.load(featcols_path)

    baseline_csv = outdir / 'baseline_replica.csv'
    if not baseline_csv.exists():
        print('baseline csv missing:', baseline_csv)
        return 1
    _, baseline_num = load_numeric(baseline_csv)
    # if feature columns were saved by the trainer, ensure we only use those
    if featcols is not None:
        # reindex will add missing columns (filled with NaN) and keep order
        baseline_num = baseline_num.reindex(columns=featcols).fillna(0)
    n_baseline = baseline_num.shape[0]
    holdout_n = max(1, int(0.2 * n_baseline))
    X_holdout = baseline_num.iloc[:holdout_n].values

    # gather attacks
    report = []
    attack_csvs = sorted(outdir.glob('attack_*.csv'))
    if not attack_csvs:
        print('no attack csv files found in', outdir)
        return 1
    all_attack_windows = 0
    for csv in attack_csvs:
        # skip auth bruteforce entries that might be empty but we can compute
        _, num = load_numeric(csv)
        if num.empty:
            print('skipping empty attack csv', csv)
            continue
        if featcols is not None:
            num = num.reindex(columns=featcols).fillna(0)
        X_attack = num.values
        all_attack_windows += X_attack.shape[0]

        X_test = np.vstack([X_holdout, X_attack])
        y_test = np.concatenate([np.zeros(X_holdout.shape[0], dtype=int), np.ones(X_attack.shape[0], dtype=int)])

        scores = score_with_model(model, scaler, X_test)
        try:
            auc = float(roc_auc_score(y_test, scores)) if len(np.unique(y_test)) > 1 else float('nan')
        except Exception:
            auc = float('nan')
        best = sweep_best_threshold(scores, y_test)

    # ensure JSON-serializable native Python types
    report.append({'attack': csv.name.replace('attack_','').replace('.csv',''),
               'n_attack_windows': int(X_attack.shape[0]),
               'auc': float(auc) if not (auc is None) else None,
               'best_f1': float(best.get('f1', 0)),
               'best_threshold': float(best.get('thr')) if best.get('thr') is not None else None,
               'prec': float(best.get('prec', 0)),
               'rec': float(best.get('rec', 0)),
               'tp': int(best.get('tp', 0)), 'fp': int(best.get('fp', 0)), 'tn': int(best.get('tn', 0)), 'fn': int(best.get('fn', 0))})

    # global combined test
    all_attack_frames = []
    for csv in attack_csvs:
        _, num = load_numeric(csv)
        if num.empty:
            continue
        if featcols is not None:
            num = num.reindex(columns=featcols).fillna(0)
        all_attack_frames.append(num)
    if all_attack_frames:
        X_attack_all = pd.concat(all_attack_frames, ignore_index=True).values
        X_test = np.vstack([X_holdout, X_attack_all])
        y_test = np.concatenate([np.zeros(X_holdout.shape[0], dtype=int), np.ones(X_attack_all.shape[0], dtype=int)])
        scores_all = score_with_model(model, scaler, X_test)
        try:
            auc_all = float(roc_auc_score(y_test, scores_all))
        except Exception:
            auc_all = float('nan')
        best_all = sweep_best_threshold(scores_all, y_test)
    else:
        auc_all = float('nan')
        best_all = {'f1': 0}

    out = {'per_attack': report, 'combined': {'auc': auc_all, 'best_f1': best_all.get('f1'), 'best_threshold': best_all.get('thr')}}
    print(json.dumps(out, indent=2))
    return 0


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--outdir', default='experiments/run_live_v1')
    args = p.parse_args()
    raise SystemExit(analyze(Path(args.outdir)))
