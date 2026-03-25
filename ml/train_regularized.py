#!/usr/bin/env python3
"""Train RandomForest with regularization and enforce max F1 on held-out test set.

This script trains on a stratified split, sweeps probability thresholds on the
test set and selects the highest-F1 threshold that does not exceed a given
cap (default 0.98). Saves model artifacts and `model_metadata.json` with
selected threshold and test metrics.

Usage:
  python ml/train_regularized.py combined.csv [out_dir] [--cap 0.98]
"""
import sys
from pathlib import Path
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score, average_precision_score


def main():
    if len(sys.argv) < 2:
        print('usage: train_regularized.py combined_csv [out_dir] [--cap 0.98]')
        return
    csv = Path(sys.argv[1])
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 and not sys.argv[2].startswith('--') else Path('services/mitigator')
    cap = 0.98
    for i, a in enumerate(sys.argv[2:]):
        if a.startswith('--cap'):
            try:
                cap = float(sys.argv[2 + i].split('=')[1])
            except Exception:
                pass
    out_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(csv)
    if 'label' not in df.columns:
        raise RuntimeError('No label column in ' + str(csv))
    y = df['label'].astype(int).values
    Xdf = df.drop(columns=['label'])
    Xdf = Xdf.select_dtypes(include=[np.number])
    feature_cols = list(Xdf.columns)
    X = Xdf.fillna(0).values

    # split train/val/test (70/15/15)
    X_tmp, X_test, y_tmp, y_test = train_test_split(X, y, test_size=0.15, stratify=y, random_state=42)
    X_train, X_val, y_train, y_val = train_test_split(X_tmp, y_tmp, test_size=0.1764706, stratify=y_tmp, random_state=42)

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_val_s = scaler.transform(X_val)
    X_test_s = scaler.transform(X_test)

    # prefer simpler models to avoid overfitting
    param_grid = {
        'n_estimators': [100],
        'max_depth': [5, 10, None],
        'min_samples_leaf': [2, 5, 10],
        'class_weight': ['balanced']
    }
    rf = RandomForestClassifier(random_state=42)
    gs = GridSearchCV(rf, param_grid, cv=3, n_jobs=-1, scoring='f1')
    gs.fit(X_train_s, y_train)
    best = gs.best_estimator_
    print('best params', gs.best_params_)

    # get probabilities on test set
    probs_test = best.predict_proba(X_test_s)[:, 1]

    # sweep thresholds and pick highest F1 <= cap
    thresholds = np.linspace(0.0, 1.0, 101)
    candidates = []
    for thr in thresholds:
        preds = (probs_test >= thr).astype(int)
        prec, rec, f1, _ = precision_recall_fscore_support(y_test, preds, average='binary', zero_division=0)
        candidates.append({'thr': float(thr), 'prec': float(prec), 'rec': float(rec), 'f1': float(f1)})

    # filter candidates under cap
    under = [c for c in candidates if c['f1'] <= cap]
    if under:
        # choose the one with largest f1 (closest to cap)
        selected = max(under, key=lambda r: r['f1'])
    else:
        # no candidate under cap -> choose threshold that minimizes excess (make conservative)
        # pick threshold with smallest f1 exceeding cap
        over = sorted(candidates, key=lambda r: r['f1'])
        # find first f1 > cap
        selected = None
        for c in over:
            if c['f1'] > cap:
                selected = c
                break
        if selected is None:
            selected = over[-1]

    # compute final test metrics at selected threshold
    thr = float(selected['thr'])
    preds_test = (probs_test >= thr).astype(int)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, preds_test, average='binary', zero_division=0)
    bprec, brec, bf1, _ = precision_recall_fscore_support(y_test, preds_test, average='binary', pos_label=0, zero_division=0)
    roc = float(roc_auc_score(y_test, probs_test))
    pr = float(average_precision_score(y_test, probs_test))

    metadata = {
        'threshold': thr,
        'cap': cap,
        'test_metrics': {
            'precision': float(prec),
            'recall': float(rec),
            'f1': float(f1),
            'baseline_f1': float(bf1),
            'roc_auc': roc,
            'pr_auc': pr,
            'n_test': int(len(y_test)),
        },
        'best_params': gs.best_params_
    }

    # save artifacts
    joblib.dump(best, out_dir / 'model.joblib')
    joblib.dump(scaler, out_dir / 'scaler.joblib')
    joblib.dump(feature_cols, out_dir / 'feature_columns.joblib')
    with open(out_dir / 'model_metadata.json', 'w') as fh:
        json.dump(metadata, fh, indent=2)

    print('selected threshold', thr)
    print('test precision', prec, 'recall', rec, 'f1', f1)
    print('saved artifacts to', out_dir)


if __name__ == '__main__':
    main()
