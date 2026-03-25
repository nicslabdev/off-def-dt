#!/usr/bin/env python3
"""Train RandomForest and select probability threshold by sweeping to meet targets.

Saves: services/mitigator/model.joblib, scaler.joblib, feature_columns.joblib,
  model_metadata.json (includes selected threshold)

Usage:
  python ml/train_with_threshold.py experiments/run_live_v2_cleaned/combined_data_fixed.csv
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
        print('usage: train_with_threshold.py combined_csv [out_dir]')
        return
    csv = Path(sys.argv[1])
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path('services/mitigator')
    out_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(csv)
    if 'label' not in df.columns:
        raise RuntimeError('No label column in ' + str(csv))
    y = df['label'].astype(int).values
    Xdf = df.drop(columns=['label'])
    # keep numeric cols only
    Xdf = Xdf.select_dtypes(include=[np.number])
    feature_cols = list(Xdf.columns)

    X = Xdf.fillna(0).values

    # split
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_val_s = scaler.transform(X_val)

    # grid search with class_weight balanced to reduce baseline false positives
    param_grid = {
        'n_estimators': [100, 200],
        'max_depth': [10, 20, None],
        'min_samples_leaf': [1, 2],
        'class_weight': ['balanced']
    }
    rf = RandomForestClassifier(random_state=42)
    gs = GridSearchCV(rf, param_grid, cv=3, n_jobs=-1, scoring='f1')
    gs.fit(X_train_s, y_train)
    best = gs.best_estimator_
    print('best params', gs.best_params_)

    # predict probabilities on validation
    if hasattr(best, 'predict_proba'):
        probs = best.predict_proba(X_val_s)[:, 1]
    else:
        # fallback to decision_function
        probs = -best.decision_function(X_val_s)

    # sweep thresholds
    thresholds = np.linspace(0.0, 1.0, 101)
    best_row = None
    rows = []
    for thr in thresholds:
        preds = (probs >= thr).astype(int)
        # combined metrics
        prec, rec, f1, _ = precision_recall_fscore_support(y_val, preds, average='binary', zero_division=0)
        # baseline f1 (treat 0 as positive)
        try:
            bprec, brec, bf1, _ = precision_recall_fscore_support(y_val, preds, average='binary', pos_label=0, zero_division=0)
        except Exception:
            # fallback compute manually
            inv_y = 1 - y_val
            inv_preds = 1 - preds
            tp = int(((inv_y==1) & (inv_preds==1)).sum())
            fp = int(((inv_y==0) & (inv_preds==1)).sum())
            fn = int(((inv_y==1) & (inv_preds==0)).sum())
            bprec = tp/(tp+fp) if (tp+fp) else 0.0
            brec = tp/(tp+fn) if (tp+fn) else 0.0
            bf1 = (2*bprec*brec/(bprec+brec)) if (bprec+brec) else 0.0

        rows.append({'thr': float(thr), 'prec': float(prec), 'rec': float(rec), 'f1': float(f1), 'b_f1': float(bf1)})

        # selection: prefer thresholds meeting constraints
        if bf1 > 0.5 and f1 > 0.6 and prec > 0.4:
            if best_row is None or f1 > best_row['f1']:
                best_row = {'thr': thr, 'prec': prec, 'rec': rec, 'f1': f1, 'b_f1': bf1}

    if best_row is None:
        # choose threshold with highest combined f1
        best_row = max(rows, key=lambda r: r['f1'])

    print('selected threshold', best_row)

    # save artifacts
    joblib.dump(best, out_dir / 'model.joblib')
    joblib.dump(scaler, out_dir / 'scaler.joblib')
    joblib.dump(feature_cols, out_dir / 'feature_columns.joblib')
    md = {'threshold': float(best_row['thr']), 'selected_metrics': best_row}
    with open(out_dir / 'model_metadata.json', 'w') as fh:
        json.dump(md, fh, indent=2)

    print('saved model and metadata to', out_dir)


if __name__ == '__main__':
    main()
