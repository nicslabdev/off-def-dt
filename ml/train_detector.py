#!/usr/bin/env python3
"""Train a simple Random Forest classifier on extracted window features.

Usage: python ml/train_detector.py combined_data.csv
Saves model and scaler to services/mitigator/model.joblib and scaler.joblib
"""
import argparse
import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.metrics import make_scorer, f1_score
from collections import Counter

def train(combined_csv, out_dir='services/mitigator'):
    df = pd.read_csv(combined_csv)
    # Extract labels and features
    if 'label' not in df.columns:
        raise RuntimeError('No label column found in ' + combined_csv)
    labels = df['label']
    features = df.drop(columns=['label'])

    # Debugging: Check label distribution
    print("Label distribution:", Counter(labels))

    # Ensure labels are integers
    labels = labels.astype(int)

    # drop non-numeric columns if present
    numeric = features.select_dtypes(include=['number'])
    if numeric.empty:
        raise RuntimeError('no numeric features found in ' + combined_csv)
    X = numeric.fillna(0).values
    y = labels.values.ravel()  # Flatten labels
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    # Hyperparameter tuning for RandomForestClassifier
    param_grid = {
        'n_estimators': [100, 200, 300],
        'max_depth': [None, 10, 20, 30],
        'min_samples_split': [2, 5, 10],
        'min_samples_leaf': [1, 2, 4]
    }
    cv = StratifiedKFold(n_splits=2, shuffle=True, random_state=42)  # Reduced splits to handle small class sizes
    scorer = make_scorer(f1_score, pos_label=1)
    grid_search = GridSearchCV(RandomForestClassifier(random_state=42), param_grid, scoring=scorer, cv=cv, n_jobs=-1)
    grid_search.fit(Xs, y)
    model = grid_search.best_estimator_

    os.makedirs(out_dir, exist_ok=True)
    joblib.dump(model, os.path.join(out_dir, 'model.joblib'))
    joblib.dump(scaler, os.path.join(out_dir, 'scaler.joblib'))
    # save feature columns
    joblib.dump(list(numeric.columns), os.path.join(out_dir, 'feature_columns.joblib'))
    print('saved optimized model and scaler to', out_dir)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('combined_csv')
    p.add_argument('--out-dir', default='services/mitigator')
    args = p.parse_args()
    train(args.combined_csv, out_dir=args.out_dir)

if __name__ == '__main__':
    main()
