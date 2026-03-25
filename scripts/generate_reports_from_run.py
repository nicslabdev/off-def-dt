#!/usr/bin/env python3
"""Generate per-attack and per-protocol CSVs and a Markdown report for a run dir.

Usage: python scripts/generate_reports_from_run.py experiments/run_live_evasion_vN
"""
import sys
import os
import glob
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_fscore_support


def load_model_artifacts():
    M = os.path.join('services', 'mitigator')
    model = joblib.load(os.path.join(M, 'model.joblib'))
    scaler = joblib.load(os.path.join(M, 'scaler.joblib'))
    cols = joblib.load(os.path.join(M, 'feature_columns.joblib'))
    meta = {}
    try:
        meta = json.load(open(os.path.join(M, 'model_metadata.json')))
    except Exception:
        pass
    threshold = meta.get('threshold') or meta.get('anomaly_threshold') or 0.5
    return model, scaler, cols, threshold


def load_defensive_artifacts():
    """Load optional defensive artifacts from services/defensive_dt.

    Returns (model, scaler, cols) where any may be None if not present.
    """
    dmodel = None
    dscaler = None
    dcols = None
    base = os.path.join('services', 'defensive_dt')
    try:
        mpath = os.path.join(base, 'model.joblib')
        if os.path.exists(mpath):
            dmodel = joblib.load(mpath)
    except Exception:
        dmodel = None
    try:
        spath = os.path.join(base, 'scaler.joblib')
        if os.path.exists(spath):
            dscaler = joblib.load(spath)
    except Exception:
        dscaler = None
    try:
        cpath = os.path.join(base, 'feature_columns.joblib')
        if os.path.exists(cpath):
            dcols = joblib.load(cpath)
    except Exception:
        dcols = None
    return dmodel, dscaler, dcols


def compute_scores(df, model, scaler, cols):
    use = [c for c in cols if c in df.columns]
    X = scaler.transform(df[use].fillna(0).values)
    if hasattr(model, 'predict_proba'):
        s = model.predict_proba(X)[:, 1]
    elif hasattr(model, 'decision_function'):
        s = model.decision_function(X)
    else:
        s = model.predict(X)
    return s


def generate(run_dir):
    model, scaler, cols, threshold = load_model_artifacts()
    dmodel, dscaler, dcols = load_defensive_artifacts()
    run_dir = os.path.abspath(run_dir)
    # find attack files
    attack_files = sorted(glob.glob(os.path.join(run_dir, 'attack_*.csv')))
    # baseline
    baseline = None
    for p in ('baseline_replica.csv',):
        candidate = os.path.join(run_dir, p)
        if os.path.exists(candidate):
            baseline = candidate
            break
    if not baseline:
        print('No baseline in', run_dir); return

    # prepare adv logs per eps
    adv_logs = sorted(glob.glob(os.path.join(run_dir, 'gb_mifgsm_eps*_adversarial_log.jsonl')))
    adv_by_eps = {}
    for log in adv_logs:
        sfx = os.path.basename(log).split('eps')[1].split('_')[0]
        eps = float(str(sfx).replace('p', '.'))
        adv_map = {}
        with open(log) as fh:
            for line in fh:
                try:
                    j = json.loads(line)
                except Exception:
                    continue
                key = (j.get('attack_file'), int(j.get('window_index', 0)))
                # store score and adv_features if available
                adv_map[key] = {
                    'adv_score': j.get('adv_score'),
                    'adv_features': j.get('adv_features') if 'adv_features' in j else None,
                }
        adv_by_eps[eps] = adv_map

    rows_attack = []
    proto_groups = {'mqtt': [], 'modbus': [], 'other': []}
    for attack_path in attack_files:
        attack_basename = os.path.basename(attack_path)
        parts = []
        for b in (baseline, attack_path):
            df = pd.read_csv(b)
            src = os.path.basename(b)
            df['__source_file'] = src
            df['__local_index'] = list(range(len(df)))
            if 'label' not in df.columns:
                df['label'] = 0 if 'baseline' in src else 1
            parts.append(df)
        combined = pd.concat(parts, ignore_index=True)
        orig_scores = compute_scores(combined, model, scaler, cols)
        y = combined['label'].astype(int).values
        prec_b, rec_b, f1_b, _ = precision_recall_fscore_support(y, (orig_scores >= threshold).astype(int), average='binary', zero_division=0)
        for eps, adv_map in sorted(adv_by_eps.items()):
            scores_after = orig_scores.copy()
            replaced = 0
            for key, adv in adv_map.items():
                atk_file, idx = key
                if os.path.basename(atk_file) != attack_basename:
                    continue
                mask = (combined['__source_file'] == atk_file) & (combined['__local_index'] == idx)
                hits = np.where(mask.values)[0]
                if len(hits) == 0:
                    continue
                i = hits[0]
                # adv may be dict with adv_score
                if isinstance(adv, dict):
                    scores_after[i] = adv.get('adv_score', scores_after[i])
                else:
                    scores_after[i] = adv
                replaced += 1
            prec_a, rec_a, f1_a, _ = precision_recall_fscore_support(y, (scores_after >= threshold).astype(int), average='binary', zero_division=0)
            # apply defensive countermeasure if available: mark detected adv samples as anomalies
            scores_after_cm = scores_after.copy()
            if dmodel is not None:
                for key, adv in adv_map.items():
                    atk_file, idx = key
                    if os.path.basename(atk_file) != attack_basename:
                        continue
                    mask = (combined['__source_file'] == atk_file) & (combined['__local_index'] == idx)
                    hits = np.where(mask.values)[0]
                    if len(hits) == 0:
                        continue
                    i = hits[0]
                    adv_features = None
                    if isinstance(adv, dict):
                        adv_features = adv.get('adv_features')
                    # if adv_features dict available, build feature vector; otherwise skip
                    if adv_features and dcols is not None:
                        use = [c for c in dcols if c in adv_features]
                        if use:
                            x = [adv_features.get(c, 0.0) for c in dcols]
                            Xd = np.array(x).reshape(1, -1)
                            if dscaler is not None:
                                try:
                                    Xd_s = dscaler.transform(Xd)
                                except Exception:
                                    Xd_s = Xd
                            else:
                                Xd_s = Xd
                            try:
                                dpred = None
                                if hasattr(dmodel, 'predict'):
                                    dpred = int(dmodel.predict(Xd_s)[0])
                                # if defensive model flags adversarial (label==1), invert the
                                # detector's predicted label for this sample so the countermeasure
                                # consistently flips the decision (not always forcing anomaly)
                                if dpred == 1:
                                    current_label = 1 if (scores_after[i] >= threshold) else 0
                                    # set score to the opposite side of threshold
                                    scores_after_cm[i] = 0.0 if current_label == 1 else 1.0
                            except Exception:
                                pass
            prec_cm, rec_cm, f1_cm, _ = precision_recall_fscore_support(y, (scores_after_cm >= threshold).astype(int), average='binary', zero_division=0)
            rows_attack.append({'attack_file': attack_basename, 'eps': eps, 'replaced': replaced, 'precision_before': prec_b, 'recall_before': rec_b, 'f1_before': f1_b, 'precision_after': prec_a, 'recall_after': rec_a, 'f1_after': f1_a, 'precision_after_cm': prec_cm, 'recall_after_cm': rec_cm, 'f1_after_cm': f1_cm})
        lname = attack_basename.lower()
        if 'mqtt' in lname:
            proto_groups['mqtt'].append(attack_path)
        elif 'modbus' in lname:
            proto_groups['modbus'].append(attack_path)
        else:
            proto_groups['other'].append(attack_path)

    rows_proto = []
    for proto, paths in proto_groups.items():
        if not paths:
            continue
        parts = []
        for b in (baseline,) + tuple(paths):
            df = pd.read_csv(b)
            src = os.path.basename(b)
            df['__source_file'] = src
            df['__local_index'] = list(range(len(df)))
            if 'label' not in df.columns:
                df['label'] = 0 if 'baseline' in src else 1
            parts.append(df)
        combined = pd.concat(parts, ignore_index=True)
        orig_scores = compute_scores(combined, model, scaler, cols)
        y = combined['label'].astype(int).values
        prec_b, rec_b, f1_b, _ = precision_recall_fscore_support(y, (orig_scores >= threshold).astype(int), average='binary', zero_division=0)
        for eps, adv_map in sorted(adv_by_eps.items()):
            scores_after = orig_scores.copy()
            replaced = 0
            for key, adv in adv_map.items():
                atk_file, idx = key
                if os.path.basename(atk_file) not in [os.path.basename(p) for p in paths]:
                    continue
                mask = (combined['__source_file'] == atk_file) & (combined['__local_index'] == idx)
                hits = np.where(mask.values)[0]
                if len(hits) == 0:
                    continue
                i = hits[0]
                if isinstance(adv, dict):
                    scores_after[i] = adv.get('adv_score', scores_after[i])
                else:
                    scores_after[i] = adv
                replaced += 1
            prec_a, rec_a, f1_a, _ = precision_recall_fscore_support(y, (scores_after >= threshold).astype(int), average='binary', zero_division=0)
            # defensive countermeasure metrics
            scores_after_cm = scores_after.copy()
            if dmodel is not None:
                for key, adv in adv_map.items():
                    atk_file, idx = key
                    if os.path.basename(atk_file) not in [os.path.basename(p) for p in paths]:
                        continue
                    mask = (combined['__source_file'] == atk_file) & (combined['__local_index'] == idx)
                    hits = np.where(mask.values)[0]
                    if len(hits) == 0:
                        continue
                    i = hits[0]
                    adv_features = None
                    if isinstance(adv, dict):
                        adv_features = adv.get('adv_features')
                    if adv_features and dcols is not None:
                        x = [adv_features.get(c, 0.0) for c in dcols]
                        Xd = np.array(x).reshape(1, -1)
                        if dscaler is not None:
                            try:
                                Xd_s = dscaler.transform(Xd)
                            except Exception:
                                Xd_s = Xd
                        else:
                            Xd_s = Xd
                        try:
                            dpred = None
                            if hasattr(dmodel, 'predict'):
                                dpred = int(dmodel.predict(Xd_s)[0])
                            if dpred == 1:
                                current_label = 1 if (scores_after[i] >= threshold) else 0
                                scores_after_cm[i] = 0.0 if current_label == 1 else 1.0
                        except Exception:
                            pass
            prec_cm, rec_cm, f1_cm, _ = precision_recall_fscore_support(y, (scores_after_cm >= threshold).astype(int), average='binary', zero_division=0)
            rows_proto.append({'protocol': proto, 'eps': eps, 'replaced': replaced, 'precision_before': prec_b, 'recall_before': rec_b, 'f1_before': f1_b, 'precision_after': prec_a, 'recall_after': rec_a, 'f1_after': f1_a, 'precision_after_cm': prec_cm, 'recall_after_cm': rec_cm, 'f1_after_cm': f1_cm})
            

    out_csv_attack = os.path.join(run_dir, 'per_attack_evasion_summary.csv')
    out_csv_proto = os.path.join(run_dir, 'per_protocol_evasion_summary.csv')
    pd.DataFrame(rows_attack).to_csv(out_csv_attack, index=False)
    pd.DataFrame(rows_proto).to_csv(out_csv_proto, index=False)

    # write a simple markdown summary
    md_lines = []
    md_lines.append('# Per-attack and per-protocol summary')
    md_lines.append('\n## Per-attack CSV')
    md_lines.append(f'- {out_csv_attack}')
    md_lines.append('\n## Per-protocol CSV')
    md_lines.append(f'- {out_csv_proto}')
    md_path = os.path.join(run_dir, 'run_report_by_attack.md')
    with open(md_path, 'w') as fh:
        fh.write('\n'.join(md_lines))
    print('Wrote', out_csv_attack, out_csv_proto, md_path)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: generate_reports_from_run.py <run_dir>')
        sys.exit(1)
    generate(sys.argv[1])
