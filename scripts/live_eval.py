#!/usr/bin/env python3
"""Live evaluation helper: query running mitigator for windows in experiment pcaps
and compute precision / recall / f1 (per-attack and combined) using an operational
threshold. Default threshold is read from experiments/*/mitigator/model_metadata.json
if present; can be overridden with --threshold.

Usage: python3 scripts/live_eval.py --outdir experiments/run_live_v1 --mitigator http://127.0.0.1:8080
"""
import argparse
import json
import requests
from pathlib import Path
import statistics

try:
    from sklearn.metrics import precision_recall_fscore_support, roc_auc_score, average_precision_score
    SKLEARN = True
except Exception:
    SKLEARN = False


def load_threshold(outdir: Path):
    md = outdir / 'mitigator' / 'model_metadata.json'
    if md.exists():
        try:
            j = json.load(open(md))
            if 'threshold' in j:
                return float(j['threshold'])
        except Exception:
            pass
    return None


def score_pcaps(outdir: Path, mitigator: str, window_size: float = 3.0):
    pcaps = {}
    base = outdir
    # baseline first
    baseline_pcap = base / 'baseline_replica.pcap'
    if baseline_pcap.exists():
        pcaps['baseline'] = baseline_pcap
    # attacks
    for p in sorted(base.glob('attack_*.pcap')):
        pcaps[p.stem.replace('attack_', '')] = p

    results = {}
    for name, p in pcaps.items():
        if not p.exists():
            continue
        # estimate windows from csv if available
        csv = base / (p.stem + '.csv')
        n_windows = None
        if csv.exists():
            try:
                import pandas as pd
                n_windows = len(pd.read_csv(csv))
            except Exception:
                n_windows = 50
        if n_windows is None:
            n_windows = 50
        rows = []
        for i in range(n_windows):
            try:
                r = requests.post(mitigator.rstrip('/') + '/infer_from_pcap', json={'pcap_path': str(p), 'window_index': i, 'window_size': window_size}, timeout=5)
                if r.status_code != 200:
                    # skip windows that fail
                    continue
                j = r.json()
                rows.append({'index': i, 'score': float(j.get('anomaly_score', 0.0)), 'is_anomaly': bool(j.get('is_anomaly', False))})
            except Exception:
                continue
        results[name] = rows
    return results


def compute_metrics(results, threshold=None, min_consecutive: int = 0):
    # Build combined arrays and per-attack metrics
    per_attack = {}
    all_y = []
    all_pred = []
    all_scores = []
    for name, rows in results.items():
        if name == 'baseline':
            y_true = [0] * len(rows)
        else:
            y_true = [1] * len(rows)
        scores = [r['score'] for r in rows]
        if threshold is None:
            # use mitigator is_anomaly as prediction if no threshold provided
            preds = [1 if r.get('is_anomaly') else 0 for r in rows]
        else:
            preds = [1 if s >= threshold else 0 for s in scores]

        # apply hysteresis / min consecutive filter: only keep anomaly labels
        # that are part of a run of length >= min_consecutive
        if min_consecutive and min_consecutive > 1 and preds:
            new_preds = [0] * len(preds)
            run_start = None
            for i, v in enumerate(preds):
                if v == 1:
                    if run_start is None:
                        run_start = i
                else:
                    if run_start is not None:
                        run_len = i - run_start
                        if run_len >= min_consecutive:
                            for j in range(run_start, i):
                                new_preds[j] = 1
                        run_start = None
            # handle tail run
            if run_start is not None:
                run_len = len(preds) - run_start
                if run_len >= min_consecutive:
                    for j in range(run_start, len(preds)):
                        new_preds[j] = 1
            preds = new_preds

        # compute metrics
        # Special-case baseline: report metrics for "normal detection" by treating
        # baseline (normal) windows as the positive class. This gives meaningful
        # precision/recall/F1 for baseline (otherwise baseline has no positive
        # labels and sklearn will return zeros).
        if name == 'baseline':
            if SKLEARN and len(y_true) > 0:
                # pos_label=0 treats label 0 as the positive class (normal)
                prec, rec, f1, _ = precision_recall_fscore_support(
                    y_true, preds, average='binary', pos_label=0, zero_division=0
                )
            else:
                # fallback: invert labels and predictions and compute metrics
                inv_y = [1 - v for v in y_true]
                inv_preds = [1 - v for v in preds]
                tp = sum(1 for a, b in zip(inv_y, inv_preds) if a == 1 and b == 1)
                fp = sum(1 for a, b in zip(inv_y, inv_preds) if a == 0 and b == 1)
                fn = sum(1 for a, b in zip(inv_y, inv_preds) if a == 1 and b == 0)
                prec = tp / (tp + fp) if (tp + fp) else 0.0
                rec = tp / (tp + fn) if (tp + fn) else 0.0
                f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
        else:
            if SKLEARN and len(y_true) > 0 and (sum(y_true) + (len(y_true)-sum(y_true)))>0:
                prec, rec, f1, _ = precision_recall_fscore_support(y_true, preds, average='binary', zero_division=0)
            else:
                # simple fallback
                tp = sum(1 for a, b in zip(y_true, preds) if a == 1 and b == 1)
                fp = sum(1 for a, b in zip(y_true, preds) if a == 0 and b == 1)
                fn = sum(1 for a, b in zip(y_true, preds) if a == 1 and b == 0)
                prec = tp / (tp + fp) if (tp + fp) else 0.0
                rec = tp / (tp + fn) if (tp + fn) else 0.0
                f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0

        per_attack[name] = {'n_windows': len(rows), 'n_anomalies_pred': int(sum(preds)), 'precision': float(prec), 'recall': float(rec), 'f1': float(f1)}

        all_y.extend(y_true)
        all_pred.extend(preds)
        all_scores.extend(scores)

    # combined
    combined = {}
    if all_y:
        if SKLEARN:
            try:
                auc = float(roc_auc_score(all_y, all_scores))
            except Exception:
                auc = None
            try:
                pr_auc = float(average_precision_score(all_y, all_scores))
            except Exception:
                pr_auc = None
            prec, rec, f1, _ = precision_recall_fscore_support(all_y, all_pred, average='binary', zero_division=0)
            combined = {'n_total': len(all_y), 'precision': float(prec), 'recall': float(rec), 'f1': float(f1), 'roc_auc': auc, 'pr_auc': pr_auc}
        else:
            tp = sum(1 for a, b in zip(all_y, all_pred) if a == 1 and b == 1)
            fp = sum(1 for a, b in zip(all_y, all_pred) if a == 0 and b == 1)
            fn = sum(1 for a, b in zip(all_y, all_pred) if a == 1 and b == 0)
            prec = tp / (tp + fp) if (tp + fp) else 0.0
            rec = tp / (tp + fn) if (tp + fn) else 0.0
            f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
            combined = {'n_total': len(all_y), 'precision': float(prec), 'recall': float(rec), 'f1': float(f1)}

    return {'per_attack': per_attack, 'combined': combined}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--outdir', default='experiments/run_live_v1')
    p.add_argument('--mitigator', default='http://127.0.0.1:8080')
    p.add_argument('--threshold', type=float, default=None, help='optional numeric threshold to apply to anomaly_score (if omitted uses metadata threshold or mitigator is_anomaly)')
    p.add_argument('--sweep', action='store_true', help='sweep thresholds across observed score quantiles and report best-F1 and table of metrics')
    p.add_argument('--min-consecutive', type=int, default=0, help='require this many consecutive anomalous windows to count as an anomaly (hysteresis)')
    p.add_argument('--window-size', type=float, default=3.0)
    args = p.parse_args()

    outdir = Path(args.outdir)
    thr = args.threshold
    if thr is None:
        t = load_threshold(outdir)
        if t is not None:
            thr = t
            print('Using threshold from metadata:', thr)
        else:
            print('No threshold provided and metadata missing; will use mitigator is_anomaly flags')

    results = score_pcaps(outdir, args.mitigator, window_size=args.window_size)
    if args.sweep:
        # collect all observed scores
        all_scores = []
        for rows in results.values():
            all_scores.extend([r['score'] for r in rows])
        if not all_scores:
            print('No scores observed to sweep over')
            return
        qs = [i/100.0 for i in range(0, 101, 1)]
        best = {'f1': -1, 'thr': None, 'prec': 0, 'rec': 0}
        table = []
        import numpy as _np
        for q in qs:
            thr_q = float(_np.quantile(all_scores, q))
            m = compute_metrics(results, threshold=thr_q, min_consecutive=args.min_consecutive)
            f1 = m['combined'].get('f1', 0.0)
            prec = m['combined'].get('precision', 0.0)
            rec = m['combined'].get('recall', 0.0)
            table.append({'quantile': q, 'threshold': thr_q, 'precision': prec, 'recall': rec, 'f1': f1})
            if f1 > best['f1']:
                best.update({'f1': f1, 'thr': thr_q, 'prec': prec, 'rec': rec})
        print('best by F1:', best)
        print(json.dumps(table, indent=2))
    else:
        metrics = compute_metrics(results, threshold=thr, min_consecutive=args.min_consecutive)
        print(json.dumps(metrics, indent=2))


if __name__ == '__main__':
    main()
