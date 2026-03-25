#!/usr/bin/env python3
"""Offensive DT adversarial evasion module.

Provides constrained PGD and MIFGSM attacks in a gray-box setting against the
RandomForest classifier used by the mitigator. The attacker operates on
feature vectors extracted from windows and respects feature masks and
value clipping to keep perturbed samples realistic.

API functions:
- attack_pgd(X, predict_fn, eps, alpha, steps, mask, clip_min, clip_max)
- attack_mifgsm(X, predict_fn, eps, alpha, steps, mask, clip_min, clip_max, momentum)

The module includes helpers to build a realistic mask (discrete features
protected) and clipping bounds (based on per-feature means/std or provided
values).
"""
from typing import Callable, Tuple, Optional
import numpy as np


def default_mask(feature_names):
    """Return mask array (1 => can perturb, 0 => protected) based on simple heuristics.

    Heuristics: features with names containing 'unique', 'count', 'id', 'src', 'dst',
    or that are integer-like should be treated as discrete and protected.
    """
    mask = np.ones(len(feature_names), dtype=float)
    for i, n in enumerate(feature_names):
        ln = n.lower()
        if any(k in ln for k in ('unique', 'count', 'id', 'src', 'dst', 'topic')):
            mask[i] = 0.0
    return mask


def build_clip_bounds(X: np.ndarray, clip_scale: float = 3.0) -> Tuple[np.ndarray, np.ndarray]:
    """Compute per-feature clipping bounds from data: mean +/- clip_scale*std.

    Returns (min, max) arrays for clipping perturbed features.
    """
    mu = np.nanmean(X, axis=0)
    std = np.nanstd(X, axis=0)
    clip_min = mu - clip_scale * std
    clip_max = mu + clip_scale * std
    # for near-zero std, expand small epsilon bounds
    small = std < 1e-6
    clip_min[small] = mu[small] - 1.0
    clip_max[small] = mu[small] + 1.0
    return clip_min, clip_max


def _project(x_adv, x_orig, mask, eps, clip_min, clip_max):
    """Project perturbation to L-infinity ball with mask and clip to bounds."""
    delta = x_adv - x_orig
    # mask applied to delta: protected features stay zero
    delta = delta * mask
    delta = np.clip(delta, -eps, eps)
    x_proj = x_orig + delta
    x_proj = np.minimum(np.maximum(x_proj, clip_min), clip_max)
    return x_proj


def attack_pgd(X: np.ndarray,
               predict_fn: Callable[[np.ndarray], np.ndarray],
               eps: float = 0.1,
               alpha: float = 0.02,
               steps: int = 10,
               mask: Optional[np.ndarray] = None,
               clip_min: Optional[np.ndarray] = None,
               clip_max: Optional[np.ndarray] = None) -> np.ndarray:
    """Perform constrained PGD (L-inf) on a batch of feature vectors.

    predict_fn: callable that accepts a (N, D) array and returns logits or
                probabilities for the positive class (shape (N,) ). In the
                gray-box setting we only query probabilities.
    Returns perturbed X_adv array of same shape.
    """
    X = X.astype(float)
    N, D = X.shape
    if mask is None:
        mask = np.ones(D, dtype=float)
    if clip_min is None or clip_max is None:
        clip_min = np.min(X, axis=0) - 1.0
        clip_max = np.max(X, axis=0) + 1.0

    X_adv = X.copy()
    for step in range(steps):
        # gray-box: estimate gradient via finite differences on probability
        probs = predict_fn(X_adv)
        grad = np.zeros_like(X_adv)
        # finite-diff: perturb each feature slightly (vectorized by batch)
        h = 1e-3
        for j in range(D):
            if mask[j] == 0.0:
                continue
            e = np.zeros(D)
            e[j] = h
            Xp = X_adv + e
            Xm = X_adv - e
            p_plus = predict_fn(Xp)
            p_minus = predict_fn(Xm)
            # approximate gradient of probability w.r.t feature j
            grad[:, j] = (p_plus - p_minus) / (2 * h)

        # ascend probability of negative class? For evasion we want reduce prob of positive (anomalous)
        # so we take negative gradient of prob
        X_adv = X_adv - alpha * np.sign(grad)
        # projection & clipping
        for i in range(N):
            X_adv[i] = _project(X_adv[i], X[i], mask, eps, clip_min, clip_max)

    return X_adv


def attack_mifgsm(X: np.ndarray,
                  predict_fn: Callable[[np.ndarray], np.ndarray],
                  eps: float = 0.1,
                  alpha: float = 0.02,
                  steps: int = 10,
                  mask: Optional[np.ndarray] = None,
                  clip_min: Optional[np.ndarray] = None,
                  clip_max: Optional[np.ndarray] = None,
                  momentum: float = 0.9) -> np.ndarray:
    """Momentum Iterative FGSM adapted to gray-box by using finite-diff gradients.
    """
    X = X.astype(float)
    N, D = X.shape
    if mask is None:
        mask = np.ones(D, dtype=float)
    if clip_min is None or clip_max is None:
        clip_min = np.min(X, axis=0) - 1.0
        clip_max = np.max(X, axis=0) + 1.0

    X_adv = X.copy()
    g = np.zeros_like(X)
    h = 1e-3
    for step in range(steps):
        probs = predict_fn(X_adv)
        grad = np.zeros_like(X_adv)
        for j in range(D):
            if mask[j] == 0.0:
                continue
            e = np.zeros(D)
            e[j] = h
            Xp = X_adv + e
            Xm = X_adv - e
            p_plus = predict_fn(Xp)
            p_minus = predict_fn(Xm)
            grad[:, j] = (p_plus - p_minus) / (2 * h)

        # update momentum: we want to reduce prob of positive class => negative grad
        g = momentum * g + grad / (np.mean(np.abs(grad), axis=1, keepdims=True) + 1e-12)
        X_adv = X_adv - alpha * np.sign(g)
        for i in range(N):
            X_adv[i] = _project(X_adv[i], X[i], mask, eps, clip_min, clip_max)

    return X_adv


def eval_evasion(X, y, predict_prob_fn, attack_fn, **attack_kwargs):
    """Run attack on positives and measure evasion and metric drop.

    - runs attack on positive-class samples (y==1) and on a balanced sample of negatives
    - returns dict with evasion_rate, f1_before/after, recall_before/after, precision_before/after
    """
    # full dataset baseline predictions
    probs = predict_prob_fn(X)
    preds = (probs >= attack_kwargs.get('threshold', 0.5)).astype(int)

    from sklearn.metrics import precision_recall_fscore_support
    prec_b, rec_b, f1_b, _ = precision_recall_fscore_support(y, preds, average='binary', zero_division=0)

    # attack only positives to measure evasions
    pos_idx = np.where(y == 1)[0]
    if len(pos_idx) == 0:
        return {}
    X_pos = X[pos_idx]
    X_pos_adv = attack_fn(X_pos, predict_prob_fn, **attack_kwargs)
    probs_pos_adv = predict_prob_fn(X_pos_adv)
    preds_pos_adv = (probs_pos_adv >= attack_kwargs.get('threshold', 0.5)).astype(int)
    # evasion: fraction of pos that become predicted negative
    evaded = (preds_pos_adv == 0).sum()
    evasion_rate = float(evaded) / len(pos_idx)

    # recompute metrics on full dataset with attacked positives replaced
    X_attacked = X.copy()
    X_attacked[pos_idx] = X_pos_adv
    probs_a = predict_prob_fn(X_attacked)
    preds_a = (probs_a >= attack_kwargs.get('threshold', 0.5)).astype(int)
    prec_a, rec_a, f1_a, _ = precision_recall_fscore_support(y, preds_a, average='binary', zero_division=0)

    return {
        'evasion_rate': evasion_rate,
        'precision_before': float(prec_b),
        'recall_before': float(rec_b),
        'f1_before': float(f1_b),
        'precision_after': float(prec_a),
        'recall_after': float(rec_a),
        'f1_after': float(f1_a),
        'n_pos': int(len(pos_idx)),
    }
#!/usr/bin/env python3
import argparse
import csv
import json
import math
import os
import time
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone

import numpy as np
import requests
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler


def _iso_now():
    return datetime.now(timezone.utc).isoformat()


def _to_bool(v, default=False):
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")


def load_attack_windows(run_dir, attack_glob="attack_*.csv", max_windows=None):
    windows = []
    files = sorted(
        os.path.join(run_dir, p)
        for p in os.listdir(run_dir)
        if p.startswith("attack_") and p.endswith(".csv")
    )
    for fp in files:
        with open(fp, "r", newline="") as fh:
            reader = csv.DictReader(fh)
            for idx, row in enumerate(reader):
                features = {}
                for k, v in row.items():
                    if k in ("start_ts", "end_ts"):
                        continue
                    try:
                        features[k] = float(v)
                    except Exception:
                        continue
                if not features:
                    continue
                windows.append(
                    {
                        "attack_file": os.path.basename(fp),
                        "window_index": idx,
                        "start_ts": row.get("start_ts"),
                        "end_ts": row.get("end_ts"),
                        "features": features,
                    }
                )
                if max_windows and len(windows) >= max_windows:
                    return windows
    return windows


def _stream_to_float(stream_key):
    if stream_key is None:
        return None
    s = str(stream_key).encode("utf-8")
    return float(zlib.crc32(s))


def infer_features(mitigator_url, features, timeout=10, stream_key=None):
    payload_features = dict(features)
    if stream_key is not None:
        payload_features["stream"] = _stream_to_float(stream_key)
    r = requests.post(
        mitigator_url.rstrip("/") + "/infer",
        json={"features": payload_features},
        timeout=timeout,
    )
    r.raise_for_status()
    j = r.json()
    return {
        "anomaly_score": float(j.get("anomaly_score", 0.0)),
        "is_anomaly": bool(j.get("is_anomaly", False)),
        "raw_is_anomaly": bool(j.get("raw_is_anomaly", j.get("is_anomaly", False))),
        "is_alert": bool(j.get("is_alert", False)),
        "stream_key": j.get("stream_key"),
    }


def get_mitigator_config(mitigator_url, timeout=10):
    try:
        r = requests.get(mitigator_url.rstrip("/") + "/config", timeout=timeout)
        r.raise_for_status()
        j = r.json()
        return {
            "anomaly_threshold": float(j.get("anomaly_threshold", 0.0)),
            "anomaly_hysteresis": int(j.get("anomaly_hysteresis", 1)),
        }
    except Exception:
        return {
            "anomaly_threshold": 0.0,
            "anomaly_hysteresis": 1,
        }


@dataclass
class AttackConfig:
    eps: float = 0.12
    alpha: float = 0.03
    steps: int = 6
    momentum: float = 0.9
    fd_eps: float = 0.02
    rel_clip: float = 0.20
    max_features: int = 12


def train_surrogate_model(features, labels):
    """Train a surrogate model to approximate the mitigator's decision boundary."""
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(features)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_scaled, labels)
    return model, scaler


def compute_surrogate_gradients(model, scaler, x):
    """Compute gradients using the surrogate model."""
    X_scaled = scaler.transform([x])
    # Use feature importances as a proxy for gradients (approximation)
    gradients = model.feature_importances_
    return gradients


def constrained_mifgsm(features, score_fn, cfg: AttackConfig):
    keys = list(features.keys())
    x0 = np.array([float(features[k]) for k in keys], dtype=float)
    x = x0.copy()
    m = np.zeros_like(x)

    scales = np.maximum(np.abs(x0), 1.0)
    eps_vec = cfg.eps * scales
    alpha_vec = cfg.alpha * scales
    rel_clip_vec = cfg.rel_clip * scales

    lb = np.maximum(0.0, x0 - np.minimum(eps_vec, rel_clip_vec))
    ub = x0 + np.minimum(eps_vec, rel_clip_vec)

    score_before = float(score_fn(x0))
    queries = 1

    # Use finite-difference gradient estimates per feature (gray-box)
    mask = default_mask(keys)
    h = np.maximum(cfg.fd_eps * scales, 1e-6)
    for _ in range(int(cfg.steps)):
        grad = np.zeros_like(x)
        # finite-difference per feature
        for j in range(len(x)):
            if mask[j] == 0.0:
                continue
            xp = x.copy()
            xm = x.copy()
            xp[j] = xp[j] + h[j]
            xm[j] = xm[j] - h[j]
            p_plus = score_fn(xp)
            p_minus = score_fn(xm)
            grad[j] = (p_plus - p_minus) / (2.0 * h[j])
            queries += 2

        # normalize and apply momentum
        denom = np.mean(np.abs(grad)) + 1e-12
        g_norm = grad / denom
        m = cfg.momentum * m + g_norm
        x = x - alpha_vec * np.sign(m)
        # project and clip
        for i in range(len(x)):
            x[i] = min(max(x[i], lb[i]), ub[i])
        # respect mask: protected features remain at original values
        x = x0 + (x - x0) * mask

    score_after = float(score_fn(x))
    adv_features = {k: float(v) for k, v in zip(keys, x.tolist())}
    delta = {k: adv_features[k] - float(features[k]) for k in keys}
    return {
        "adv_features": adv_features,
        "delta": delta,
        "score_before": score_before,
        "score_after": score_after,
        "queries": int(queries),
    }


def load_surrogate_model(model_path, scaler_path):
    """Load the surrogate model and scaler from disk."""
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    return model, scaler


def run_offensive_campaign(
    run_dir,
    mitigator_url,
    out_jsonl=None,
    out_summary=None,
    max_windows=200,
    timeout=10,
    cfg: AttackConfig | None = None,
    dry_run=True,
    mitigate_action="stop_service",
):
    cfg = cfg or AttackConfig()
    windows = load_attack_windows(run_dir, max_windows=max_windows)
    if not windows:
        raise RuntimeError(f"no attack windows loaded from {run_dir}")
    mitigator_cfg = get_mitigator_config(mitigator_url, timeout=timeout)
    anomaly_threshold = float(mitigator_cfg.get("anomaly_threshold", 0.0))
    anomaly_hysteresis = int(mitigator_cfg.get("anomaly_hysteresis", 1))

    out_jsonl = out_jsonl or os.path.join(run_dir, "offensive_dt_adversarial_log.jsonl")
    out_summary = out_summary or os.path.join(run_dir, "offensive_dt_impact.json")
    os.makedirs(os.path.dirname(out_jsonl), exist_ok=True)
    os.makedirs(os.path.dirname(out_summary), exist_ok=True)

    # Load surrogate model (optional)
    try:
        surrogate_model, surrogate_scaler = load_surrogate_model(
            "ml/surrogate_model.joblib",
            "ml/surrogate_scaler.joblib",
        )
    except Exception:
        surrogate_model = None
        surrogate_scaler = None

    total = 0
    baseline_alerts = 0
    adv_alerts = 0
    evasions = 0
    baseline_raw_detections = 0
    adv_raw_detections = 0
    raw_evasions = 0
    score_drop_sum = 0.0
    mitigation_calls = 0

    with open(out_jsonl, "w") as log_fh:
        for w in windows:
            window_stream = f"offdt:{w['attack_file']}:{w['window_index']}"
            base = infer_features(
                mitigator_url,
                w["features"],
                timeout=timeout,
                stream_key=f"{window_stream}:base",
            )
            total += 1
            base_is_raw = bool(base.get("raw_is_anomaly"))
            base_is_alert = bool(base.get("is_alert") or base.get("is_anomaly"))
            if base_is_alert:
                baseline_alerts += 1
            if base_is_raw:
                baseline_raw_detections += 1

            keys = list(w["features"].keys())

            probe_counter = {"n": 0}

            def score_fn(vec):
                probe_counter["n"] += 1
                feat = {k: float(v) for k, v in zip(keys, vec.tolist())}
                r = infer_features(
                    mitigator_url,
                    feat,
                    timeout=timeout,
                    stream_key=f"{window_stream}:probe:{probe_counter['n']}",
                )
                return float(r["anomaly_score"] - anomaly_threshold)

            if base_is_raw:
                adv = constrained_mifgsm(w["features"], score_fn, cfg)
                adv_inf = infer_features(
                    mitigator_url,
                    adv["adv_features"],
                    timeout=timeout,
                    stream_key=f"{window_stream}:adv",
                )
            else:
                adv = {
                    "adv_features": dict(w["features"]),
                    "delta": {k: 0.0 for k in keys},
                    "queries": 0,
                }
                adv_inf = infer_features(
                    mitigator_url,
                    adv["adv_features"],
                    timeout=timeout,
                    stream_key=f"{window_stream}:adv",
                )

            adv_is_alert = bool(adv_inf.get("is_alert") or adv_inf.get("is_anomaly"))
            adv_is_raw = bool(adv_inf.get("raw_is_anomaly"))
            if adv_is_alert:
                adv_alerts += 1
            if adv_is_raw:
                adv_raw_detections += 1
            if base_is_alert and not adv_is_alert:
                evasions += 1
            if base_is_raw and not adv_is_raw:
                raw_evasions += 1

            score_drop = float(base["anomaly_score"] - adv_inf["anomaly_score"])
            score_drop_sum += score_drop

            entry = {
                "ts": _iso_now(),
                "attack_file": w["attack_file"],
                "window_index": w["window_index"],
                "base_score": base["anomaly_score"],
                "adv_score": adv_inf["anomaly_score"],
                "base_margin_to_threshold": float(base["anomaly_score"] - anomaly_threshold),
                "adv_margin_to_threshold": float(adv_inf["anomaly_score"] - anomaly_threshold),
                "score_drop": score_drop,
                "base_is_alert": base_is_alert,
                "adv_is_alert": adv_is_alert,
                "base_is_raw": base_is_raw,
                "adv_is_raw": adv_is_raw,
                "evasion_success": bool(base_is_alert and not adv_is_alert),
                "raw_evasion_success": bool(base_is_raw and not adv_is_raw),
                "queries": adv["queries"],
                "delta_linf": max(abs(v) for v in adv["delta"].values()) if adv["delta"] else 0.0,
                "delta_l2": float(np.linalg.norm(np.array(list(adv["delta"].values()), dtype=float), ord=2)) if adv["delta"] else 0.0,
                "dry_run": bool(dry_run),
            }
            log_fh.write(json.dumps(entry) + "\n")

            # optional: propagate surviving alerts to mitigator to measure operational impact
            if adv_is_alert:
                payload = {
                    "stream_key": adv_inf.get("stream_key") or f"offensive-dt:{w['attack_file']}:{w['window_index']}",
                    "action": mitigate_action,
                    "target": {
                        "pcap": os.path.join(run_dir, w["attack_file"].replace(".csv", ".pcap")),
                        "window_index": w["window_index"],
                        "mode": "offensive_dt_adversarial",
                    },
                    "reason": "offensive-dt-adversarial-alert",
                    "dry_run": bool(dry_run),
                }
                try:
                    mr = requests.post(mitigator_url.rstrip("/") + "/mitigate", json=payload, timeout=timeout)
                    if mr.status_code == 200:
                        mitigation_calls += 1
                except Exception:
                    pass

    baseline_alert_rate = baseline_alerts / total if total else 0.0
    adv_alert_rate = adv_alerts / total if total else 0.0
    evasion_rate = evasions / baseline_alerts if baseline_alerts else 0.0
    est_unmitigated_increase = max(0, baseline_alerts - adv_alerts)
    baseline_raw_rate = baseline_raw_detections / total if total else 0.0
    adv_raw_rate = adv_raw_detections / total if total else 0.0
    raw_evasion_rate = raw_evasions / baseline_raw_detections if baseline_raw_detections else 0.0

    summary = {
        "ts": _iso_now(),
        "run_dir": run_dir,
        "mitigator_url": mitigator_url,
        "attack": {
            "type": "constrained_mifgsm_blackbox",
            "eps": cfg.eps,
            "alpha": cfg.alpha,
            "steps": cfg.steps,
            "momentum": cfg.momentum,
            "fd_eps": cfg.fd_eps,
            "rel_clip": cfg.rel_clip,
            "max_features": cfg.max_features,
            "objective": "minimize_margin_to_threshold",
            "target_threshold": anomaly_threshold,
            "target_hysteresis": anomaly_hysteresis,
        },
        "impact": {
            "windows_total": total,
            "baseline_alerts": baseline_alerts,
            "adversarial_alerts": adv_alerts,
            "baseline_alert_rate": baseline_alert_rate,
            "adversarial_alert_rate": adv_alert_rate,
            "evasion_count": evasions,
            "evasion_rate_given_alert": evasion_rate,
            "baseline_raw_detections": baseline_raw_detections,
            "adversarial_raw_detections": adv_raw_detections,
            "baseline_raw_detection_rate": baseline_raw_rate,
            "adversarial_raw_detection_rate": adv_raw_rate,
            "raw_evasion_count": raw_evasions,
            "raw_evasion_rate_given_raw_detection": raw_evasion_rate,
            "estimated_unmitigated_window_increase": est_unmitigated_increase,
            "mean_score_drop": (score_drop_sum / total) if total else 0.0,
            "mitigation_calls_from_adversarial_alerts": mitigation_calls,
        },
        "outputs": {
            "adversarial_log": out_jsonl,
            "impact_summary": out_summary,
        },
    }

    with open(out_summary, "w") as fh:
        json.dump(summary, fh, indent=2)

    # If baseline windows exist in run_dir, compute precision/F1 on combined set
    try:
        import pandas as pd
        all_csvs = [os.path.join(run_dir, p) for p in os.listdir(run_dir) if p.endswith('.csv')]
        df_list = []
        for fp in all_csvs:
            try:
                df = pd.read_csv(fp)
                # infer label if not present: attack files -> 1, others -> 0
                if 'label' not in df.columns:
                    label = 1 if 'attack' in os.path.basename(fp) else 0
                    df['label'] = label
                df_list.append(df)
            except Exception:
                continue
        if df_list:
            df_all = pd.concat(df_list, ignore_index=True)
            # use feature columns available in model artifacts if present
            try:
                cols = joblib.load(os.path.join('services', 'mitigator', 'feature_columns.joblib'))
            except Exception:
                cols = [c for c in df_all.columns if c not in ('start_ts', 'end_ts', 'label')]
            use = [c for c in cols if c in df_all.columns]
            X_all = df_all[use].fillna(0).values
            y_all = df_all['label'].astype(int).values
            # query mitigator for baseline scores
            probs_all = []
            for row in df_all[use].fillna(0).to_dict(orient='records'):
                try:
                    r = infer_features(mitigator_url, row, timeout=timeout)
                    probs_all.append(r['anomaly_score'])
                except Exception:
                    probs_all.append(0.0)
            probs_all = np.array(probs_all)
            preds_before = (probs_all >= anomaly_threshold).astype(int)
            from sklearn.metrics import precision_recall_fscore_support
            prec_b, rec_b, f1_b, _ = precision_recall_fscore_support(y_all, preds_before, average='binary', zero_division=0)
            # For after-attack, replace attack windows with adversarial scores where available
            # build mapping from attack_file+index -> adv_margin recorded in out_jsonl
            # parse out_jsonl
            try:
                adv_scores = {}
                with open(out_jsonl, 'r') as fh:
                    for line in fh:
                        e = json.loads(line)
                        key = f"{e.get('attack_file')}|{e.get('window_index')}"
                        adv_scores[key] = e.get('adv_score', e.get('adv_margin_to_threshold', None))
                probs_after = probs_all.copy()
                for i, row in df_all.iterrows():
                    fname = os.path.basename(row.get('attack_file', '')) if 'attack_file' in row.index else ''
                    if fname and 'window_index' in row.index:
                        key = f"{fname}|{int(row['window_index'])}"
                        if key in adv_scores and adv_scores[key] is not None:
                            probs_after[i] = adv_scores[key]
                preds_after = (probs_after >= anomaly_threshold).astype(int)
                prec_a, rec_a, f1_a, _ = precision_recall_fscore_support(y_all, preds_after, average='binary', zero_division=0)
                summary['impact']['combined_precision_before'] = float(prec_b)
                summary['impact']['combined_recall_before'] = float(rec_b)
                summary['impact']['combined_f1_before'] = float(f1_b)
                summary['impact']['combined_precision_after'] = float(prec_a)
                summary['impact']['combined_recall_after'] = float(rec_a)
                summary['impact']['combined_f1_after'] = float(f1_a)
            except Exception:
                pass
    except Exception:
        # best-effort: skip combined metrics if unavailable
        pass

    return summary


def main():
    p = argparse.ArgumentParser(description="Offensive-DT adversarial campaign against detector")
    p.add_argument("--run-dir", default="experiments/run_live_v2")
    p.add_argument("--mitigator", default="http://127.0.0.1:8082")
    p.add_argument("--max-windows", type=int, default=200)
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--eps", type=float, default=0.12)
    p.add_argument("--alpha", type=float, default=0.03)
    p.add_argument("--steps", type=int, default=6)
    p.add_argument("--momentum", type=float, default=0.9)
    p.add_argument("--fd-eps", type=float, default=0.02)
    p.add_argument("--rel-clip", type=float, default=0.2)
    p.add_argument("--max-features", type=int, default=12)
    p.add_argument("--dry-run", action="store_true", default=False,
                   help='If set, run in dry-run mode (no perturbations)')
    p.add_argument("--out-jsonl", default=None)
    p.add_argument("--out-summary", default=None)
    args = p.parse_args()

    cfg = AttackConfig(
        eps=args.eps,
        alpha=args.alpha,
        steps=args.steps,
        momentum=args.momentum,
        fd_eps=args.fd_eps,
        rel_clip=args.rel_clip,
        max_features=args.max_features,
    )
    summary = run_offensive_campaign(
        run_dir=args.run_dir,
        mitigator_url=args.mitigator,
        out_jsonl=args.out_jsonl,
        out_summary=args.out_summary,
        max_windows=args.max_windows,
        timeout=args.timeout,
        cfg=cfg,
        dry_run=args.dry_run,
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
