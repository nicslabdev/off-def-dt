#!/usr/bin/env python3
"""Lightweight inference service for IsolationForest detector.

Endpoints:
- GET /health
- POST /infer  (accepts features JSON -> returns anomaly score)
- POST /infer_from_pcap (accepts {pcap_path, window_index}) -> extracts windows and runs inference
"""
import os
import traceback
from typing import Dict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

import joblib
import numpy as np
import json
import subprocess
import uuid
import time
from datetime import datetime, timezone

from sklearn.ensemble import RandomForestClassifier

app = FastAPI()

MODEL_PATH = os.getenv('MITIGATOR_MODEL_PATH', 'services/mitigator/model.joblib')
SCALER_PATH = os.getenv('MITIGATOR_SCALER_PATH', 'services/mitigator/scaler.joblib')
FEATURES_PATH = os.getenv('MITIGATOR_FEATURES_PATH', 'services/mitigator/feature_columns.joblib')

# metadata (optional) - allow model folder to supply a tuned threshold
METADATA_PATH = os.getenv('MITIGATOR_METADATA_PATH', 'experiments/run_bigbaseline_v5/mitigator/model_metadata.json')
ANOMALY_THRESHOLD = float(os.getenv('ANOMALY_THRESHOLD', '0.0'))
MODEL_TYPE = os.getenv('MITIGATOR_MODEL_TYPE', 'auto').lower()  # auto|if|lof

# try to load metadata threshold if present
try:
    if os.path.exists(METADATA_PATH):
        import json
        with open(METADATA_PATH) as fh:
            md = json.load(fh)
            if 'threshold' in md:
                ANOMALY_THRESHOLD = float(md['threshold'])
except Exception:
    pass


class InferRequest(BaseModel):
    features: Dict[str, float]


class PcapRequest(BaseModel):
    pcap_path: str
    window_index: int = 0
    window_size: float = 10.0


class MitigateRequest(BaseModel):
    stream_key: str
    action: str  # tag|notify|stop_service|simulate
    target: dict | None = None
    duration_seconds: int | None = 60
    reason: str | None = None
    dry_run: bool = True


def load_artifacts():
    model = None
    scaler = None
    cols = None
    mtimes = {}
    try:
        model = joblib.load(MODEL_PATH)
        if not isinstance(model, RandomForestClassifier):
            raise ValueError("Loaded model is not a RandomForestClassifier")
        try:
            mtimes['model'] = os.path.getmtime(MODEL_PATH)
        except Exception:
            mtimes['model'] = None
    except Exception:
        print('model not found at', MODEL_PATH)
    try:
        scaler = joblib.load(SCALER_PATH)
        try:
            mtimes['scaler'] = os.path.getmtime(SCALER_PATH)
        except Exception:
            mtimes['scaler'] = None
    except Exception:
        print('scaler not found at', SCALER_PATH)
    try:
        cols = joblib.load(FEATURES_PATH)
        try:
            mtimes['cols'] = os.path.getmtime(FEATURES_PATH)
        except Exception:
            mtimes['cols'] = None
    except Exception:
        print('feature columns not found at', FEATURES_PATH)
    return model, scaler, cols, mtimes


def load_defensive_artifacts():
    """Load an optional defensive (CatBoost) model and its artifacts.

    Tries joblib first, then CatBoost model loader. Returns (model, scaler, cols, mtimes)
    where scaler/cols may be None if not present.
    """
    try:
        from catboost import CatBoostClassifier
    except Exception:
        CatBoostClassifier = None

    dmodel = None
    dscaler = None
    dcols = None
    dmtimes = {}
    # allow defensive model to supply a tuned threshold via model_metadata.json
    global DEFENSIVE_THRESHOLD
    try:
        DEFENSIVE_THRESHOLD = None
    except Exception:
        pass
    DEF_PATH = os.getenv('DEFENSIVE_MODEL_PATH', 'services/defensive_dt/model.joblib')
    DEF_SCALER = os.getenv('DEFENSIVE_SCALER_PATH', 'services/defensive_dt/scaler.joblib')
    DEF_COLS = os.getenv('DEFENSIVE_FEATURES_PATH', 'services/defensive_dt/feature_columns.joblib')
    # try joblib first
    try:
        if os.path.exists(DEF_PATH):
            dmodel = joblib.load(DEF_PATH)
            try:
                dmtimes['model'] = os.path.getmtime(DEF_PATH)
            except Exception:
                dmtimes['model'] = None
    except Exception:
        dmodel = None

    # try CatBoost native loader if joblib failed and CatBoost is available
    if dmodel is None and CatBoostClassifier is not None:
        try:
            # assume CBM format
            if os.path.exists(DEF_PATH):
                cb = CatBoostClassifier()
                cb.load_model(DEF_PATH)
                dmodel = cb
                try:
                    dmtimes['model'] = os.path.getmtime(DEF_PATH)
                except Exception:
                    dmtimes['model'] = None
        except Exception:
            dmodel = None

    try:
        if os.path.exists(DEF_SCALER):
            dscaler = joblib.load(DEF_SCALER)
            try:
                dmtimes['scaler'] = os.path.getmtime(DEF_SCALER)
            except Exception:
                dmtimes['scaler'] = None
    except Exception:
        dscaler = None

    try:
        if os.path.exists(DEF_COLS):
            dcols = joblib.load(DEF_COLS)
            try:
                dmtimes['cols'] = os.path.getmtime(DEF_COLS)
            except Exception:
                dmtimes['cols'] = None
    except Exception:
        dcols = None

    # try to read a model_metadata.json alongside the defensive artifacts
    try:
        meta_path = os.path.join(os.path.dirname(DEF_PATH), 'model_metadata.json')
        if os.path.exists(meta_path):
            with open(meta_path) as fh:
                md = json.load(fh)
                if 'threshold' in md:
                    try:
                        DEFENSIVE_THRESHOLD = float(md['threshold'])
                    except Exception:
                        DEFENSIVE_THRESHOLD = None
    except Exception:
        pass

    return dmodel, dscaler, dcols, dmtimes


MODEL, SCALER, FEATURE_COLS, ARTIFACT_MTIMES = load_artifacts()
# defensive model (optional)
DEF_MODEL, DEF_SCALER, DEF_FEATURE_COLS, DEF_ARTIFACT_MTIMES = load_defensive_artifacts()
# hysteresis state: count consecutive anomalous inferences per stream/key.
# We key by a stream identifier derived from features (client_id, src, src_ip, topic),
# falling back to a global key when none present.
CONSECUTIVE_ANOMALY_COUNT = {}  # Dict[str, int]
ANOMALY_HYSTERESIS = int(os.getenv('ANOMALY_HYSTERESIS', '1'))
MITIGATION_LOG = os.getenv('MITIGATION_LOG', 'experiments/run_live_v1/mitigation_log.jsonl')


def _get_mtimes():
    """Return current mtimes for model/scaler/cols files (or None)."""
    res = {}
    for k, p in (('model', MODEL_PATH), ('scaler', SCALER_PATH), ('cols', FEATURES_PATH)):
        try:
            res[k] = os.path.getmtime(p)
        except Exception:
            res[k] = None
    return res


def maybe_reload_artifacts():
    """Reload artifacts if underlying files have changed on disk.

    This is a cheap check run before inference so the running service will
    pick up updated model/scaler/feature files without a restart.
    """
    global MODEL, SCALER, FEATURE_COLS, ARTIFACT_MTIMES
    try:
        current = _get_mtimes()
        if ARTIFACT_MTIMES is None:
            MODEL, SCALER, FEATURE_COLS, ARTIFACT_MTIMES = load_artifacts()
            return
        changed = False
        for k in ('model', 'scaler', 'cols'):
            if current.get(k) != ARTIFACT_MTIMES.get(k):
                changed = True
                break
        if changed:
            print('artifacts changed on disk; reloading')
            MODEL, SCALER, FEATURE_COLS, ARTIFACT_MTIMES = load_artifacts()
        # also check defensive artifacts
        try:
            dcurrent = {}
            for k, p in (('model', os.getenv('DEFENSIVE_MODEL_PATH', 'services/defensive_dt/model.joblib')), ('scaler', os.getenv('DEFENSIVE_SCALER_PATH', 'services/defensive_dt/scaler.joblib')), ('cols', os.getenv('DEFENSIVE_FEATURES_PATH', 'services/defensive_dt/feature_columns.joblib'))):
                try:
                    dcurrent[k] = os.path.getmtime(p)
                except Exception:
                    dcurrent[k] = None
            dchanged = False
            if DEF_ARTIFACT_MTIMES is None:
                dchanged = True
            else:
                for k in ('model', 'scaler', 'cols'):
                    if dcurrent.get(k) != DEF_ARTIFACT_MTIMES.get(k):
                        dchanged = True
                        break
            if dchanged:
                print('defensive artifacts changed on disk; reloading')
                DEF_MODEL, DEF_SCALER, DEF_FEATURE_COLS, DEF_ARTIFACT_MTIMES = load_defensive_artifacts()
        except Exception:
            pass
    except Exception:
        # loading is best-effort; don't crash the service on reload issues
        pass


def _write_mitigation_log(entry: dict):
    """Append a JSON line to mitigation log (best-effort)."""
    try:
        d = dict(entry)
        # ensure timestamp
        if 'ts' not in d:
            d['ts'] = datetime.now(timezone.utc).isoformat()
        os.makedirs(os.path.dirname(MITIGATION_LOG), exist_ok=True)
        with open(MITIGATION_LOG, 'a') as fh:
            fh.write(json.dumps(d) + '\n')
    except Exception:
        # never crash service on logging failures
        traceback.print_exc()


def _demo_stop_attacker(target: dict | None, dry_run: bool = True):
    """Demo adapter: attempt to stop an attacker container/service.

    Strategy (best-effort): try common docker-compose files under repo, else try
    `docker compose stop attacker`. On dry_run just return the command that
    would be executed.
    """
    candidates = [
        'delete/docker-compose.yml',
        'delete/docker-compose.emulation.yml',
        'docker-compose.isolated.yml',
        'docker-compose.yml',
    ]
    cmd = None
    for c in candidates:
        if os.path.exists(c):
            cmd = ['docker', 'compose', '-f', c, 'stop', 'attacker']
            break
    if cmd is None:
        # fallback to plain compose
        cmd = ['docker', 'compose', 'stop', 'attacker']

    if dry_run:
        return {'dry_run': True, 'cmd': cmd}

    try:
        # run the stop command and capture output
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {
            'dry_run': False,
            'returncode': proc.returncode,
            'stdout': proc.stdout,
            'stderr': proc.stderr,
        }
    except Exception as e:
        return {'error': str(e)}


@app.get('/debug')
def debug_info():
    """Return debugging info about loaded artifacts and a sample score.

    This endpoint is temporary and intended to help diagnose mismatches
    between the on-disk artifacts and the running in-memory model.
    """
    maybe_reload_artifacts()
    info = {
        'model_loaded': MODEL is not None,
        'scaler_loaded': SCALER is not None,
        'feature_cols_loaded': FEATURE_COLS is not None,
        'artifact_mtimes': ARTIFACT_MTIMES,
        'anomaly_threshold': ANOMALY_THRESHOLD,
        'model_type': None,
        'anomaly_hysteresis': ANOMALY_HYSTERESIS,
        'consecutive_anomaly_count_sample': {k: v for k, v in list(CONSECUTIVE_ANOMALY_COUNT.items())[:10]},
    }
    try:
        if MODEL is not None:
            info['model_type'] = type(MODEL).__name__
    except Exception:
        info['model_type'] = 'unknown'

    # attempt to compute a sample score on a zero-vector of the right length
    try:
        if MODEL is not None and SCALER is not None and FEATURE_COLS is not None:
            vec = np.zeros((1, len(FEATURE_COLS)))
            Xs = SCALER.transform(vec)
            if hasattr(MODEL, 'decision_function'):
                s = float(-MODEL.decision_function(Xs)[0])
            elif hasattr(MODEL, 'score_samples'):
                s = float(-MODEL.score_samples(Xs)[0])
            else:
                s = None
            # ensure JSON-serializable native types
            info['sample_zero_score'] = float(s) if s is not None else None
    except Exception as e:
        info['sample_zero_score_error'] = str(e)

    return info


@app.get('/health')
def health():
    return {'model_loaded': MODEL is not None, 'scaler_loaded': SCALER is not None}


@app.get('/config')
def config():
    """Expose simple runtime config values for debugging (hysteresis, threshold)."""
    return {'anomaly_threshold': ANOMALY_THRESHOLD, 'anomaly_hysteresis': ANOMALY_HYSTERESIS}


@app.post('/reload')
def reload_artifacts():
    """Force reload model/scaler/feature columns from disk.

    Returns current loaded status.
    """
    global MODEL, SCALER, FEATURE_COLS, ARTIFACT_MTIMES, ANOMALY_THRESHOLD, ANOMALY_HYSTERESIS
    MODEL, SCALER, FEATURE_COLS, ARTIFACT_MTIMES = load_artifacts()

    # also reload defensive artifacts when explicitly reloading
    try:
        global DEF_MODEL, DEF_SCALER, DEF_FEATURE_COLS, DEF_ARTIFACT_MTIMES
        DEF_MODEL, DEF_SCALER, DEF_FEATURE_COLS, DEF_ARTIFACT_MTIMES = load_defensive_artifacts()
    except Exception:
        pass

    # prefer explicit METADATA_PATH (env), but also check alongside the model path
    candidates = []
    if METADATA_PATH:
        candidates.append(METADATA_PATH)
    try:
        model_dir = os.path.dirname(MODEL_PATH) if MODEL_PATH else None
        if model_dir:
            candidates.append(os.path.join(model_dir, 'model_metadata.json'))
    except Exception:
        pass
    # add a known experiments fallback
    candidates.append('experiments/run_live_v1/mitigator/model_metadata.json')

    for mp in candidates:
        if not mp:
            continue
        if not os.path.exists(mp):
            continue
        try:
            with open(mp) as fh:
                md = json.load(fh)
                if 'threshold' in md:
                    try:
                        ANOMALY_THRESHOLD = float(md['threshold'])
                    except Exception:
                        pass
                # allow metadata to set an in-service hysteresis (min consecutive windows)
                if 'min_consecutive' in md:
                    try:
                        ANOMALY_HYSTERESIS = int(md['min_consecutive'])
                    except Exception:
                        pass
                if 'anomaly_hysteresis' in md:
                    try:
                        ANOMALY_HYSTERESIS = int(md['anomaly_hysteresis'])
                    except Exception:
                        pass
        except Exception:
            # ignore parse errors on this candidate and continue
            continue

    return {'model_loaded': MODEL is not None, 'scaler_loaded': SCALER is not None, 'anomaly_hysteresis': ANOMALY_HYSTERESIS}


@app.post('/infer')
def infer(req: InferRequest):
    # auto-reload if underlying artifact files changed
    maybe_reload_artifacts()

    if MODEL is None or SCALER is None or FEATURE_COLS is None:
        raise HTTPException(status_code=500, detail='model artifacts missing')

    # Build feature vector
    x = [req.features.get(c, 0.0) for c in FEATURE_COLS]
    X = np.array(x).reshape(1, -1)
    Xs = SCALER.transform(X)

    try:
        # Predict using RandomForestClassifier
        prediction = MODEL.predict(Xs)[0]
        # cast to native Python types to avoid FastAPI encoder issues with numpy types
        anomaly_score = MODEL.predict_proba(Xs)[0][1]
        raw_is_anomaly = (prediction == 1)

        # default final label is the raw prediction
        final_is_anomaly = bool(raw_is_anomaly)
        defensive_detected = False
        defensive_score = None

        # apply defensive model if available: detect adversarial samples and apply countermeasure
        try:
            if DEF_MODEL is not None:
                # build defensive feature vector - prefer DEF_FEATURE_COLS, fall back to FEATURE_COLS
                use_cols = DEF_FEATURE_COLS if DEF_FEATURE_COLS is not None else FEATURE_COLS
                if use_cols is not None:
                    x_def = [req.features.get(c, 0.0) for c in use_cols]
                    Xdef = np.array(x_def).reshape(1, -1)
                    if DEF_SCALER is not None:
                        Xdef_s = DEF_SCALER.transform(Xdef)
                    else:
                        Xdef_s = Xdef

                    # CatBoostClassifier may not have predict_proba attribute depending on loader
                    try:
                        dprob = None
                        if hasattr(DEF_MODEL, 'predict_proba'):
                            dprob = DEF_MODEL.predict_proba(Xdef_s)[0][1]
                        defensive_score = float(dprob) if dprob is not None else None
                        dpred = None
                        # Prefer thresholding on defensive_score when available and configured
                        try:
                            if defensive_score is not None and globals().get('DEFENSIVE_THRESHOLD') is not None:
                                dpred = int(defensive_score >= float(globals().get('DEFENSIVE_THRESHOLD')))
                            elif hasattr(DEF_MODEL, 'predict'):
                                dpred = int(DEF_MODEL.predict(Xdef_s)[0])
                        except Exception:
                            dpred = None
                        # interpret dpred==1 as adversarial sample
                        if dpred == 1:
                            defensive_detected = True
                            # countermeasure: invert the detector's raw label so that
                            # every detected adversarial sample flips the prediction
                            final_is_anomaly = not raw_is_anomaly
                    except Exception:
                        # defensive prediction failed; ignore
                        defensive_detected = False
        except Exception:
            defensive_detected = False

        return {
            'anomaly_score': float(anomaly_score),
            'is_anomaly': bool(final_is_anomaly),
            'raw_is_anomaly': bool(raw_is_anomaly),
            'defensive_detected': bool(defensive_detected),
            'defensive_score': defensive_score,
        }
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.post('/infer_from_pcap')
def infer_from_pcap(req: PcapRequest):
    # lazy import to avoid hard dependency until endpoint used
    try:
        from tools.pcap_to_features import extract_windows
    except Exception as e:
        raise HTTPException(status_code=500, detail='pcap extractor not available: ' + str(e))
    if not os.path.exists(req.pcap_path):
        raise HTTPException(status_code=400, detail='pcap not found')
    windows = extract_windows(req.pcap_path, window_size=req.window_size)
    if not windows:
        raise HTTPException(status_code=400, detail='no windows extracted')
    i = req.window_index if req.window_index < len(windows) else 0
    features = windows[i]
    # remove start_ts/end_ts
    features = {k: v for k, v in features.items() if k not in ('start_ts', 'end_ts')}
    return infer(InferRequest(features=features))


@app.post('/mitigate')
def mitigate(req: MitigateRequest):
    """Perform a mitigation action for a stream.

    This endpoint is intentionally conservative: by default requests are
    dry-run and the service will only simulate or log the mitigation action.
    The `action` supports simple demo adapters:
      - tag: attach a tag/label (simulated)
      - notify: emit a notification (simulated)
      - stop_service: demo adapter that attempts to stop an `attacker` service
      - simulate: no-op simulation

    All mitigation attempts are appended to a JSONL audit log for tracing.
    """
    # normalize action
    a = (req.action or '').lower()
    if a not in ('tag', 'notify', 'stop_service', 'simulate'):
        raise HTTPException(status_code=400, detail='unsupported action')

    event = {
        'id': str(uuid.uuid4()),
        'stream_key': req.stream_key,
        'action': a,
        'target': req.target,
        'duration_seconds': req.duration_seconds,
        'reason': req.reason,
        'dry_run': bool(req.dry_run),
        'ts': datetime.now(timezone.utc).isoformat(),
    }

    result = None
    try:
        if a == 'stop_service':
            result = _demo_stop_attacker(req.target, dry_run=req.dry_run)
        elif a == 'tag':
            # tagging is a simulated action in this PoC
            result = {'simulated': True, 'message': f"tagged {req.stream_key} "}
        elif a == 'notify':
            result = {'simulated': True, 'message': f"notified ops for {req.stream_key} "}
        else:
            result = {'simulated': True, 'message': 'simulate no-op'}
    except Exception as e:
        result = {'error': str(e)}

    event['result'] = result
    # best-effort logging of mitigation event
    _write_mitigation_log(event)

    return {'event': event}


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=int(os.getenv('MITIGATOR_PORT', '8080')))
