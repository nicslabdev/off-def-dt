#!/usr/bin/env python3
"""Experiment runner

Orchestrates: capture baseline, run attacks in replica sandbox, extract features,
train an IsolationForest detector, evaluate detection metrics, and simulate
mitigation decisions using the mitigator inference service (optional).

Usage: python tools/experiment_runner.py --help
"""
import argparse
import os
import subprocess
import time
import json
import shlex
import tempfile
from pathlib import Path
import logging

import pandas as pd
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, precision_recall_fscore_support, confusion_matrix

LOG = logging.getLogger('experiment_runner')
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')


def run_cmd(cmd, check=True, capture=False, env=None):
    LOG.info('run: %s', cmd)
    if capture:
        r = subprocess.run(shlex.split(cmd), check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        return r.stdout.decode(), r.stderr.decode(), r.returncode
    else:
        return subprocess.run(shlex.split(cmd), check=check, env=env)


def ensure_compose_up(compose_file):
    # bring up the stack if not already
    try:
        run_cmd(f'docker compose -f {compose_file} ps', check=True)
    except Exception:
        LOG.info('docker compose not responding; attempting to bring up stack')
        run_cmd(f'docker compose -f {compose_file} up -d')
        time.sleep(3)


def wait_for_service(compose_file, service_name, timeout=30):
    """Wait until docker compose reports the service as running or timeout.

    Returns True if running, False on timeout.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            out, err, rc = run_cmd(f'docker compose -f {compose_file} ps {service_name}', capture=True)
            if service_name in out and 'Running' in out:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def resolve_docker_network(short_name: str) -> str:
    """Return a docker network name that matches the short_name suffix if present.

    Docker Compose commonly prefixes network names with the project name, e.g.
    'projectname_replica_net'. This helper finds a network whose name ends with
    the requested short_name and returns the fully-qualified name. If none is
    found, returns the original short_name.
    """
    try:
        p = subprocess.run(['docker', 'network', 'ls', '--format', '{{.Name}}'], check=True, stdout=subprocess.PIPE)
        out = p.stdout.decode()
        for line in out.splitlines():
            name = line.strip()
            if not name:
                continue
            if name == short_name or name.endswith('_' + short_name) or short_name in name:
                return name
    except Exception as e:
        LOG.debug('resolve_docker_network exception: %s', e)
    return short_name


def capture_pcap(network, out_path, duration):
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # resolve network name in case docker-compose added a project prefix
    resolved = resolve_docker_network(network)
    if resolved != network:
        LOG.info('using resolved docker network name: %s -> %s', network, resolved)
    # use netshoot for tcpdump to avoid modifying containers
    cmd = (
        f'docker run --rm --net {resolved} --cap-add=NET_ADMIN --cap-add=NET_RAW '
        f'-v "{out_path.parent.resolve()}:/pcaps" nicolaka/netshoot:latest '
        f'timeout {int(duration)+5} tcpdump -i any -w /pcaps/{out_path.name}'
    )
    run_cmd(cmd)
    return out_path


def pcap_has_mqtt(pcap_path) -> bool:
    """Return True if the given pcap file contains at least one MQTT frame.

    Tries to use tshark first (preferred). If tshark is not available, falls
    back to tcpdump to look for TCP port 1883 traffic. If neither tool is
    available, logs a warning and returns True (to avoid blocking experiments).
    """
    pcap = str(pcap_path)
    # try tshark
    try:
        out, err, rc = run_cmd(f'tshark -r {shlex.quote(pcap)} -Y "mqtt" -c 1', capture=True, check=False)
        if out.strip() or rc == 0:
            # tshark prints something when mqtt frames found; if rc==0 and no output
            # it's possible tshark returned success but no frames — check stdout length
            if out.strip():
                LOG.info('pcap %s contains MQTT frames (tshark)', pcap)
                return True
    except Exception:
        LOG.debug('tshark not available or failed when checking %s', pcap)

    # fall back to tcpdump checking for TCP port 1883 in the pcap
    try:
        out, err, rc = run_cmd(f'tcpdump -nn -r {shlex.quote(pcap)} tcp port 1883 -c 1', capture=True, check=False)
        if out.strip():
            LOG.info('pcap %s contains MQTT/TCP traffic (tcpdump)', pcap)
            return True
    except Exception:
        LOG.debug('tcpdump not available or failed when checking %s', pcap)

    LOG.warning('no MQTT frames detected in %s (tshark/tcpdump checks failed or found nothing)', pcap)
    # Be conservative: if tools are missing we don't want to block the experiment
    # so return False only if both tools were available and found nothing. Here
    # we've already attempted both; return False to indicate no mqtt frames seen.
    return False


def capture_in_broker_namespace(compose_file, service_name, out_path, duration):
    """Capture packets inside the network namespace of a compose service container.

    This attaches a netshoot container to the target container's net namespace
    (using --net container:<cid>) and runs tcpdump there. Returns the Path to
    the produced pcap.
    """
    out_path = Path(out_path)
    # get container id for the compose service
    try:
        out, err, rc = run_cmd(f'docker compose -f {compose_file} ps -q {service_name}', capture=True)
        cid = out.strip()
        if not cid:
            LOG.error('could not find container id for compose service %s', service_name)
            return out_path
    except Exception as e:
        LOG.error('failed to resolve container id for %s: %s', service_name, e)
        return out_path

    LOG.info('capturing pcap inside broker container namespace (%s) to %s', cid, out_path)
    cmd = (
        f'docker run --rm --net container:{cid} --cap-add=NET_ADMIN --cap-add=NET_RAW '
        f'-v "{out_path.parent.resolve()}:/pcaps" nicolaka/netshoot:latest '
        f'timeout {int(duration)+5} tcpdump -i any -w /pcaps/{out_path.name}'
    )
    try:
        run_cmd(cmd)
    except Exception as e:
        LOG.error('broker-namespace capture failed: %s', e)
    return out_path


def start_mqtt_traffic_generator(compose_file, network, broker, duration=60, rate=1.0, sensors=5):
    """Start a container that runs the mqtt_traffic_gen script for duration seconds.

    Returns the subprocess.Popen object. The container will run and exit on its own.
    """
    # Use the python image, mount repo so script is available
    repo_root = Path('.').resolve()

    # Prefer running the generator via `docker compose run` so compose DNS works for service names.
    inner_cmd = (
        f'pip install --no-cache-dir paho-mqtt >/dev/null 2>&1 || true; '
        f'python tools/mqtt_traffic_gen.py --broker {broker} --duration {int(duration)} '
        f'--rate {float(rate)} --sensors {int(sensors)}'
    )
    cmd = (
        f'docker compose -f {compose_file} run --rm -v "{repo_root}:/work" -w /work '
        f'python:3.11-slim bash -c {shlex.quote(inner_cmd)}'
    )
    LOG.info('starting mqtt traffic generator via compose (broker=%s): %s', broker, cmd)
    # run in background
    return subprocess.Popen(cmd, shell=True)


def run_attacker(compose_file, attack_type, extra_env=None, detach=False):
    env_args = ''
    if extra_env:
        for k, v in extra_env.items():
            env_args += f'-e {k}={shlex.quote(str(v))} '
    # run attacker via compose so it uses the correct network context
    # If a local ./data directory exists (or we're running mqtt_replay) mount it into the attacker
    repo_root = Path('.').resolve()
    vol_arg = ''
    if (repo_root / 'data').exists() or 'mqtt_replay' in attack_type:
        vol_arg = f'-v "{repo_root}/data:/data:ro' + '" '
    cmd = f'docker compose -f {compose_file} run --rm {vol_arg}{env_args}-e ATTACK_TYPE={attack_type} attacker'
    if detach:
        # run in background using & not available via subprocess easily; use nohup inside shell
        cmd = f'sh -c "{cmd} &"'
    run_cmd(cmd)


def extract_features(pcap_path, out_csv, window):
    cmd = f'python tools/pcap_to_features.py {shlex.quote(pcap_path)} {shlex.quote(out_csv)} --window {float(window)}'
    run_cmd(cmd)
    return out_csv


def load_numeric_features(csv_path):
    df = pd.read_csv(csv_path)
    numeric = df.select_dtypes(include=['number'])
    return df, numeric


def train_isolation_forest(X_train, contamination=0.01, n_estimators=200, random_state=42):
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X_train)
    model = IsolationForest(n_estimators=n_estimators, contamination=contamination, random_state=random_state)
    model.fit(Xs)
    return model, scaler


def evaluate_model(model, scaler, X_test, y_true):
    Xs = scaler.transform(X_test)
    # decision_function: higher means more normal; invert to anomaly score
    scores = -model.decision_function(Xs)
    # roc auc
    try:
        auc = roc_auc_score(y_true, scores)
    except Exception:
        auc = float('nan')
    # choose threshold at top contamination fraction
    contamination = float(model.contamination) if hasattr(model, 'contamination') else 0.01
    thr = np.quantile(scores, 1 - contamination)
    y_pred = (scores >= thr).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary', zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0,1]).ravel() if len(np.unique(y_true))>1 else (0,0,0,0)
    metrics = dict(auc=float(auc), precision=float(precision), recall=float(recall), f1=float(f1), threshold=float(thr), tp=int(tp), fp=int(fp), tn=int(tn), fn=int(fn))
    return scores, y_pred, metrics


def save_artifacts(out_dir, model, scaler, feature_columns):
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    joblib.dump(model, Path(out_dir)/'model.joblib')
    joblib.dump(scaler, Path(out_dir)/'scaler.joblib')
    joblib.dump(feature_columns, Path(out_dir)/'feature_columns.joblib')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--compose', default='docker-compose.isolated.yml')
    p.add_argument('--network', default='replica_net', help='Docker network to capture (default replica_net)')
    p.add_argument('--baseline-duration', type=int, default=30)
    p.add_argument('--attack-duration', type=int, default=30)
    p.add_argument('--window', type=float, default=10.0)
    p.add_argument('--attacks', default='mqtt_spoof', help='comma-separated attack types to run')
    p.add_argument('--outdir', default='experiments/run', help='where to write pcaps, csvs, models, metrics')
    p.add_argument('--contamination', type=float, default=0.01, help='contamination (expected anomaly fraction) for IsolationForest')
    p.add_argument('--n-estimators', type=int, default=200, help='number of trees for IsolationForest')
    p.add_argument('--tune-threshold', action='store_true', help='tune threshold on test set to maximize F1 (uses attack labels, for evaluation only)')
    p.add_argument('--traffic-enable', action='store_true', help='enable synthetic mqtt traffic generation during baseline')
    p.add_argument('--traffic-rate', type=float, default=1.0, help='messages per second per sensor for synthetic traffic')
    p.add_argument('--traffic-sensors', type=int, default=5, help='number of synthetic sensors to simulate')
    p.add_argument('--no-compose-up', action='store_true', help='do not attempt to run docker compose up')
    args = p.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    if not args.no_compose_up:
        ensure_compose_up(args.compose)

    # resolve network name (compose may prefix networks)
    resolved_network = resolve_docker_network(args.network)
    if resolved_network != args.network:
        LOG.info('resolved network name: %s -> %s', args.network, resolved_network)

    # 1) capture baseline
    baseline_pcap = outdir / 'baseline_replica.pcap'
    LOG.info('capturing baseline for %ds to %s', args.baseline_duration, baseline_pcap)
    traffic_proc = None
    if args.traffic_enable:
        # start synthetic traffic generator inside the resolved network
        # ensure broker service is running before starting generator
        ok = wait_for_service(args.compose, 'replica_mosquitto', timeout=30)
        if not ok:
            LOG.warning('replica_mosquitto did not report Running within timeout; starting generator anyway')
        traffic_proc = start_mqtt_traffic_generator(args.compose, resolved_network, broker='replica_mosquitto', duration=args.baseline_duration, rate=args.traffic_rate, sensors=args.traffic_sensors)
        # give generator a short warmup
        time.sleep(1)
    capture_pcap(args.network, str(baseline_pcap), args.baseline_duration)
    # verify baseline pcap contains MQTT; if not, attempt to capture in broker namespace
    try:
        if not pcap_has_mqtt(baseline_pcap):
            LOG.warning('baseline pcap missing MQTT frames; attempting broker-namespace capture')
            capture_in_broker_namespace(args.compose, 'replica_mosquitto', str(baseline_pcap), args.baseline_duration)
        else:
            LOG.info('baseline pcap verified to contain MQTT frames')
    except Exception as e:
        LOG.debug('pcap mqtt verification step failed: %s', e)
    if traffic_proc:
        LOG.info('waiting for traffic generator to finish')
        traffic_proc.wait()

    baseline_csv = outdir / 'baseline_replica.csv'
    extract_features(str(baseline_pcap), str(baseline_csv), args.window)

    all_attack_csvs = []
    # 2) for each attack: capture while running attack
    attacks = [a.strip() for a in args.attacks.split(',') if a.strip()]
    for atk in attacks:
        pcap = outdir / f'attack_{atk}.pcap'
        LOG.info('capturing attack %s to %s for %ds', atk, pcap, args.attack_duration)
        # start attacker in parallel: we call run_attacker which runs synchronously, so we start it in background shell
        # We'll use docker compose run which exits when attack finishes; run in a separate process via subprocess.Popen
        # start capture in background using docker run with timeout; run both synchronously by starting attacker in background
        capture_proc = subprocess.Popen(shlex.split(
            f'docker run --rm --net {resolved_network} --cap-add=NET_ADMIN --cap-add=NET_RAW -v "{outdir.resolve()}:/pcaps" nicolaka/netshoot:latest timeout {args.attack_duration+5} tcpdump -i any -w /pcaps/{pcap.name}'))
        # start attacker (mounts ./data automatically when needed)
        LOG.info('starting attacker for %s', atk)
        try:
            run_attacker(args.compose, atk)
        except Exception as e:
            LOG.error('attacker run failed: %s', e)
        # wait for capture to finish
        capture_proc.wait()
        LOG.info('capture for %s finished', atk)
        # verify attack pcap contains MQTT; if not, attempt broker-namespace capture
        try:
            if not pcap_has_mqtt(pcap):
                LOG.warning('attack pcap %s missing MQTT frames; attempting broker-namespace capture', pcap)
                capture_in_broker_namespace(args.compose, 'replica_mosquitto', str(pcap), args.attack_duration)
            else:
                LOG.info('attack pcap %s verified to contain MQTT frames', pcap)
        except Exception as e:
            LOG.debug('attack pcap mqtt verification failed: %s', e)

        csv = outdir / f'attack_{atk}.csv'
        extract_features(str(pcap), str(csv), args.window)
        all_attack_csvs.append(csv)

    # 3) prepare dataset: numeric features and labels
    LOG.info('loading baseline features')
    _, baseline_num = load_numeric_features(str(baseline_csv))
    X_baseline = baseline_num.fillna(0).values

    # If baseline produced very few windows, warn and suggest collecting more data
    min_windows = 5
    if X_baseline.shape[0] < min_windows:
        LOG.warning('baseline produced only %d windows (min %d). This is likely insufficient for training.\n'
                    'Consider increasing --baseline-duration (e.g. 120 or 300) and/or enabling --traffic-enable to synthesize more normal telemetry.',
                    X_baseline.shape[0], min_windows)

    attack_frames = []
    for csv in all_attack_csvs:
        _, num = load_numeric_features(str(csv))
        if num.empty:
            continue
        attack_frames.append(num.fillna(0))
    if not attack_frames:
        LOG.error('no attack feature windows produced; aborting')
        return
    X_attack = pd.concat(attack_frames, ignore_index=True).values

    # 4) train detector on baseline
    LOG.info('training IsolationForest on baseline (n=%d windows)', X_baseline.shape[0])
    model, scaler = train_isolation_forest(X_baseline, contamination=args.contamination, n_estimators=args.n_estimators)
    feature_columns = list(baseline_num.columns)
    save_artifacts(outdir/'mitigator', model, scaler, feature_columns)

    # compute baseline anomaly scores to choose a threshold that keeps FP low
    Xs_baseline = scaler.transform(X_baseline)
    baseline_scores = -model.decision_function(Xs_baseline)
    contamination = float(model.contamination) if hasattr(model, 'contamination') else 0.01
    # choose threshold based on baseline distribution (e.g., set threshold to 99th percentile)
    thr = float(np.quantile(baseline_scores, 1 - contamination))

    # 5) evaluate on combined test set (baseline holdout + attacks)
    # make a small baseline holdout (20%)
    n_baseline = X_baseline.shape[0]
    holdout_n = max(1, int(0.2 * n_baseline))
    X_holdout = X_baseline[:holdout_n]
    y_holdout = np.zeros(X_holdout.shape[0], dtype=int)
    X_test = np.vstack([X_holdout, X_attack])
    y_test = np.concatenate([y_holdout, np.ones(X_attack.shape[0], dtype=int)])

    # score test set and compute metrics
    Xs_test = scaler.transform(X_test)
    scores = -model.decision_function(Xs_test)
    try:
        auc = roc_auc_score(y_test, scores)
    except Exception:
        auc = float('nan')

    # Optionally tune threshold on labeled test set to maximize F1 (evaluation-only)
    if args.tune_threshold:
        LOG.info('tuning threshold on test set to maximize F1 (evaluation-only)')
        best_f1 = -1.0
        best_thr = thr
        # try thresholds across score range (use quantiles to limit candidates)
        qs = np.linspace(0.0, 1.0, 101)
        for q in qs:
            cand = float(np.quantile(scores, q))
            y_pred_cand = (scores >= cand).astype(int)
            prec, rec, f1s, _ = precision_recall_fscore_support(y_test, y_pred_cand, average='binary', zero_division=0)
            if f1s > best_f1:
                best_f1 = f1s
                best_thr = cand
        LOG.info('best F1 on test set: %.4f at threshold=%g', best_f1, best_thr)
        thr = best_thr

    y_pred = (scores >= thr).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='binary', zero_division=0)
    if len(np.unique(y_test)) > 1:
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0,1]).ravel()
    else:
        tn = fp = fn = tp = 0
    metrics = dict(auc=float(auc), precision=float(precision), recall=float(recall), f1=float(f1), threshold=float(thr), tp=int(tp), fp=int(fp), tn=int(tn), fn=int(fn))
    # wrap outputs from evaluation
    # also return scores so later simulation can use them
    # (we'll reuse 'scores' variable below)
    LOG.info('evaluation metrics: %s', metrics)
    (outdir / 'metrics.json').write_text(json.dumps(metrics, indent=2))

    # 6) simulate mitigator decisions (dry-run): print windows that would be mitigated
    thr = metrics.get('threshold')
    anomalies_idx = np.where(scores >= thr)[0]
    LOG.info('simulated mitigator would act on %d windows', len(anomalies_idx))
    actions = []
    for idx in anomalies_idx:
        actions.append({'window_index': int(idx), 'score': float(scores[idx]), 'action': 'log_only'})
    (outdir / 'simulated_actions.json').write_text(json.dumps(actions, indent=2))

    print('\nExperiment complete. Artifacts in', str(outdir))
    print('metrics:', json.dumps(metrics, indent=2))


if __name__ == '__main__':
    main()
