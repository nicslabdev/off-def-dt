#!/usr/bin/env python3
"""Run a lightweight mitigation test against the in-process FastAPI app.

This script performs:
 - dry-run /mitigate call
 - monkeypatches the demo adapter and performs a non-dry-run call
 - reads the mitigation JSONL log and prints simple metrics JSON

Exits with code 0 on success or 2 on assertion failure.
"""
import os
import json
import time
import sys

import importlib.util
import types

# load services/mitigator/app.py as a module (not a package)
MITIGATOR_PATH = os.path.join(os.path.dirname(__file__), '..', 'services', 'mitigator', 'app.py')
MITIGATOR_PATH = os.path.abspath(MITIGATOR_PATH)

spec = importlib.util.spec_from_file_location('mitigator_app', MITIGATOR_PATH)
mitigator_mod = importlib.util.module_from_spec(spec)
sys.modules['mitigator_app'] = mitigator_mod
spec.loader.exec_module(mitigator_mod)

mitigator_app = mitigator_mod
MitigateRequest = mitigator_mod.MitigateRequest

MIT_LOG = os.getenv('MITIGATION_LOG', 'experiments/run_live_v1/mitigation_log.jsonl')


def teardown_log():
    try:
        if os.path.exists(MIT_LOG):
            os.remove(MIT_LOG)
    except Exception:
        pass


def read_log_entries():
    if not os.path.exists(MIT_LOG):
        return []
    out = []
    with open(MIT_LOG, 'r') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


def main():
    try:
        teardown_log()

        # Dry-run stop_service by calling handler directly
        req1 = MitigateRequest(stream_key='test-stream-1', action='stop_service', target={'note': 'test'}, dry_run=True, reason='ci test')
        data = mitigator_app.mitigate(req1)
        evt = data['event']
        if not (evt['stream_key'] == 'test-stream-1' and evt['action'] == 'stop_service'):
            print('unexpected dry-run event:', evt)
            sys.exit(2)

        time.sleep(0.05)
        entries = read_log_entries()
        if len(entries) < 1:
            print('no log entries after dry-run')
            sys.exit(2)

        # Monkeypatch the adapter and call handler directly for non-dry-run
        def fake_demo(target, dry_run=False):
            return {'mocked': True, 'target': target, 'dry_run': dry_run}

        mitigator_app._demo_stop_attacker = fake_demo

        req2 = MitigateRequest(stream_key='test-stream-2', action='stop_service', target={'note': 'real-run-test'}, dry_run=False, reason='ci test run')
        data2 = mitigator_app.mitigate(req2)
        evt2 = data2['event']
        if evt2.get('dry_run') is not False or not evt2.get('result', {}).get('mocked'):
            print('unexpected non-dry-run result:', evt2)
            sys.exit(2)

        time.sleep(0.05)
        entries2 = read_log_entries()
        metrics = {
            'total_events': len(entries2),
            'stream_1_logged': any(e.get('stream_key') == 'test-stream-1' for e in entries2),
            'stream_2_logged': any(e.get('stream_key') == 'test-stream-2' for e in entries2),
            'log_path': MIT_LOG,
        }

        out_path = 'experiments/run_live_v1/mitigation_test_metrics.json'
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, 'w') as fh:
            json.dump(metrics, fh)

        print(json.dumps(metrics, indent=2))
        if not (metrics['stream_1_logged'] and metrics['stream_2_logged']):
            sys.exit(2)

        sys.exit(0)
    except AssertionError as e:
        print('assertion failed:', e)
        sys.exit(2)
    except Exception as e:
        print('error during test:', e)
        sys.exit(2)


if __name__ == '__main__':
    main()
