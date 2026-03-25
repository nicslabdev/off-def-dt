import os
import json
import time

from fastapi.testclient import TestClient

from services.mitigator import app as mitigator_app

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
                # skip malformed
                continue
    return out


def test_mitigation_dry_and_mocked_run(monkeypatch):
    # ensure clean state
    teardown_log()

    client = TestClient(mitigator_app.app)

    # Dry-run stop_service should return the command and be logged
    resp = client.post('/mitigate', json={
        'stream_key': 'test-stream-1',
        'action': 'stop_service',
        'target': {'note': 'test'},
        'dry_run': True,
        'reason': 'ci test'
    })
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert 'event' in data
    evt = data['event']
    assert evt['stream_key'] == 'test-stream-1'
    assert evt['action'] == 'stop_service'
    assert evt['dry_run'] is True
    # dry-run should include a cmd (no execution)
    assert 'result' in evt
    assert isinstance(evt['result'], dict)
    assert 'cmd' in evt['result'] or 'simulated' in evt['result']

    # Give a small delay to ensure log flushed
    time.sleep(0.1)
    entries = read_log_entries()
    assert len(entries) >= 1
    last = entries[-1]
    assert last.get('stream_key') == 'test-stream-1'
    assert last.get('action') == 'stop_service'

    # Now mock the _demo_stop_attacker adapter so we can exercise non-dry-run
    def fake_demo(target, dry_run=False):
        return {'mocked': True, 'target': target, 'dry_run': dry_run}

    # monkeypatch the adapter in module
    monkeypatch.setattr(mitigator_app, '_demo_stop_attacker', fake_demo)

    resp2 = client.post('/mitigate', json={
        'stream_key': 'test-stream-2',
        'action': 'stop_service',
        'target': {'note': 'real-run-test'},
        'dry_run': False,
        'reason': 'ci test run'
    })
    assert resp2.status_code == 200, resp2.text
    evt2 = resp2.json()['event']
    assert evt2['dry_run'] is False
    assert evt2['result'].get('mocked') is True

    time.sleep(0.1)
    entries2 = read_log_entries()
    # two entries should now be present
    assert len(entries2) >= 2
    found_streams = [e.get('stream_key') for e in entries2[-2:]]
    assert 'test-stream-1' in found_streams
    assert 'test-stream-2' in found_streams

    # basic metrics: at least these two events logged
    metrics = {
        'total_events': len(entries2),
        'stream_1_logged': any(e.get('stream_key') == 'test-stream-1' for e in entries2),
        'stream_2_logged': any(e.get('stream_key') == 'test-stream-2' for e in entries2),
    }

    # write metrics to a small file for user verification
    metrics_path = 'experiments/run_live_v1/mitigation_test_metrics.json'
    os.makedirs(os.path.dirname(metrics_path), exist_ok=True)
    with open(metrics_path, 'w') as fh:
        json.dump(metrics, fh)

    assert metrics['stream_1_logged'] and metrics['stream_2_logged']


if __name__ == '__main__':
    # allow running directly
    import pytest

    pytest.main([__file__])
