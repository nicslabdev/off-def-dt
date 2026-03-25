#!/usr/bin/env python3
"""Simulate mitigation events by appending entries into mitigation_log.jsonl.

Behavior:
 - For each attack_*.csv in the given run folder, take the first window and append
   a mitigation event with ts = start_ts + 0.5 seconds, stream_key = attack name.
 - Result field is mocked as {'mocked': True}
 - By default writes to experiments/run_live_v1/mitigation_log.jsonl
"""
import argparse
import os
import json
from pathlib import Path
from datetime import datetime, timezone


def simulate(run_path, only_first_per_attack=True, overwrite=False):
    runp = Path(run_path)
    mit_log = runp / 'mitigation_log.jsonl'
    attack_files = sorted(runp.glob('attack_*.csv'))
    os.makedirs(runp, exist_ok=True)

    # optionally remove prior simulated entries
    if overwrite and mit_log.exists():
        kept = []
        with open(mit_log, 'r') as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                # keep non-simulated events
                if str(ev.get('id','')).startswith('sim-') or ev.get('result',{}).get('mocked'):
                    continue
                kept.append(ev)
        with open(mit_log, 'w') as fh:
            for e in kept:
                fh.write(json.dumps(e) + '\n')

    entries = []
    for af in attack_files:
        name = af.stem.replace('attack_', '')
        # read windows
        with open(af, 'r') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                if line.startswith('#'):
                    continue
                parts = line.split(',')
                try:
                    start = float(parts[0])
                    end = float(parts[1])
                except Exception:
                    continue
                ts = start + 0.5
                evt = {
                    'id': f'sim-{name}-{int(ts)}',
                    'stream_key': name,
                    'action': 'stop_service',
                    'target': {'simulated': True},
                    'duration_seconds': 60,
                    'reason': 'simulated test',
                    'dry_run': False,
                    'ts': datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                    'result': {'mocked': True}
                }
                entries.append(evt)
                if only_first_per_attack:
                    break
    # append to mitigation log
    with open(mit_log, 'a') as fh:
        for e in entries:
            fh.write(json.dumps(e) + '\n')
    print(f'appended {len(entries)} simulated mitigations to {mit_log}')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--run', default='experiments/run_live_v1')
    p.add_argument('--all-windows', action='store_true', dest='all_windows', help='simulate mitigations for all windows in each attack file')
    p.add_argument('--overwrite', action='store_true', help='remove prior simulated mitigation entries before appending')
    args = p.parse_args()
    simulate(args.run, only_first_per_attack=not args.all_windows, overwrite=args.overwrite)
