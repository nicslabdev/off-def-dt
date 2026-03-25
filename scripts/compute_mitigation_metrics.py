#!/usr/bin/env python3
"""Compute mitigation-level metrics for an experiment run.

Usage:
  python scripts/compute_mitigation_metrics.py --run experiments/run_live_v1

Outputs:
  - prints a summary
  - writes experiments/<run>/mitigation_metrics.json

Metrics computed:
  - TPm: mitigation events occurring during attack windows
  - FPm: mitigation events occurring during baseline or outside any window
  - FNw: attack windows without any mitigation (missed windows)
  - Precision_mitigator (event-level) = TPm / (TPm + FPm)
  - Recall_mitigator (window-level) = attack_windows_with_mitigation / total_attack_windows
  - F1 (harmonic mean of event-precision and window-recall) - best-effort
  - latency stats (mitigation ts - attack_start) for mitigations falling in attack windows
"""
import argparse
import os
import json
from pathlib import Path
from datetime import datetime, timezone
import math


def parse_iso(ts):
    # returns epoch float
    try:
        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        return dt.timestamp()
    except Exception:
        try:
            return float(ts)
        except Exception:
            return None


def load_jsonl(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path, 'r') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


def load_windows_from_csv(path):
    # expecting CSV with start_ts,end_ts as first two columns
    windows = []
    if not os.path.exists(path):
        return windows
    with open(path, 'r') as fh:
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
                windows.append((start, end))
            except Exception:
                continue
    return windows


def stats_from_list(vals):
    if not vals:
        return {'count': 0}
    vals_sorted = sorted(vals)
    n = len(vals_sorted)
    mean = sum(vals_sorted) / n
    med = vals_sorted[n//2]
    p95 = vals_sorted[min(n-1, math.ceil(n*0.95)-1)]
    return {'count': n, 'mean': mean, 'median': med, 'p95': p95, 'min': vals_sorted[0], 'max': vals_sorted[-1]}


def compute_metrics(run_path):
    runp = Path(run_path)
    mit_log = runp / 'mitigation_log.jsonl'
    mitigation_events = load_jsonl(str(mit_log))
    # default: no alerts log; can be provided by caller via global var
    alerts = compute_metrics.alerts if hasattr(compute_metrics, 'alerts') else []
    ignore_dry = compute_metrics.ignore_dry if hasattr(compute_metrics, 'ignore_dry') else False
    max_delay = compute_metrics.max_delay if hasattr(compute_metrics, 'max_delay') else 300.0
    match_by_target = compute_metrics.match_by_target if hasattr(compute_metrics, 'match_by_target') else False

    # gather attack windows from attack_*.csv
    attack_files = sorted(runp.glob('attack_*.csv'))
    attacks = {}
    total_attack_windows = 0
    for af in attack_files:
        name = af.stem.replace('attack_', '')
        w = load_windows_from_csv(str(af))
        attacks[name] = w
        total_attack_windows += len(w)

    # baseline windows
    baseline_windows = load_windows_from_csv(str(runp / 'baseline_replica.csv'))

    # flatten attack windows with name
    flat_attacks = []  # (start,end,attack_name)
    for name, windows in attacks.items():
        for (s,e) in windows:
            flat_attacks.append((s,e,name))

    # map attack pcap basename -> attack name for replay-safe target matching
    pcap_to_attack_name = {}
    for name in attacks.keys():
        pcap_to_attack_name[f'attack_{name}.pcap'] = name

    # for matching, create index of attack windows per name
    attack_windows_per_name = {name: list(windows) for name, windows in attacks.items()}

    # iterate mitigations
    tp_events = []
    fp_events = []
    outside_events = []
    latencies = []

    # also track which attack windows had at least one mitigation
    attack_window_hits = []
    for name, windows in attacks.items():
        attack_window_hits.append({ 'name': name, 'windows_hit': [False]*len(windows) })

    # if alerts were provided, index them by stream_key for fast lookup
    alerts_by_stream = {}
    if alerts:
        for a in alerts:
            ats = None
            if 'ts' in a:
                ats = parse_iso(a['ts'])
            elif 'time' in a:
                ats = parse_iso(a['time'])
            if ats is None:
                continue
            sk = a.get('stream_key') or a.get('stream') or 'global'
            alerts_by_stream.setdefault(sk, []).append(ats)
        # sort lists
        for k in alerts_by_stream:
            alerts_by_stream[k].sort()

    for ev in mitigation_events:
        ts = None
        if 'ts' in ev:
            ts = parse_iso(ev['ts'])
        elif 'time' in ev:
            ts = parse_iso(ev['time'])
        if ts is None:
            # skip undatable events
            outside_events.append(ev)
            continue
        # optionally ignore dry-run events
        if ignore_dry and ev.get('dry_run'):
            continue

        # replay-safe mode: match mitigation event by explicit target pcap/window index
        if match_by_target:
            tgt = ev.get('target') if isinstance(ev.get('target'), dict) else None
            t_pcap = None
            t_idx = None
            if tgt:
                t_pcap = tgt.get('pcap')
                t_idx = tgt.get('window_index')

            aname = None
            if isinstance(t_pcap, str):
                base = os.path.basename(t_pcap)
                aname = pcap_to_attack_name.get(base)

            idx = None
            try:
                if t_idx is not None:
                    idx = int(t_idx)
            except Exception:
                idx = None

            if aname is not None and idx is not None and 0 <= idx < len(attacks.get(aname, [])):
                tp_events.append(ev)
                # mark attack window hit
                for aw in attack_window_hits:
                    if aw['name'] == aname:
                        aw['windows_hit'][idx] = True
                        break
            else:
                fp_events.append(ev)
            continue

        # if alerts present, attempt to match mitigation to a prior alert for same stream_key
        if alerts:
            sk = ev.get('stream_key') or ev.get('stream') or 'global'
            matched = False
            if sk in alerts_by_stream:
                # find latest alert <= mitigation time
                times = alerts_by_stream[sk]
                # binary search for rightmost <= ts
                import bisect
                idx = bisect.bisect_right(times, ts) - 1
                if idx >= 0:
                    alert_ts = times[idx]
                    delta = ts - alert_ts
                    if 0 <= delta <= max_delay:
                        matched = True
                        tp_events.append(ev)
                        latencies.append(delta)
                        # mark this alert as hit by removing it (so we can count missed alerts)
                        # but keep a record in a separate set
                        ev['_matched_alert_ts'] = alert_ts
                        continue
            if not matched:
                # treat as FP if no matching alert found
                fp_events.append(ev)
            continue
        matched_attack = False
        # check each attack file windows
        for aname, windows in attacks.items():
            for idx, (s,e) in enumerate(windows):
                if s <= ts <= e:
                    matched_attack = True
                    tp_events.append(ev)
                    # latency relative to attack start
                    latencies.append(ts - s)
                    # mark hit
                    # find corresponding entry in attack_window_hits
                    for aw in attack_window_hits:
                        if aw['name'] == aname:
                            aw['windows_hit'][idx] = True
                            break
                    break
            if matched_attack:
                break
        if matched_attack:
            continue
        # check baseline
        matched_baseline = False
        for (s,e) in baseline_windows:
            if s <= ts <= e:
                matched_baseline = True
                break
        if matched_baseline:
            fp_events.append(ev)
        else:
            outside_events.append(ev)

    TPm = len(tp_events)
    FPm = len(fp_events) + len(outside_events)

    # additional alert-based stats: missed alerts
    missed_alerts = 0
    if alerts:
        total_alerts = 0
        matched_alerts = 0
        for sk, times in alerts_by_stream.items():
            total_alerts += len(times)
        # count matched alerts by scanning tp_events '_matched_alert_ts'
        matched_set = set()
        for ev in tp_events:
            if '_matched_alert_ts' in ev:
                matched_set.add(ev['_matched_alert_ts'])
        matched_alerts = len(matched_set)
        missed_alerts = total_alerts - matched_alerts
    else:
        missed_alerts = None

    # window-level recall: number of attack windows with ≥1 mitigation
    windows_hit = 0
    total_windows = 0
    for aname, windows in attacks.items():
        total_windows += len(windows)
    hit_windows = 0
    for aw in attack_window_hits:
        hit_windows += sum(1 for v in aw['windows_hit'] if v)

    FNw = total_windows - hit_windows

    event_precision = TPm / (TPm + FPm) if (TPm + FPm) > 0 else None
    window_recall = hit_windows / total_windows if total_windows > 0 else None
    f1 = None
    if event_precision is not None and window_recall is not None and event_precision + window_recall > 0:
        f1 = 2 * event_precision * window_recall / (event_precision + window_recall)

    latency_stats = stats_from_list(latencies)

    # build per-attack-file summary
    per_attack = {}
    # attack_window_hits is a list of {'name': name, 'windows_hit': [bools]}
    hits_map = {aw['name']: aw['windows_hit'] for aw in attack_window_hits}

    # prepare a mapping of mitigations -> file name (if any) and latencies per file
    mitigations_by_file = {name: [] for name in attacks.keys()}
    if match_by_target:
        for ev in mitigation_events:
            tgt = ev.get('target') if isinstance(ev.get('target'), dict) else None
            if not tgt:
                continue
            t_pcap = tgt.get('pcap')
            t_idx = tgt.get('window_index')
            aname = None
            if isinstance(t_pcap, str):
                aname = pcap_to_attack_name.get(os.path.basename(t_pcap))
            try:
                idx = int(t_idx) if t_idx is not None else None
            except Exception:
                idx = None
            if aname is None or idx is None or idx < 0 or idx >= len(attacks.get(aname, [])):
                continue
            start_ts = attacks[aname][idx][0]
            mitigations_by_file.setdefault(aname, []).append({'event': ev, 'ts': None, 'window_idx': idx, 'start': start_ts})
    else:
        for ev in mitigation_events:
            if 'ts' in ev:
                ev_ts = parse_iso(ev['ts'])
            elif 'time' in ev:
                ev_ts = parse_iso(ev['time'])
            else:
                ev_ts = None
            if ev_ts is None:
                continue
            # find which attack file window (if any) contains this event
            for aname, windows in attacks.items():
                for idx, (s, e) in enumerate(windows):
                    if s <= ev_ts <= e:
                        mitigations_by_file.setdefault(aname, []).append({'event': ev, 'ts': ev_ts, 'window_idx': idx, 'start': s})
                        break
    # assemble per-attack stats
    for name, windows in attacks.items():
        total_w = len(windows)
        windows_hit = sum(1 for v in hits_map.get(name, []) if v)
        events_in_file = len(mitigations_by_file.get(name, []))
        lat_list = []
        for item in mitigations_by_file.get(name, []):
            if item.get('ts') is not None and item.get('start') is not None:
                lat_list.append(item['ts'] - item['start'])
        # compute simple latency stats
        lat_stats_pa = {}
        if lat_list:
            lat_sorted = sorted(lat_list)
            n = len(lat_sorted)
            lat_stats_pa = {
                'count': n,
                'mean': sum(lat_sorted) / n,
                'median': lat_sorted[n//2],
                'min': lat_sorted[0],
                'max': lat_sorted[-1],
            }
        else:
            lat_stats_pa = {'count': 0}

        per_attack[name] = {
            'attack_name': name,
            'total_windows': total_w,
            'windows_mitigated': windows_hit,
            'window_recall': (windows_hit / total_w) if total_w > 0 else None,
            'mitigation_events_in_file': events_in_file,
            'latency_stats_seconds': lat_stats_pa,
        }

    res = {
        'run': str(runp),
        'mitigation_log_path': str(mit_log),
        'total_mitigation_events': len(mitigation_events),
        'TPm_events': TPm,
        'FPm_events': FPm,
        'FNw_windows': FNw,
        'total_attack_windows': total_windows,
        'attack_files': [p.name for p in attack_files],
        'event_precision': event_precision,
        'window_recall': window_recall,
        'f1_harmonic': f1,
        'latency_stats_seconds': latency_stats,
        'per_attack_summary': per_attack,
    }
    return res


def write_report(run_path, max_delay=0.0, ignore_dry=False, out_csv=None, match_by_target=False):
    """Write a per-attack-window mitigation report CSV into the run directory.

    Columns: run, attack_file, window_index, start_ts, end_ts, mitigated,
    mitigation_id, mitigation_ts, latency_seconds, dry_run, action
    """
    import csv
    from pathlib import Path

    runp = Path(run_path)
    mit_log = runp / 'mitigation_log.jsonl'
    mitigation_events = load_jsonl(str(mit_log))

    # prepare mitigations: parse ts to epoch and sort
    for ev in mitigation_events:
        if 'ts' in ev:
            ev['_ts_epoch'] = parse_iso(ev['ts'])
        elif 'time' in ev:
            ev['_ts_epoch'] = parse_iso(ev['time'])
        else:
            ev['_ts_epoch'] = None
    mitigation_events = [e for e in mitigation_events if not (ignore_dry and e.get('dry_run'))]
    mitigation_events.sort(key=lambda x: x.get('_ts_epoch') if x.get('_ts_epoch') is not None else 0)

    attack_files = sorted(runp.glob('attack_*.csv'))
    attack_pcap_by_csv = {}
    for af in attack_files:
        attack_pcap_by_csv[af.name] = af.name.replace('.csv', '.pcap')
    rows = []
    for af in attack_files:
        # load windows using existing loader
        windows = []
        with open(af, 'r') as fh:
            # reuse load_windows_from_csv which expects start_ts,end_ts first
            windows = load_windows_from_csv(str(af))
        for idx, (s, e) in enumerate(windows):
            # find matched mitigation either by explicit target or timestamp window
            matched = None
            if match_by_target:
                expect_pcap = attack_pcap_by_csv.get(af.name)
                for m in mitigation_events:
                    tgt = m.get('target') if isinstance(m.get('target'), dict) else None
                    if not tgt:
                        continue
                    t_pcap = tgt.get('pcap')
                    t_idx = tgt.get('window_index')
                    if not isinstance(t_pcap, str):
                        continue
                    try:
                        t_idx = int(t_idx)
                    except Exception:
                        continue
                    if os.path.basename(t_pcap) == expect_pcap and t_idx == idx:
                        matched = m
                        break
            else:
                limit = e + (max_delay or 0)
                for m in mitigation_events:
                    t = m.get('_ts_epoch')
                    if t is None:
                        continue
                    if t >= s and t <= limit:
                        matched = m
                        break
            if matched:
                mid = matched.get('id') or ''
                mts = matched.get('ts') or ''
                lat = ''
                if matched.get('_ts_epoch') is not None:
                    lat = matched.get('_ts_epoch') - s
                dry = matched.get('dry_run') if 'dry_run' in matched else ''
                action = matched.get('action') if 'action' in matched else ''
                mitigated = True
            else:
                mid = ''
                mts = ''
                lat = ''
                dry = ''
                action = ''
                mitigated = False
            rows.append({
                'run': str(runp),
                'attack_file': af.name,
                'window_index': idx,
                'start_ts': s,
                'end_ts': e,
                'mitigated': mitigated,
                'mitigation_id': mid,
                'mitigation_ts': mts,
                'latency_seconds': lat,
                'dry_run': dry,
                'action': action,
            })

    out_path = out_csv or str(runp / 'mitigation_report.csv')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    fieldnames = ['run','attack_file','window_index','start_ts','end_ts','mitigated','mitigation_id','mitigation_ts','latency_seconds','dry_run','action']
    with open(out_path, 'w', newline='') as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    return out_path


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--run', default='experiments/run_live_v1')
    p.add_argument('--alerts', default=None, help='optional alerts JSONL file to match mitigations to alerts')
    p.add_argument('--ignore-dry-run', action='store_true', dest='ignore_dry', help='exclude dry_run mitigation events from metrics')
    p.add_argument('--max-delay', type=float, default=300.0, help='max seconds from alert to mitigation to consider a match')
    p.add_argument('--write-report', action='store_true', help='also write per-window mitigation_report.csv into the run dir')
    p.add_argument('--match-by-target', action='store_true', help='match mitigation events to attack windows by target pcap/window_index (replay-safe mode)')
    args = p.parse_args()
    # load alerts if provided
    alerts = []
    if args.alerts:
        alerts = load_jsonl(args.alerts)
    # attach to function for use
    compute_metrics.alerts = alerts
    compute_metrics.ignore_dry = args.ignore_dry
    compute_metrics.max_delay = args.max_delay
    compute_metrics.match_by_target = args.match_by_target
    res = compute_metrics(args.run)
    out_path = os.path.join(args.run, 'mitigation_metrics.json')
    with open(out_path, 'w') as fh:
        json.dump(res, fh, indent=2)
    print(json.dumps(res, indent=2))
    # optionally write per-window report
    if args.write_report:
        try:
            rpt = write_report(args.run, max_delay=args.max_delay, ignore_dry=args.ignore_dry, match_by_target=args.match_by_target)
            print(f'Wrote mitigation report: {rpt}')
        except Exception as e:
            print('Failed to write mitigation report:', e)
    # write per-attack summary CSV
    try:
        summary_csv = os.path.join(args.run, 'mitigation_summary.csv')
        with open(summary_csv, 'w', newline='') as fh:
            import csv
            fieldnames = ['attack_name','total_windows','windows_mitigated','window_recall','mitigation_events_in_file']
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for name, info in res.get('per_attack_summary', {}).items():
                writer.writerow({
                    'attack_name': name,
                    'total_windows': info.get('total_windows'),
                    'windows_mitigated': info.get('windows_mitigated'),
                    'window_recall': info.get('window_recall'),
                    'mitigation_events_in_file': info.get('mitigation_events_in_file'),
                })
        print(f'Wrote mitigation summary: {summary_csv}')
    except Exception as e:
        print('Failed to write mitigation summary CSV:', e)
