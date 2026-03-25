#!/usr/bin/env python3
"""
Random attack runner + mitigator checker.

Usage examples:

# 10 attacks, 1-5 minutes apart, use docker-compose exec to run attacks,
# after each attack check mitigator with windows extracted from `live.pcap`.
python3 scripts/random_attack_runner.py \
  --n-attacks 10 --min-interval 60 --max-interval 300 \
  --attacks mqtt_spoof,mqtt_replay,high_rate_pub \
  --pcap-path /path/to/live.pcap \
  --mitigator http://127.0.0.1:8080 \
  --use-docker

# Run attacks locally (if attacker deps are installed) and check mitigator
python3 scripts/random_attack_runner.py --n-attacks 5 --attacks mqtt_spoof --pcap-path experiments/run_live_v1/baseline_replica.pcap --mitigator http://127.0.0.1:8080
"""
import argparse
import random
import time
import subprocess
import os
import sys
import requests
import json
from pathlib import Path

# lazy import scapy-based extractor if available
try:
    from tools.pcap_to_features import extract_windows
except Exception:
    extract_windows = None


def trigger_attack_docker(attack, duration, rate, compose_file=None, service_name="attacker"):
    # builds a sh -c command that sets env vars for the attacker process
    cmd = f"DURATION={duration} RATE={rate} python3 /app/attacks.py {attack}"
    base = ["docker", "compose"]
    if compose_file:
        base += ["-f", compose_file]
    base += ["exec", "-T", service_name, "sh", "-c", cmd]
    print("Running (docker):", " ".join(base))
    # run in foreground and wait for completion
    proc = subprocess.Popen(base, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in proc.stdout:
        print("[attacker]", line.rstrip())
    proc.wait()
    return proc.returncode


def trigger_attack_local(attack, duration, rate):
    # Run the local attacker file directly (use only if dependencies installed)
    env = os.environ.copy()
    env["DURATION"] = str(duration)
    env["RATE"] = str(rate)
    cmd = [sys.executable, "services/attacker/attacks.py", attack]
    print("Running (local):", " ".join(cmd), "with env DURATION, RATE")
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in proc.stdout:
        print("[attacker-local]", line.rstrip())
    proc.wait()
    return proc.returncode


def query_mitigator_infer(mitigator_url, features):
    try:
        r = requests.post(mitigator_url.rstrip("/") + "/infer", json={"features": features}, timeout=10)
        return r.status_code, r.json() if r.headers.get("Content-Type", "").startswith("application/json") else r.text
    except Exception as e:
        return None, str(e)


def check_pcap_windows(mitigator_url, pcap_path, window_size=3.0):
    if extract_windows is None:
        print("pcap extractor not available (scapy). Can't extract windows locally.")
        return None
    if not os.path.exists(pcap_path):
        print("pcap not found:", pcap_path)
        return None
    windows = extract_windows(pcap_path, window_size=window_size)
    if not windows:
        print("no windows extracted from pcap:", pcap_path)
        return []
    results = []
    for i, w in enumerate(windows):
        features = {k: v for k, v in w.items() if k not in ("start_ts", "end_ts")}
        status, body = query_mitigator_infer(mitigator_url, features)
        results.append({"window_index": i, "status": status, "body": body, "features": features})
    return results


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--attacks", default="mqtt_spoof,mqtt_replay,high_rate_pub", help="comma-separated attack names (as in services/attacker/attacks.py)")
    p.add_argument("--n-attacks", type=int, default=5)
    p.add_argument("--min-interval", type=int, default=60, help="minimum seconds between attacks")
    p.add_argument("--max-interval", type=int, default=300, help="maximum seconds between attacks")
    p.add_argument("--duration", type=int, default=10, help="attack duration (seconds)")
    p.add_argument("--rate", type=int, default=100, help="attack rate (pubs/sec or similar)")
    p.add_argument("--use-docker", action="store_true", help="use docker compose exec attacker to run attacks")
    p.add_argument("--compose-file", default=None, help="optional docker compose file (path) to pass to `docker compose -f ...`")
    p.add_argument("--pcap-path", default=None, help="optional pcap to extract windows from for immediate checking")
    p.add_argument("--mitigator", default="http://127.0.0.1:8080", help="mitigator base url")
    p.add_argument("--window-size", type=float, default=3.0, help="window size (s) used for extracting windows from pcap")
    p.add_argument("--log-dir", default="logs", help="directory to append CSV logs to")
    p.add_argument("--log-file", default="attack_log.csv", help="CSV filename to append attack logs to (inside --log-dir)")
    args = p.parse_args()

    attacks = [a.strip() for a in args.attacks.split(",") if a.strip()]
    if not attacks:
        print("no attacks provided")
        return

    print("Random attack runner starting. Attacks:", attacks)
    print("Mitigator URL:", args.mitigator)
    for idx in range(args.n_attacks):
        wait = random.uniform(args.min_interval, args.max_interval)
        print(f"\n[{idx+1}/{args.n_attacks}] Waiting {wait:.1f}s until next attack...")
        time.sleep(wait)

        attack = random.choice(attacks)
        print(f"Triggering attack '{attack}' duration={args.duration} rate={args.rate}")

        if args.use_docker:
            rc = trigger_attack_docker(attack, args.duration, args.rate, compose_file=args.compose_file)
        else:
            rc = trigger_attack_local(attack, args.duration, args.rate)
        print("Attack finished with rc=", rc)

        # Allow a short settling time for mitigator/collector to see traffic
        settle = 3
        print(f"Sleeping {settle}s to let capture/mitigator process traffic...")
        time.sleep(settle)
        # After each attack: either check provided pcap windows OR call /debug
        if args.pcap_path:
            print("Extracting windows from pcap and querying mitigator:", args.pcap_path)
            res = check_pcap_windows(args.mitigator, args.pcap_path, window_size=args.window_size)
            if res is None:
                print("No results (extractor missing or pcap absent).")
            else:
                # Print compact summary
                for r in res:
                    print(f"window {r['window_index']}: status={r['status']}, body={r['body']}")
        else:
            # if no pcap provided, call /debug to check model state and sample score
            try:
                r = requests.get(args.mitigator.rstrip("/") + "/debug", timeout=5)
                try:
                    print("mitigator /debug:", json.dumps(r.json(), indent=2))
                except Exception:
                    print("mitigator /debug raw:", r.text)
            except Exception as e:
                print("failed to call mitigator /debug:", e)

        # Run the collect_scores_from_mitigator script to aggregate PCAP anomaly stats
        # and append a CSV log entry for later analysis.
        try:
            collect_cmd = [sys.executable, 'scripts/collect_scores_from_mitigator.py']
            print('Running collector:', ' '.join(collect_cmd))
            proc = subprocess.Popen(collect_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out, err = proc.communicate(timeout=300)
            if proc.returncode != 0:
                print('collector failed:', err)
            else:
                try:
                    summary = json.loads(out)
                except Exception:
                    print('collector output not JSON; raw output:\n', out)
                    summary = None

                # Prepare CSV log
                log_dir = Path(args.log_dir)
                log_dir.mkdir(parents=True, exist_ok=True)
                log_file = log_dir / (args.log_file or 'attack_log.csv')

                # compute aggregated metrics
                ts = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime())
                baseline_stats = summary.get('baseline', {}) if summary else {}
                baseline_n = baseline_stats.get('n_windows', 0)
                baseline_anoms = baseline_stats.get('n_anomalies', 0)
                baseline_mean = baseline_stats.get('mean', '')
                # attacks aggregated
                attack_names = [k for k in (summary.keys() if summary else []) if k != 'baseline']
                total_attack_windows = 0
                total_attack_anoms = 0
                weighted_mean_sum = 0.0
                weighted_count = 0
                if summary:
                    for a in attack_names:
                        s = summary.get(a, {})
                        n = s.get('n_windows', 0)
                        m = s.get('mean', 0.0)
                        total_attack_windows += n
                        total_attack_anoms += s.get('n_anomalies', 0)
                        if n and m is not None:
                            weighted_mean_sum += float(m) * int(n)
                            weighted_count += int(n)
                attack_mean = (weighted_mean_sum / weighted_count) if weighted_count else ''

                # write CSV header if not exists
                header = 'timestamp,attack_name,duration,rate,total_attack_windows,total_attack_anoms,attack_mean_score,baseline_n,baseline_anoms,baseline_mean,raw_summary'
                write_header = not log_file.exists()
                with open(log_file, 'a') as fh:
                    if write_header:
                        fh.write(header + '\n')
                    row = [ts, attack, str(args.duration), str(args.rate), str(total_attack_windows), str(total_attack_anoms), str(attack_mean), str(baseline_n), str(baseline_anoms), str(baseline_mean), json.dumps(summary).replace('\n',' ')]
                    fh.write(','.join('"' + r.replace('"','""') + '"' for r in row) + '\n')
                print('Appended log to', log_file)
        except Exception as e:
            print('collector/logging failed:', e)

    print("Done running random attacks.")

if __name__ == "__main__":
    main()