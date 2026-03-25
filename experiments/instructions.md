# Industrial Network + Digital Twin Testbed

This repository contains a Docker-based industrial cyber-physical simulation with MQTT, Modbus, a replica topology, and digital twin (DT) components for attack/defense experimentation.

## Architecture at a glance

- **Isolated infrastructure (`docker-compose.isolated.yml`)**: treated as the **real infrastructure**.
- **`emulator` and `simulation` services**: treated as synchronized **digital twins**.
- **`replica_replicator` service**: synchronization bridge between real-side and replica-side streams.
- **`attacker` service**: injects adversarial traffic.
- **`services/mitigator/app.py`**: detection + mitigation API (`/infer*`, `/mitigate`).

## Quick start

```bash
docker compose -f docker-compose.isolated.yml up --build -d
docker compose -f docker-compose.isolated.yml ps
```

Stop and cleanup:

```bash
docker compose -f docker-compose.isolated.yml down
```

## Services

- MQTT broker and sensors publish telemetry (`sensors/<id>/telemetry`).
- Modbus slaves expose register state.
- Gateway maps MQTT telemetry to Modbus writes.
- Replica broker/slaves mirror selected traffic/state.
- Attacker can run scenarios like `mqtt_spoof`, `mqtt_replay`, `high_rate_pub`, etc.

## End-to-end DT runbook (live attack → detection → mitigation → metrics)

The runbook below is the recommended sequence for reproducible experiments in `experiments/run_live_v2`.

### 1) Initialize experiment context

```bash
cd /mnt/AI-DATA/imanb/off-deff-dt
source .venv/bin/activate

export RUN_DIR="experiments/run_live_v2"
export MITIGATION_LOG="$RUN_DIR/mitigation_log.jsonl"
export MITIGATOR_PORT=8082

mkdir -p "$RUN_DIR"
: > "$MITIGATION_LOG"
```

### 2) Ensure no stale mitigator process exists

```bash
pkill -f "uvicorn services.mitigator.app:app" || true
```

### 3) Start mitigator service (Terminal A)

```bash
cd /mnt/AI-DATA/imanb/off-deff-dt
source .venv/bin/activate
export MITIGATION_LOG="experiments/run_live_v2/mitigation_log.jsonl"
.venv/bin/uvicorn services.mitigator.app:app --host 127.0.0.1 --port 8082
```

### 4) Validate mitigator health (Terminal B)

```bash
cd /mnt/AI-DATA/imanb/off-deff-dt
.venv/bin/python - <<'PY'
import requests
for u in ["http://127.0.0.1:8082/health", "http://127.0.0.1:8082/config"]:
    r = requests.get(u, timeout=5)
    print(u, r.status_code, r.text)
PY
```

### 5) Start isolated real+DT stack

```bash
cd /mnt/AI-DATA/imanb/off-deff-dt
docker compose -f docker-compose.isolated.yml up --build -d \
  mosquitto replica_mosquitto replica_replicator attacker emulator simulation gateway

docker compose -f docker-compose.isolated.yml ps
```

### 6) Launch a live attack stimulus

```bash
cd /mnt/AI-DATA/imanb/off-deff-dt
source .venv/bin/activate
.venv/bin/python scripts/random_attack_runner.py \
  --n-attacks 1 \
  --min-interval 0 --max-interval 0 \
  --attacks mqtt_spoof \
  --duration 10 \
  --rate 200 \
  --use-docker \
  --compose-file docker-compose.isolated.yml \
  --mitigator http://127.0.0.1:8082
```

### 7) Force detector→mitigator event generation (recommended)

```bash
cd /mnt/AI-DATA/imanb/off-deff-dt
source .venv/bin/activate
.venv/bin/python scripts/run_detector_and_trigger_mitigations.py \
  --run experiments/run_live_v2 \
  --mitigator http://127.0.0.1:8082 \
  --dry-run
```

### 8) Sanity-check mitigation log before metrics

```bash
cd /mnt/AI-DATA/imanb/off-deff-dt
wc -l experiments/run_live_v2/mitigation_log.jsonl
tail -n 5 experiments/run_live_v2/mitigation_log.jsonl
```

If line count is `0`, rerun step 7 before computing metrics.

### 9) Compute detection metrics first

```bash
cd /mnt/AI-DATA/imanb/off-deff-dt
source .venv/bin/activate
.venv/bin/python scripts/live_eval.py \
  --outdir experiments/run_live_v2 \
  --mitigator http://127.0.0.1:8082 \
  > experiments/run_live_v2/detection_metrics_live.json

python - <<'PY'
import json
txt = open("experiments/run_live_v2/detection_metrics_live.json").read()
j = json.loads(txt[txt.find("{"):])
print("Detection Precision:", j["combined"]["precision"])
print("Detection Recall:", j["combined"]["recall"])
print("Detection F1:", j["combined"]["f1"])
PY
```

### 10) Compute mitigation metrics (replay-safe mode)

Use `--match-by-target` for replayed PCAP workflows.

```bash
cd /mnt/AI-DATA/imanb/off-deff-dt
source .venv/bin/activate
.venv/bin/python scripts/compute_mitigation_metrics.py \
  --run experiments/run_live_v2 \
  --write-report \
  --match-by-target

python - <<'PY'
import json
j = json.load(open("experiments/run_live_v2/mitigation_metrics.json"))
print("Mitigator Event Precision:", j.get("event_precision"))
print("Mitigator Window Recall:", j.get("window_recall"))
print("Mitigator F1:", j.get("f1_harmonic"))
print("TPm:", j.get("TPm_events"), "FPm:", j.get("FPm_events"), "FNw:", j.get("FNw_windows"))
PY
```

### 11) Inspect generated artifacts

```bash
cd /mnt/AI-DATA/imanb/off-deff-dt
ls -lh experiments/run_live_v2/*metrics*.json \
       experiments/run_live_v2/mitigation_report.csv \
       experiments/run_live_v2/mitigation_summary.csv

head -n 20 experiments/run_live_v2/mitigation_summary.csv
```

### 12) Cleanup

```bash
cd /mnt/AI-DATA/imanb/off-deff-dt
docker compose -f docker-compose.isolated.yml down
```

Stop the mitigator process in Terminal A with `Ctrl+C`.

## Metric interpretation (important)

- `event_precision = TPm / (TPm + FPm)`
- `window_recall = mitigated_attack_windows / total_attack_windows`
- `f1_harmonic = 2 * precision * recall / (precision + recall)`

For replay runs, if timestamp-only matching is used, TP may become zero due to clock mismatch between historical CSV windows and current mitigation timestamps. Use `--match-by-target` to avoid this.

## Offensive DT: adversarial attacks against detector (constrained MI-FGSM)

You can simulate adversarial evasion from the **offensive DT** to estimate how attack perturbations reduce detector alerts and impact mitigation coverage.

### What it does

- Loads attack windows from `attack_*.csv` in a run directory.
- Queries mitigator `/infer` for baseline score/alert.
- Applies a constrained MI-FGSM-like black-box attack on feature vectors.
- Re-queries `/infer` on adversarial features.
- Logs per-window adversarial outcomes and writes impact summary.

### Host-side execution (recommended)

```bash
cd /mnt/AI-DATA/imanb/off-deff-dt
source .venv/bin/activate

.venv/bin/python scripts/run_offensive_dt_adversarial_eval.py \
  --run-dir experiments/run_live_v2 \
  --mitigator http://127.0.0.1:8082 \
  --max-windows 200 \
  --eps 0.12 \
  --alpha 0.03 \
  --steps 6 \
  --momentum 0.9 \
  --fd-eps 0.02 \
  --rel-clip 0.2 \
  --max-features 12 \
  --dry-run
```

### Simulator-integrated execution (container)

Set these environment variables in the `simulation` service to enable offensive-DT mode:

- `OFFENSIVE_DT_ENABLED=1`
- `OFFENSIVE_DT_RUN_DIR=experiments/run_live_v2`
- `OFFENSIVE_DT_MITIGATOR=http://<mitigator-host>:8082`
- `OFFENSIVE_DT_MAX_WINDOWS=200`
- `OFFENSIVE_DT_EPS=0.12`
- `OFFENSIVE_DT_ALPHA=0.03`
- `OFFENSIVE_DT_STEPS=6`
- `OFFENSIVE_DT_MOMENTUM=0.9`
- `OFFENSIVE_DT_FD_EPS=0.02`
- `OFFENSIVE_DT_REL_CLIP=0.2`
- `OFFENSIVE_DT_MAX_FEATURES=12`
- `OFFENSIVE_DT_DRY_RUN=1`

Optional periodic reruns:

- `OFFENSIVE_DT_INTERVAL_SECONDS=0` (run once; set >0 for loop)

### Outputs

- `experiments/<run>/offensive_dt_adversarial_log.jsonl` (per-window adversarial outcomes)
- `experiments/<run>/offensive_dt_impact.json` (aggregate impact)

Key impact fields:

- `baseline_alert_rate`
- `adversarial_alert_rate`
- `evasion_rate_given_alert`
- `estimated_unmitigated_window_increase`
- `mean_score_drop`
- `mitigation_calls_from_adversarial_alerts`
