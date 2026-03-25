# Defensor Applied Metrics — run_live_evasion_v1..v10

This file reproduces the per-run before/after/after-countermeasure metrics produced earlier.

Commands

- Create / activate virtualenv and install deps (if not already):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

- Run the defensor-evaluation script for runs v1..v10 (writes `experiments/defensor_applied_metrics.json`):

```bash
.venv/bin/python3 scripts/eval_with_defensor.py --runs \
  experiments/run_live_evasion_v1 \
  experiments/run_live_evasion_v2 \
  experiments/run_live_evasion_v3 \
  experiments/run_live_evasion_v4 \
  experiments/run_live_evasion_v5 \
  experiments/run_live_evasion_v6 \
  experiments/run_live_evasion_v7 \
  experiments/run_live_evasion_v8 \
  experiments/run_live_evasion_v9 \
  experiments/run_live_evasion_v10
```

- To run the script for a single run (defaults to `experiments/run_live_v1`):

```bash
.venv/bin/python3 scripts/eval_with_defensor.py
```

- View the generated JSON results:

```bash
cat experiments/defensor_applied_metrics.json | jq .
```

- View the pre-/post-attack aggregated CSV used for the "Before" and "After attack" columns:

```bash
cat experiments/per_run_evasion_aggregated_from_agg.csv
```

Per-run metrics (extracted)

- run_live_evasion_v1
  - Before attack — precision: 0.9222756410256412, recall: 1.0, f1: 0.9595652173913043
  - After attack — precision: 0.8693910256410258, recall: 0.8854166666666666, f1: 0.8574223602484472
  - After countermeasure — precision: 0.46153846153846156, recall: 1.0, f1: 0.631578947368421

- run_live_evasion_v2
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.0, recall: 0.0, f1: 0.0
  - After countermeasure — N/A (no adversarial feature vectors)

- run_live_evasion_v3
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.5, recall: 0.0833333333333333, f1: 0.1428571428571428
  - After countermeasure — N/A (no adversarial feature vectors)

- run_live_evasion_v4
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.0, recall: 0.0, f1: 0.0
  - After countermeasure — N/A (no adversarial feature vectors)

- run_live_evasion_v5
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.5, recall: 0.0833333333333333, f1: 0.1428571428571428
  - After countermeasure — precision: 0.4166666666666667, recall: 0.8333333333333334, f1: 0.5555555555555556

- run_live_evasion_v6
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.6666666666666666, recall: 0.1666666666666666, f1: 0.2666666666666666
  - After countermeasure — N/A (no adversarial feature vectors)

- run_live_evasion_v7
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.5, recall: 0.0833333333333333, f1: 0.1428571428571428
  - After countermeasure — N/A (no adversarial feature vectors)

- run_live_evasion_v8
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.0, recall: 0.0, f1: 0.0
  - After countermeasure — N/A (no adversarial feature vectors)

- run_live_evasion_v9
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.5, recall: 0.0833333333333333, f1: 0.1428571428571428
  - After countermeasure — precision: 0.46153846153846156, recall: 1.0, f1: 0.631578947368421

- run_live_evasion_v10
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.5, recall: 0.0833333333333333, f1: 0.1428571428571428
  - After countermeasure — N/A (no adversarial feature vectors)

Notes
- "Before" and "After attack" metrics are taken from `experiments/per_run_evasion_aggregated_from_agg.csv`.
- "After countermeasure" metrics were computed by `scripts/eval_with_defensor.py` using artifacts in `services/mitigator/` and `services/defensor_dt/` and written to `experiments/defensor_applied_metrics.json`.

If you want these recomputed from a single unified codepath (to ensure exact parity) or want a threshold sweep to reduce baseline false positives before the 0→1 flip, tell me which and I'll run it next.
