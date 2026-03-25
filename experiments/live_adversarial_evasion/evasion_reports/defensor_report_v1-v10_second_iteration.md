# Defensor Report — Second Iteration (run_live_evasion_v1..v10)

This report uses the defender tuning and recomputed countermeasure (CM) metrics from `experiments/per_run_evasion_with_cm.csv`.

Per-run summary

- run_live_evasion_v1
  - Before attack — precision: 0.9222756410256412, recall: 1.0, f1: 0.9595652173913043
  - After attack — precision: 0.8693910256410258, recall: 0.8854166666666666, f1: 0.8574223602484472
  - After countermeasure — precision: 0.714286, recall: 0.833333, f1: 0.769231

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
  - After countermeasure — precision: 0.692308, recall: 0.75, f1: 0.72

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
  - After countermeasure — precision: 0.75, recall: 1.0, f1: 0.857143

- run_live_evasion_v10
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.5, recall: 0.0833333333333333, f1: 0.1428571428571428
  - After countermeasure — N/A (no adversarial feature vectors)

Reproduction

```bash
# ensure environment
source .venv/bin/activate
pip install -r requirements.txt

# run tuning (already done):
.venv/bin/python3 scripts/tune_defensor_threshold.py

# regenerate aggregated CSV with CM applied (already done):
.venv/bin/python3 scripts/generate_aggregated_with_cm.py

# view results:
cat experiments/per_run_evasion_with_cm.csv
```

Notes
- "Before" and "After attack" columns are from `experiments/per_run_evasion_aggregated_from_agg.csv`.
- "After countermeasure" columns were computed by applying the trained defensor with the selected threshold from `experiments/defensor_threshold_tuning.json` and are written to `experiments/per_run_evasion_with_cm.csv`.
