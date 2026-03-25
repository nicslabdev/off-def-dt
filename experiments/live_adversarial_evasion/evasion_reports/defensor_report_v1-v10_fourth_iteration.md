# Defensor Report — Fourth Iteration (retrained defensor with augmented negatives)

This report shows the results after retraining the auxiliar defensor using augmented negatives and sample weighting, tuning its threshold, and recomputing per-run countermeasure (CM) metrics.

Notes on training
- Retraining script: `scripts/retrain_defensor_aug.py` — augments baseline negatives and trains a `HistGradientBoostingClassifier` with sample weights to emphasize adversarial positives.
- Evaluation (holdout test): `experiments/defensor_retrain_fourth_iter_eval.json` — precision/recall/f1 on the held-out set.

Per-run summary (selected runs with CM results)

- run_live_evasion_v1
  - Before attack — precision: 0.9222756410256412, recall: 1.0, f1: 0.9595652173913043
  - After attack — precision: 0.8693910256410258, recall: 0.8854166666666666, f1: 0.8574223602484472
  - After countermeasure (retrained defensor) — precision: 0.733333, recall: 0.916667, f1: 0.814815

- run_live_evasion_v5
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.5, recall: 0.0833333333333333, f1: 0.1428571428571428
  - After countermeasure (retrained defensor) — precision: 0.714286, recall: 0.833333, f1: 0.769231

- run_live_evasion_v6
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.6666666666666666, recall: 0.1666666666666666, f1: 0.2666666666666666
  - After countermeasure — N/A (no adversarial feature vectors)

- run_live_evasion_v9
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.5, recall: 0.0833333333333333, f1: 0.1428571428571428
  - After countermeasure (retrained defensor) — precision: 0.714286, recall: 0.833333, f1: 0.769231

Reproduction steps

```bash
# retrain defensor with augmented negatives
.venv/bin/python3 scripts/retrain_defensor_aug.py

# tune threshold for new model
.venv/bin/python3 scripts/tune_defensor_threshold.py

# regenerate per-run aggregated CSV with CM applied
.venv/bin/python3 scripts/generate_aggregated_with_cm.py

# view the per-run CSV
cat experiments/per_run_evasion_with_cm.csv

# view training eval
cat experiments/defensor_retrain_fourth_iter_eval.json
```

Files produced
- `services/defensor_dt/model.joblib`, `scaler.joblib`, `feature_columns.joblib` — new artifacts
- `experiments/defensor_retrain_fourth_iter_eval.json` — holdout eval
- `experiments/defensor_threshold_tuning.json` — selected threshold
- `experiments/per_run_evasion_with_cm.csv` — recomputed CM metrics

If you want, I can now:
- (A) iterate hyperparameters (sample weight, model type) to further improve F1, or
- (B) re-run simulated stronger-attacks and test robustness, or
- (C) push the defensor threshold into the running mitigator and run live evaluations. Which next? 
