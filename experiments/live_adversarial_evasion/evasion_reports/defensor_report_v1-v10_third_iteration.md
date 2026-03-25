# Defensor Report — Third Iteration (selected runs v1, v5, v6, v9)

This third-iteration report simulates an enhanced attack (stronger adversary parameters) after the first countermeasure and then reapplies the countermeasure. Attack parameters used: `attack_success_rate=0.6`, `def_proba_delta=-0.4`.

Per-run summary

- run_live_evasion_v1
  - Before attack — precision: 0.9222756410256412, recall: 1.0, f1: 0.9595652173913043
  - After attack — precision: 0.8693910256410258, recall: 0.8854166666666666, f1: 0.8574223602484472
  - After first countermeasure — precision: 0.714286, recall: 0.833333, f1: 0.769231
  - After enhanced attack (simulated) — precision: 0.0, recall: 0.0, f1: 0.0
  - After second countermeasure (re-applied) — precision: 0.0, recall: 0.0, f1: 0.0

- run_live_evasion_v5
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.5, recall: 0.0833333333333333, f1: 0.1428571428571428
  - After first countermeasure — precision: 0.692308, recall: 0.75, f1: 0.72
  - After enhanced attack (simulated) — precision: 0.0, recall: 0.0, f1: 0.0
  - After second countermeasure (re-applied) — precision: 0.0, recall: 0.0, f1: 0.0

- run_live_evasion_v6
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.6666666666666666, recall: 0.1666666666666666, f1: 0.2666666666666666
  - After first countermeasure — N/A (no adversarial feature vectors)
  - After enhanced attack (simulated) — precision: 0.0, recall: 0.0, f1: 0.0
  - After second countermeasure (re-applied) — precision: 0.0, recall: 0.0, f1: 0.0

- run_live_evasion_v9
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.5, recall: 0.0833333333333333, f1: 0.1428571428571428
  - After first countermeasure — precision: 0.75, recall: 1.0, f1: 0.857143
  - After enhanced attack (simulated) — precision: 0.0, recall: 0.0, f1: 0.0
  - After second countermeasure (re-applied) — precision: 0.0, recall: 0.0, f1: 0.0

Reproduction commands

```bash
source .venv/bin/activate
pip install -r requirements.txt

# tune defensor threshold (if not already):
.venv/bin/python3 scripts/tune_defensor_threshold.py

# generate per-run CM CSV:
.venv/bin/python3 scripts/generate_aggregated_with_cm.py

# simulate enhanced attack and re-apply CM:
.venv/bin/python3 scripts/iterate_defensor_attack.py --attack-success-rate 0.6 --def-proba-delta -0.4

# view resulting JSON metrics:
cat experiments/defensor_third_iter_metrics.json | jq .
```

Notes
- The enhanced attack is simulated: it probabilistically forces some adversarial samples to evade the RandomForest (`attack_success_rate`) and reduces defensor detection scores (`def_proba_delta`). You can adjust these parameters in `scripts/iterate_defensor_attack.py` to explore other attacker strengths.
