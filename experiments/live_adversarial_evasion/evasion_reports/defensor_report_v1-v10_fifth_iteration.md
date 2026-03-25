# Defensor Report — Fifth Iteration (stronger attack + enhanced countermeasures)

This iteration retrains the auxiliar defensor with stronger positive weighting, retunes its threshold, and evaluates robustness against a stronger simulated attacker. Steps performed:

1. Retrained defensor with augmented negatives and `w_pos=10.0` (see `scripts/retrain_defensor_aug.py`).
2. Retuned the defensor threshold (`scripts/tune_defensor_threshold.py`).
3. Recomputed per-run countermeasure metrics (`scripts/generate_aggregated_with_cm.py`).
4. Simulated a stronger attacker (`attack_success_rate=0.85`, `def_proba_delta=-0.7`) and reapplied the countermeasure (`scripts/iterate_defensor_attack.py`).

Selected runs: `run_live_evasion_v1`, `run_live_evasion_v5`, `run_live_evasion_v6`, `run_live_evasion_v9`.

Results

- run_live_evasion_v1
  - Before attack — precision: 0.9222756410256412, recall: 1.0, f1: 0.9595652173913043
  - After attack — precision: 0.8693910256410258, recall: 0.8854166666666666, f1: 0.8574223602484472
  - After first countermeasure (retrained defensor) — precision: 0.733333, recall: 0.916667, f1: 0.814815
  - After stronger attack (simulated) — precision: 0.0, recall: 0.0, f1: 0.0
  - After enhanced countermeasure (re-applied) — precision: 0.0, recall: 0.0, f1: 0.0

- run_live_evasion_v5
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.5, recall: 0.0833333333333333, f1: 0.1428571428571428
  - After first countermeasure (retrained defensor) — precision: 0.714286, recall: 0.833333, f1: 0.769231
  - After stronger attack (simulated) — precision: 0.0, recall: 0.0, f1: 0.0
  - After enhanced countermeasure (re-applied) — precision: 0.0, recall: 0.0, f1: 0.0

- run_live_evasion_v6
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.6666666666666666, recall: 0.1666666666666666, f1: 0.2666666666666666
  - After first countermeasure — N/A (no adversarial feature vectors)
  - After stronger attack (simulated) — precision: 0.0, recall: 0.0, f1: 0.0
  - After enhanced countermeasure (re-applied) — precision: 0.0, recall: 0.0, f1: 0.0

- run_live_evasion_v9
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.5, recall: 0.0833333333333333, f1: 0.1428571428571428
  - After first countermeasure (retrained defensor) — precision: 0.714286, recall: 0.833333, f1: 0.769231
  - After stronger attack (simulated) — precision: 0.0, recall: 0.0, f1: 0.0
  - After enhanced countermeasure (re-applied) — precision: 0.0, recall: 0.0, f1: 0.0

Reproduction commands

```bash
# retrain defensor with stronger positive weighting
.venv/bin/python3 scripts/retrain_defensor_aug.py --w-pos 10.0

# retune threshold
.venv/bin/python3 scripts/tune_defensor_threshold.py

# regenerate per-run CSV with CM
.venv/bin/python3 scripts/generate_aggregated_with_cm.py

# simulate stronger attack and reapply CM
.venv/bin/python3 scripts/iterate_defensor_attack.py --attack-success-rate 0.85 --def-proba-delta -0.7

# view final simulated results
cat experiments/defensor_third_iter_metrics.json | jq .
```

Observations
- The retrained defensor shifted its operating point (higher recall, lower precision) and improved CM results after the first countermeasure. The simulated stronger attacker parameters (high success rate and large score depression) were able to neutralize both RF and defensor signals in this simulation; real attacker success will depend on feasibility of such perturbations.

Next steps
- I can (A) explore hybrids (ensemble defensor + anomaly detector) to make CM more robust, (B) perform a grid search over `w_pos` and model hyperparameters to balance precision/recall, or (C) evaluate attacker constraints to simulate realistic attack budgets. Which do you prefer? 
