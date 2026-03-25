# Defensor: Six-Iteration Overview (F1 only) — runs v1, v5, v6, v9

This file mirrors the six-iteration report but shows only the F1 scores. Columns:
- Before: pre-attack F1
- After: post-attack F1
- CM1: F1 after first countermeasure
- Strong attack: F1 after simulated stronger attack (if performed)
- CM2: F1 after re-applying countermeasure (if performed)

Use `-` when a column is not present for that iteration.

---

## Iteration 1 — Initial defensor application (F1)

| Run | Before F1 | After F1 | CM1 F1 | Strong attack F1 | CM2 F1 |
|---|---:|---:|---:|---:|---:|
| v1 | 0.9595652 | 0.8574224 | 0.6315789 | - | - |
| v5 | 0.9600000 | 0.1428571 | 0.5555556 | - | - |
| v6 | 0.9600000 | 0.2666667 | - | - | - |
| v9 | 0.9600000 | 0.1428571 | 0.6315789 | - | - |

---

## Iteration 2 — Threshold tuning / early defensor tuning (F1)

| Run | Before F1 | After F1 | CM1 F1 | Strong attack F1 | CM2 F1 |
|---|---:|---:|---:|---:|---:|
| v1 | 0.9595652 | 0.8574224 | 0.7692310 | - | - |
| v5 | 0.9600000 | 0.1428571 | 0.7200000 | - | - |
| v6 | 0.9600000 | 0.2666667 | - | - | - |
| v9 | 0.9600000 | 0.1428571 | 0.8571430 | - | - |

---

## Iteration 3 — Simulated enhanced attack (attack_success_rate=0.6, def_proba_delta=-0.4) (F1)

| Run | Before F1 | After F1 | CM1 F1 | Strong attack F1 | CM2 F1 |
|---|---:|---:|---:|---:|---:|
| v1 | 0.9595652 | 0.8574224 | 0.7692310 | 0.0 | 0.0 |
| v5 | 0.9600000 | 0.1428571 | 0.7200000 | 0.0 | 0.0 |
| v6 | 0.9600000 | 0.2666667 | - | 0.0 | 0.0 |
| v9 | 0.9600000 | 0.1428571 | 0.8571430 | 0.0 | 0.0 |

---

## Iteration 4 — Retrained defensor with augmented negatives (F1)

| Run | Before F1 | After F1 | CM1 F1 | Strong attack F1 | CM2 F1 |
|---|---:|---:|---:|---:|---:|
| v1 | 0.9595652 | 0.8574224 | 0.8148150 | - | - |
| v5 | 0.9600000 | 0.1428571 | 0.7692310 | - | - |
| v6 | 0.9600000 | 0.2666667 | - | - | - |
| v9 | 0.9600000 | 0.1428571 | 0.7692310 | - | - |

---

## Iteration 5 — Stronger attacker simulation (attack_success_rate=0.85, def_proba_delta=-0.7) (F1)

| Run | Before F1 | After F1 | CM1 F1 | Strong attack F1 | CM2 F1 |
|---|---:|---:|---:|---:|---:|
| v1 | 0.9595652 | 0.8574224 | 0.8148150 | 0.0 | 0.0 |
| v5 | 0.9600000 | 0.1428571 | 0.7692310 | 0.0 | 0.0 |
| v6 | 0.9600000 | 0.2666667 | - | 0.0 | 0.0 |
| v9 | 0.9600000 | 0.1428571 | 0.7692310 | 0.0 | 0.0 |

---

## Iteration 6 — Weaker attacker simulation (attack_success_rate=0.3, def_proba_delta=-0.2) (F1)

| Run | Before F1 | After F1 | CM1 F1 | Strong attack F1 | CM2 F1 |
|---|---:|---:|---:|---:|---:|
| v1 | 0.9595652 | 0.8574224 | 0.8148150 | 0.0 | 0.7692310 |
| v5 | 0.9600000 | 0.1428571 | 0.7692310 | 0.0 | 0.7200000 |
| v6 | 0.9600000 | 0.2666667 | - | 0.0 | 0.0 |
| v9 | 0.9600000 | 0.1428571 | 0.8571430 | 0.0 | 0.7692310 |

---

References
- `experiments/per_run_evasion_aggregated_from_agg.csv`
- `experiments/per_run_evasion_with_cm.csv`
- Iteration reports in `experiments/defensor_report_v1-v10*.md`
- `experiments/defensor_third_iter_metrics.json`

Per-run attack descriptions

- `v1`: mixed protocol campaign — credential bruteforce against the MQTT broker (`attack_auth_bruteforce`), high-rate MQTT publishing (`attack_high_rate_pub`), various MQTT spoof/replay scenarios (`attack_mqtt_spoof`, `attack_mqtt_replay`, `attack_network_wide_mqtt_spoof`) and several Modbus manipulations (`attack_modbus_spoof`, `attack_modbus_replay`, `attack_modbus_corrupt`). The `attack_auth_bruteforce` traces are notable for producing the largest immediate drop in detection metrics.
- `v5`: network-distributed MQTT spoofing (`attack_network_wide_mqtt_spoof`) — coordinated spoofed publishes across replica targets to impersonate sensors and replace windows used by the ADS.
- `v6`: protocol spoofing plus adversarial feature attacks — `attack_network_wide_mqtt_spoof` was used during live traffic tests, and gradient-based adversarial examples (GB‑MIFGSM runs: `gb_mifgsm_*`) were generated against the Random Forest detector to produce adversarial feature vectors logged in `offensive_dt_adversarial_log.jsonl`.
- `v9`: Modbus replay-driven evasion (`attack_modbus_replay`) — replayed Modbus write sequences to change device register states; GB‑MIFGSM adversarial runs were also present in the run directory to evaluate feature-space evasion.
