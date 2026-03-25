# Defensor: Six-Iteration Overview (runs v1, v5, v6, v9)

This summary collects the key metrics for the six iterations performed on the auxiliar `defensor`. For each iteration we show the selected runs (`v1`, `v5`, `v6`, `v9`) with the following columns:
- Before attack: precision / recall / F1 (pre-attack baseline)
- After attack: precision / recall / F1 (post-attack, pre-countermeasure)
- CM1: precision / recall / F1 after the first countermeasure (defensor applied)
- Strong attack: precision / recall / F1 after a simulated stronger attack (if performed)
- CM2: precision / recall / F1 after re-applying the countermeasure following the stronger attack (if performed)

Use `-` for columns not present in that iteration.

---

## Iteration 1 — Initial defensor application

| Run | Before (P / R / F1) | After attack (P / R / F1) | CM1 (P / R / F1) | Strong attack | CM2 |
|---|---:|---:|---:|---:|---:|
| v1 | 0.9222756 / 1.0000000 / 0.9595652 | 0.8693910 / 0.8854167 / 0.8574224 | 0.4615385 / 1.0000000 / 0.6315789 | - | - |
| v5 | 0.9230769 / 1.0000000 / 0.9600000 | 0.5000000 / 0.0833333 / 0.1428571 | 0.4166667 / 0.8333333 / 0.5555556 | - | - |
| v6 | 0.9230769 / 1.0000000 / 0.9600000 | 0.6666667 / 0.1666667 / 0.2666667 | N/A | - | - |
| v9 | 0.9230769 / 1.0000000 / 0.9600000 | 0.5000000 / 0.0833333 / 0.1428571 | 0.4615385 / 1.0000000 / 0.6315789 | - | - |

---

## Iteration 2 — Threshold tuning / early defensor tuning

| Run | Before (P / R / F1) | After attack (P / R / F1) | CM1 (P / R / F1) | Strong attack | CM2 |
|---|---:|---:|---:|---:|---:|
| v1 | 0.9222756 / 1.0000000 / 0.9595652 | 0.8693910 / 0.8854167 / 0.8574224 | 0.7142860 / 0.8333330 / 0.7692310 | - | - |
| v5 | 0.9230769 / 1.0000000 / 0.9600000 | 0.5000000 / 0.0833333 / 0.1428571 | 0.6923080 / 0.7500000 / 0.7200000 | - | - |
| v6 | 0.9230769 / 1.0000000 / 0.9600000 | 0.6666667 / 0.1666667 / 0.2666667 | N/A | - | - |
| v9 | 0.9230769 / 1.0000000 / 0.9600000 | 0.5000000 / 0.0833333 / 0.1428571 | 0.7500000 / 1.0000000 / 0.8571430 | - | - |

---

## Iteration 3 — Simulated enhanced attack (attack_success_rate=0.6, def_proba_delta=-0.4)

| Run | Before (P / R / F1) | After attack (P / R / F1) | CM1 (P / R / F1) | Strong attack (P / R / F1) | CM2 (P / R / F1) |
|---|---:|---:|---:|---:|---:|
| v1 | 0.9222756 / 1.0000000 / 0.9595652 | 0.8693910 / 0.8854167 / 0.8574224 | 0.7142860 / 0.8333330 / 0.7692310 | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 / 0.0 |
| v5 | 0.9230769 / 1.0000000 / 0.9600000 | 0.5000000 / 0.0833333 / 0.1428571 | 0.6923080 / 0.7500000 / 0.7200000 | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 / 0.0 |
| v6 | 0.9230769 / 1.0000000 / 0.9600000 | 0.6666667 / 0.1666667 / 0.2666667 | N/A | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 / 0.0 |
| v9 | 0.9230769 / 1.0000000 / 0.9600000 | 0.5000000 / 0.0833333 / 0.1428571 | 0.7500000 / 1.0000000 / 0.8571430 | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 / 0.0 |

---

## Iteration 4 — Retrained defensor with augmented negatives

| Run | Before (P / R / F1) | After attack (P / R / F1) | CM1 (P / R / F1) | Strong attack | CM2 |
|---|---:|---:|---:|---:|---:|
| v1 | 0.9222756 / 1.0000000 / 0.9595652 | 0.8693910 / 0.8854167 / 0.8574224 | 0.7333330 / 0.9166670 / 0.8148150 | - | - |
| v5 | 0.9230769 / 1.0000000 / 0.9600000 | 0.5000000 / 0.0833333 / 0.1428571 | 0.7142860 / 0.8333330 / 0.7692310 | - | - |
| v6 | 0.9230769 / 1.0000000 / 0.9600000 | 0.6666667 / 0.1666667 / 0.2666667 | N/A | - | - |
| v9 | 0.9230769 / 1.0000000 / 0.9600000 | 0.5000000 / 0.0833333 / 0.1428571 | 0.7142860 / 0.8333330 / 0.7692310 | - | - |

---

## Iteration 5 — Stronger attacker simulation (attack_success_rate=0.85, def_proba_delta=-0.7)

| Run | Before (P / R / F1) | After attack (P / R / F1) | CM1 (P / R / F1) | Strong attack (P / R / F1) | CM2 (P / R / F1) |
|---|---:|---:|---:|---:|---:|
| v1 | 0.9222756 / 1.0000000 / 0.9595652 | 0.8693910 / 0.8854167 / 0.8574224 | 0.7333330 / 0.9166670 / 0.8148150 | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 / 0.0 |
| v5 | 0.9230769 / 1.0000000 / 0.9600000 | 0.5000000 / 0.0833333 / 0.1428571 | 0.7142860 / 0.8333330 / 0.7692310 | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 / 0.0 |
| v6 | 0.9230769 / 1.0000000 / 0.9600000 | 0.6666667 / 0.1666667 / 0.2666667 | N/A | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 / 0.0 |
| v9 | 0.9230769 / 1.0000000 / 0.9600000 | 0.5000000 / 0.0833333 / 0.1428571 | 0.7142860 / 0.8333330 / 0.7692310 | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 / 0.0 |

---

## Iteration 6 — Weaker attacker simulation (attack_success_rate=0.3, def_proba_delta=-0.2)

| Run | Before (P / R / F1) | After attack (P / R / F1) | CM1 (P / R / F1) | Strong attack (P / R / F1) | CM2 (P / R / F1) |
|---|---:|---:|---:|---:|---:|
| v1 | 0.9222756 / 1.0000000 / 0.9595652 | 0.8693910 / 0.8854167 / 0.8574224 | 0.7333330 / 0.9166670 / 0.8148150 | 0.0 / 0.0 / 0.0 | 0.7142860 / 0.8333330 / 0.7692310 |
| v5 | 0.9230769 / 1.0000000 / 0.9600000 | 0.5000000 / 0.0833333 / 0.1428571 | 0.7142860 / 0.8333330 / 0.7692310 | 0.0 / 0.0 / 0.0 | 0.6923080 / 0.7500000 / 0.7200000 |
| v6 | 0.9230769 / 1.0000000 / 0.9600000 | 0.6666667 / 0.1666667 / 0.2666667 | N/A | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 / 0.0 |
| v9 | 0.9230769 / 1.0000000 / 0.9600000 | 0.5000000 / 0.0833333 / 0.1428571 | 0.7142860 / 1.0000000 / 0.8571430 | 0.0 / 0.0 / 0.0 | 0.7142860 / 0.8333330 / 0.7692310 |

---

References
- Per-run pre/post CSV: `experiments/per_run_evasion_aggregated_from_agg.csv`
- Per-iteration reports: `experiments/defensor_report_v1-v10*.md`
- Simulated-attack metrics JSON: `experiments/defensor_third_iter_metrics.json`
