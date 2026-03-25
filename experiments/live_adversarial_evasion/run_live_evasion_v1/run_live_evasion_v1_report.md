# Run Live Evasion v1 — Summary Report

## Baseline detection metrics
| metric | value |
|---:|---|
| precision | 0.9230769230769231 |
| recall | 1.0 |
| f1 | 0.96 |
| threshold | 0.02 |
| n_windows | 114 |

## Evasion sweep summary
Columns: `eps`, `replaced` (# windows modified), `precision_before`, `recall_before`, `f1_before`, `precision_after`, `recall_after`, `f1_after`.

| eps | replaced | precision_before | recall_before | f1_before | precision_after | recall_after | f1_after | impact_json | adv_log |
|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| 0.015 | 12 | 0.9231 | 1.0000 | 0.9600 | 0.5000 | 0.0833 | 0.1429 | `gb_mifgsm_eps0p015_impact.json` | `gb_mifgsm_eps0p015_adversarial_log.jsonl` |
| 0.018 | 12 | 0.9231 | 1.0000 | 0.9600 | 0.5000 | 0.0833 | 0.1429 | `gb_mifgsm_eps0p018_impact.json` | `gb_mifgsm_eps0p018_adversarial_log.jsonl` |
| 0.021 | 12 | 0.9231 | 1.0000 | 0.9600 | 0.5000 | 0.0833 | 0.1429 | `gb_mifgsm_eps0p021_impact.json` | `gb_mifgsm_eps0p021_adversarial_log.jsonl` |
| 0.024 | 12 | 0.9231 | 1.0000 | 0.9600 | 0.5000 | 0.0833 | 0.1429 | `gb_mifgsm_eps0p024_impact.json` | `gb_mifgsm_eps0p024_adversarial_log.jsonl` |
| 0.027 | 12 | 0.9231 | 1.0000 | 0.9600 | 0.5000 | 0.0833 | 0.1429 | `gb_mifgsm_eps0p027_impact.json` | `gb_mifgsm_eps0p027_adversarial_log.jsonl` |
| 0.03 | 12 | 0.9231 | 1.0000 | 0.9600 | 0.5000 | 0.0833 | 0.1429 | `gb_mifgsm_eps0p03_impact.json` | `gb_mifgsm_eps0p03_adversarial_log.jsonl` |

## Per-eps detailed JSON snippets
### eps = 0.015
```json
{
  "eps": 0.015,
  "replaced": 12,
  "precision_before": 0.9230769230769231,
  "recall_before": 1.0,
  "f1_before": 0.96,
  "precision_after": 0.5,
  "recall_after": 0.08333333333333333,
  "f1_after": 0.14285714285714285
}
```
### eps = 0.018
```json
{
  "eps": 0.018,
  "replaced": 12,
  "precision_before": 0.9230769230769231,
  "recall_before": 1.0,
  "f1_before": 0.96,
  "precision_after": 0.5,
  "recall_after": 0.08333333333333333,
  "f1_after": 0.14285714285714285
}
```
### eps = 0.021
```json
{
  "eps": 0.021,
  "replaced": 12,
  "precision_before": 0.9230769230769231,
  "recall_before": 1.0,
  "f1_before": 0.96,
  "precision_after": 0.5,
  "recall_after": 0.08333333333333333,
  "f1_after": 0.14285714285714285
}
```
### eps = 0.024
```json
{
  "eps": 0.024,
  "replaced": 12,
  "precision_before": 0.9230769230769231,
  "recall_before": 1.0,
  "f1_before": 0.96,
  "precision_after": 0.5,
  "recall_after": 0.08333333333333333,
  "f1_after": 0.14285714285714285
}
```
### eps = 0.027
```json
{
  "eps": 0.027,
  "replaced": 12,
  "precision_before": 0.9230769230769231,
  "recall_before": 1.0,
  "f1_before": 0.96,
  "precision_after": 0.5,
  "recall_after": 0.08333333333333333,
  "f1_after": 0.14285714285714285
}
```
### eps = 0.03
```json
{
  "eps": 0.03,
  "replaced": 12,
  "precision_before": 0.9230769230769231,
  "recall_before": 1.0,
  "f1_before": 0.96,
  "precision_after": 0.5,
  "recall_after": 0.08333333333333333,
  "f1_after": 0.14285714285714285
}
```

## Notes
- Attacks used: constrained MI-FGSM (black-box finite-difference score queries).
- Model artifacts loaded from `services/mitigator` (sklearn version mismatch warnings may appear).
- `replaced` indicates number of windows for which an `adv_score` was recorded and used to compute after-attack metrics.