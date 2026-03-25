
Run-live evasion batch pipeline

1. Ensure mitigator is running and reachable at http://127.0.0.1:8080
2. Activate the python venv: `source .venv/bin/activate`
3. Execute: `python scripts/run_batch_evasion.py`

Outputs:
- `experiments/run_live_evasion_v2..v10/` — per-run artifacts, adversarial logs, impact summaries.
- Per-run CSVs and Markdown reports (if `scripts/generate_reports_from_run.py` exists).
