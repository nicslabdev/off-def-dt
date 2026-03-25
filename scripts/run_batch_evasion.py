#!/usr/bin/env python3
"""Batch-run live evasion experiments (run_live_evasion_v2..v10).

Creates per-run directories, picks a random attack, runs constrained MIFGSM
at several epsilons, computes baseline and post-attack metrics, and
writes per-attack/per-protocol CSVs and Markdown reports.

Usage: python scripts/run_batch_evasion.py
"""
import os
import sys
import glob
import json
import random
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENTS = ROOT / 'experiments'
MITIGATOR = 'http://127.0.0.1:8080'
EPS_LIST = [0.015, 0.018, 0.021, 0.024, 0.027, 0.03]


def find_attack_pool():
    pool = []
    for d in EXPERIMENTS.glob('run_live_*'):
        # skip generated evasion runs to avoid picking files that will be removed
        if 'evasion' in d.name:
            continue
        if not d.is_dir():
            continue
        for p in d.glob('attack_*.csv'):
            pool.append(p)
    # also include top-level pcaps/converted attacks if any
    for p in (ROOT / 'pcaps').glob('attack_*.csv'):
        pool.append(p)
    return list(dict.fromkeys(pool))


def pick_baseline():
    # prefer run_live_v1 baseline
    p = EXPERIMENTS / 'run_live_v1' / 'baseline_replica.csv'
    if p.exists():
        return p
    # fallback: any baseline_replica.csv
    for f in EXPERIMENTS.rglob('baseline_replica.csv'):
        return Path(f)
    raise RuntimeError('No baseline_replica.csv found in experiments')


def run_attack_for_eps(run_dir, eps):
    # run CLI without --out-jsonl/--out-summary (not accepted by older CLI),
    # then rename default outputs to eps-specific names
    cmd = [
        sys.executable,
        str(ROOT / 'scripts' / 'run_offensive_dt_adversarial_eval.py'),
        '--run-dir', str(run_dir),
        '--mitigator', MITIGATOR,
        '--eps', str(eps),
    ]
    print('Running attack:', ' '.join(cmd))
    subprocess.check_call(cmd)
    default_jsonl = run_dir / 'offensive_dt_adversarial_log.jsonl'
    default_summary = run_dir / 'offensive_dt_impact.json'
    out_jsonl = run_dir / f'gb_mifgsm_eps{str(eps).replace(".","p")}_adversarial_log.jsonl'
    out_summary = run_dir / f'gb_mifgsm_eps{str(eps).replace(".","p")}_impact.json'
    if default_jsonl.exists():
        default_jsonl.rename(out_jsonl)
    if default_summary.exists():
        default_summary.rename(out_summary)
    return out_jsonl, out_summary


def ensure_mitigator_up():
    import requests
    try:
        r = requests.get(MITIGATOR + '/config', timeout=5)
        r.raise_for_status()
        print('Mitigator config:', r.json())
        return True
    except Exception as e:
        print('Mitigator not reachable at', MITIGATOR, e)
        return False


def make_run(n, attack_path, baseline_path):
    run_dir = EXPERIMENTS / f'run_live_evasion_v{n}'
    if run_dir.exists():
        print('Removing existing', run_dir)
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    # copy baseline and attack
    shutil.copy2(baseline_path, run_dir / baseline_path.name)
    shutil.copy2(attack_path, run_dir / attack_path.name)
    # compute baseline metrics and save (best-effort via calling attack script with eps=0)
    # run attacks for each eps
    for eps in EPS_LIST:
        run_attack_for_eps(run_dir, eps)

    # generate per-attack/per-protocol summaries (reuse earlier utility in repo)
    # call small python inline that writes CSVs and md (same logic used interactively)
    gen = ROOT / 'scripts' / 'generate_reports_from_run.py'
    if gen.exists():
        subprocess.check_call([sys.executable, str(gen), str(run_dir)])
    else:
        print('report generator not found, skipping detailed CSV/MD for', run_dir)


def main():
    if not ensure_mitigator_up():
        print('Please start the mitigator at', MITIGATOR)
        return
    pool = find_attack_pool()
    if not pool:
        print('No attack files found in experiments; aborting')
        return
    baseline = pick_baseline()

    for n in range(2, 11):
        attack = random.choice(pool)
        print(f'Creating run_live_evasion_v{n} with attack {attack.name}')
        make_run(n, attack, baseline)

    # write pipeline README
    md = EXPERIMENTS / 'run_live_evasion_pipeline.md'
    md.write_text(
        """
Run-live evasion batch pipeline

1. Ensure mitigator is running and reachable at http://127.0.0.1:8080
2. Activate the python venv: `source .venv/bin/activate`
3. Execute: `python scripts/run_batch_evasion.py`

Outputs:
- `experiments/run_live_evasion_v2..v10/` — per-run artifacts, adversarial logs, impact summaries.
- Per-run CSVs and Markdown reports (if `scripts/generate_reports_from_run.py` exists).
"""
    )
    print('Wrote', md)


if __name__ == '__main__':
    main()
