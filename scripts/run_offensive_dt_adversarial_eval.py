#!/usr/bin/env python3
import argparse
import json
import os
import sys


def _repo_root():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def main():
    p = argparse.ArgumentParser(description='Run offensive-DT constrained MI-FGSM campaign and report impact')
    p.add_argument('--run-dir', default='experiments/run_live_v2')
    p.add_argument('--mitigator', default='http://127.0.0.1:8082')
    p.add_argument('--max-windows', type=int, default=200)
    p.add_argument('--eps', type=float, default=0.3, help="Perturbation magnitude")
    p.add_argument('--alpha', type=float, default=0.05, help="Step size")
    p.add_argument('--steps', type=int, default=10, help="Number of iterations")
    p.add_argument('--momentum', type=float, default=0.9)
    p.add_argument('--fd-eps', type=float, default=0.02)
    p.add_argument('--rel-clip', type=float, default=0.2)
    p.add_argument('--max-features', type=int, default=12)
    p.add_argument('--timeout', type=int, default=10)
    p.add_argument('--dry-run', action='store_true', default=False, help='If set, run in dry-run mode (no perturbations)')
    args = p.parse_args()

    root = _repo_root()
    if root not in sys.path:
        sys.path.insert(0, root)

    from services.simulation.offensive_dt import AttackConfig, run_offensive_campaign

    cfg = AttackConfig(
        eps=args.eps,
        alpha=args.alpha,
        steps=args.steps,
        momentum=args.momentum,
        fd_eps=args.fd_eps,
        rel_clip=args.rel_clip,
        max_features=args.max_features,
    )
    summary = run_offensive_campaign(
        run_dir=args.run_dir,
        mitigator_url=args.mitigator,
        max_windows=args.max_windows,
        timeout=args.timeout,
        cfg=cfg,
        dry_run=args.dry_run,
    )

    print(json.dumps(summary, indent=2))
    impact = summary.get('impact', {})
    print('--- offensive-dt impact (compact) ---')
    print('windows_total:', impact.get('windows_total'))
    print('baseline_alert_rate:', impact.get('baseline_alert_rate'))
    print('adversarial_alert_rate:', impact.get('adversarial_alert_rate'))
    print('evasion_rate_given_alert:', impact.get('evasion_rate_given_alert'))
    print('estimated_unmitigated_window_increase:', impact.get('estimated_unmitigated_window_increase'))
    print('mean_score_drop:', impact.get('mean_score_drop'))


if __name__ == '__main__':
    main()
