# Defensor Report — Sixth Iteration (weaker attack)

This iteration simulates a weaker attack and reapplies the countermeasure to observe a slight drop in F1 compared to the first countermeasure.

Attack parameters used: `attack_success_rate=0.3`, `def_proba_delta=-0.2`.

Selected runs: `run_live_evasion_v1`, `run_live_evasion_v5`, `run_live_evasion_v6`, `run_live_evasion_v9`.

Results

- run_live_evasion_v1
  - Before attack — precision: 0.9222756410256412, recall: 1.0, f1: 0.9595652173913043
  - After attack — precision: 0.8693910256410258, recall: 0.8854166666666666, f1: 0.8574223602484472
  - After first countermeasure — precision: 0.733333, recall: 0.916667, f1: 0.814815
  - After weaker attack (simulated) — raw enhanced precision/recall/f1: 0.0 / 0.0 / 0.0 (no RF positives)
  - After second countermeasure (re-applied) — precision: 0.714286, recall: 0.833333, f1: 0.769231

- run_live_evasion_v5
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.5, recall: 0.0833333333333333, f1: 0.1428571428571428
  - After first countermeasure — precision: 0.714286, recall: 0.833333, f1: 0.769231
  - After weaker attack (simulated) — raw enhanced precision/recall/f1: 0.0 / 0.0 / 0.0
  - After second countermeasure (re-applied) — precision: 0.692308, recall: 0.75, f1: 0.72

- run_live_evasion_v6
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.6666666666666666, recall: 0.1666666666666666, f1: 0.2666666666666666
  - After first countermeasure — N/A (no adversarial feature vectors)
  - After weaker attack (simulated) — raw enhanced precision/recall/f1: 0.0 / 0.0 / 0.0
  - After second countermeasure (re-applied) — precision: 0.0, recall: 0.0, f1: 0.0

- run_live_evasion_v9
  - Before attack — precision: 0.9230769230769232, recall: 1.0, f1: 0.96
  - After attack — precision: 0.5, recall: 0.0833333333333333, f1: 0.1428571428571428
  - After first countermeasure — precision: 0.714286, recall: 1.0, f1: 0.857143
  - After weaker attack (simulated) — raw enhanced precision/recall/f1: 0.0 / 0.0 / 0.0
  - After second countermeasure (re-applied) — precision: 0.714286, recall: 0.833333, f1: 0.769231

Reproduction commands

```bash
# simulate weaker attack and reapply CM
.venv/bin/python3 scripts/iterate_defensor_attack.py --attack-success-rate 0.3 --def-proba-delta -0.2

# view results
cat experiments/defensor_third_iter_metrics.json | jq .
```

Note
- The weaker attack causes only a small reduction in post-CM F1 compared to the first countermeasure; exact amounts are in `experiments/defensor_third_iter_metrics.json`.

Attacks implemented

- `high_rate_publish` (MQTT, services/attacker/attacks.py): publish large volumes of telemetry quickly to overwhelm consumers and test rate-handling.
- `mqtt_replay` (MQTT, services/attacker/attacks.py): replay recorded MQTT PUBLISH events from a JSONL trace with original timing or scaled speed.
- `mqtt_spoof` (MQTT, services/attacker/attacks.py): publish fabricated sensor readings to target topics to impersonate sensors.
- `network_wide_mqtt_spoof` (MQTT, services/attacker/attacks.py): launch spoofed publishes across multiple target replicas to simulate distributed spoofing.
- `fuzz_publish` (MQTT, services/attacker/attacks.py): send malformed/oversized/binary payloads to exercise parsers and cause crashes or misbehavior.
- `mqtt_auth_bruteforce` (MQTT, services/attacker/attacks.py): attempt credential guesses against broker authentication to find valid logins.
- `modbus_replay` (Modbus, services/attacker/attacks.py): replay Modbus write sequences from a JSONL trace to reproduce prior malicious writes.
- `modbus_spoof` (Modbus, services/attacker/attacks.py): continuously write chosen values into Modbus registers to impersonate or override device state.
- `modbus_corrupt` (Modbus, services/attacker/attacks.py): write random/garbage register values in bulk to corrupt device state and induce faults.

Related helpers/orchestrators: `tools/pcap_to_mqtt_replay.py` (convert PCAP→JSONL for `mqtt_replay`) and `scripts/random_attack_runner.py` (attack orchestration).
