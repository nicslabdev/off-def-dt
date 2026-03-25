import os
import json
import time
import random
import threading
import traceback

import paho.mqtt.client as mqtt
from offensive_dt import AttackConfig, run_offensive_campaign

# Simulation service: a copy of the emulator behavior. It runs inside the isolated
# network and publishes control messages and synthetic telemetry for co-simulation.
MQTT_BROKER = os.getenv('MQTT_BROKER', 'localhost')
MQTT_PORT = int(os.getenv('MQTT_PORT', '1883'))

OFFENSIVE_DT_ENABLED = str(os.getenv('OFFENSIVE_DT_ENABLED', '0')).strip().lower() in ('1', 'true', 'yes', 'y', 'on')
OFFENSIVE_DT_RUN_DIR = os.getenv('OFFENSIVE_DT_RUN_DIR', 'experiments/run_live_v2')
OFFENSIVE_DT_MITIGATOR = os.getenv('OFFENSIVE_DT_MITIGATOR', 'http://127.0.0.1:8082')
OFFENSIVE_DT_INTERVAL_SECONDS = int(os.getenv('OFFENSIVE_DT_INTERVAL_SECONDS', '0'))
OFFENSIVE_DT_MAX_WINDOWS = int(os.getenv('OFFENSIVE_DT_MAX_WINDOWS', '200'))
OFFENSIVE_DT_TIMEOUT = int(os.getenv('OFFENSIVE_DT_TIMEOUT', '10'))
OFFENSIVE_DT_EPS = float(os.getenv('OFFENSIVE_DT_EPS', '0.12'))
OFFENSIVE_DT_ALPHA = float(os.getenv('OFFENSIVE_DT_ALPHA', '0.03'))
OFFENSIVE_DT_STEPS = int(os.getenv('OFFENSIVE_DT_STEPS', '6'))
OFFENSIVE_DT_MOMENTUM = float(os.getenv('OFFENSIVE_DT_MOMENTUM', '0.9'))
OFFENSIVE_DT_FD_EPS = float(os.getenv('OFFENSIVE_DT_FD_EPS', '0.02'))
OFFENSIVE_DT_REL_CLIP = float(os.getenv('OFFENSIVE_DT_REL_CLIP', '0.2'))
OFFENSIVE_DT_MAX_FEATURES = int(os.getenv('OFFENSIVE_DT_MAX_FEATURES', '12'))
OFFENSIVE_DT_DRY_RUN = str(os.getenv('OFFENSIVE_DT_DRY_RUN', '1')).strip().lower() in ('1', 'true', 'yes', 'y', 'on')

client = mqtt.Client(client_id='simulation')

def on_connect(c, userdata, flags, rc):
    print('simulation connected to broker', MQTT_BROKER, rc)

client.on_connect = on_connect


def _run_offensive_dt_loop():
    cfg = AttackConfig(
        eps=OFFENSIVE_DT_EPS,
        alpha=OFFENSIVE_DT_ALPHA,
        steps=OFFENSIVE_DT_STEPS,
        momentum=OFFENSIVE_DT_MOMENTUM,
        fd_eps=OFFENSIVE_DT_FD_EPS,
        rel_clip=OFFENSIVE_DT_REL_CLIP,
        max_features=OFFENSIVE_DT_MAX_FEATURES,
    )
    while True:
        try:
            summary = run_offensive_campaign(
                run_dir=OFFENSIVE_DT_RUN_DIR,
                mitigator_url=OFFENSIVE_DT_MITIGATOR,
                max_windows=OFFENSIVE_DT_MAX_WINDOWS,
                timeout=OFFENSIVE_DT_TIMEOUT,
                cfg=cfg,
                dry_run=OFFENSIVE_DT_DRY_RUN,
            )
            print('offensive-dt summary:', json.dumps(summary.get('impact', {}), indent=2))
        except Exception as e:
            print('offensive-dt loop failed:', e)
            traceback.print_exc()

        if OFFENSIVE_DT_INTERVAL_SECONDS <= 0:
            break
        time.sleep(OFFENSIVE_DT_INTERVAL_SECONDS)

def run():
    try:
        client.connect(MQTT_BROKER, MQTT_PORT)
    except Exception as e:
        print('simulation: connect() raised exception:', e)
    client.loop_start()
    print('simulation loop started')

    if OFFENSIVE_DT_ENABLED:
        print('offensive-dt enabled: run_dir=', OFFENSIVE_DT_RUN_DIR, 'mitigator=', OFFENSIVE_DT_MITIGATOR)
        t = threading.Thread(target=_run_offensive_dt_loop, daemon=True)
        t.start()

    try:
        while True:
            # publish synthetic telemetry only (no control capabilities)
            for sid in (98, 99):
                synthetic = {
                    "sensor_id": sid,
                    "ts": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    "value": round(random.uniform(0, 100), 2)
                }
                client.publish(f'sensors/{sid}/telemetry', json.dumps(synthetic))
                print('simulation published', synthetic)
            # sleep between cycles
            time.sleep(12)
    except KeyboardInterrupt:
        pass
    finally:
        client.loop_stop()
        client.disconnect()

if __name__ == '__main__':
    run()
