import os
import json
import time
import random
import threading

import paho.mqtt.client as mqtt

# Emulator adapted to run inside the isolated environment.
# It connects to the isolated broker (service name) and simulates external inputs
# and control messages for sensors.
MQTT_BROKER = os.getenv('MQTT_BROKER', 'localhost')
MQTT_PORT = int(os.getenv('MQTT_PORT', '1883'))

client = mqtt.Client(client_id='emulator')

# Event used to wait for successful connection (helps avoid race where loop
# appears started but the connection never completes because the broker is
# unreachable). The main loop will wait up to CONNECT_TIMEOUT seconds.
connected = threading.Event()
CONNECT_TIMEOUT = 10

def on_connect(c, userdata, flags, rc):
    print('emulator connected to broker', MQTT_BROKER, rc)
    # rc == 0 means success
    if rc == 0:
        connected.set()

client.on_connect = on_connect

def run():
    try:
        client.connect(MQTT_BROKER, MQTT_PORT)
    except Exception as e:
        print('emulator: connect() raised exception:', e)
        # still attempt to start loop so reconnect logic can run
    client.loop_start()
    print('Loop started; waiting for MQTT connection...')

    if not connected.wait(CONNECT_TIMEOUT):
        print(f"Warning: did not connect to broker within {CONNECT_TIMEOUT}s; continuing anyway")
    else:
        print('Emulator: MQTT connection established')
    try:
        while True:
            # Example behavior:
            # - every 30s send a control override to sensor 1
            # - publish a synthetic external telemetry occasionally
            print('emulator: setting override on sensor 1')
            client.publish('emulation/sensor/1/control', json.dumps({"override": 42.5}))
            time.sleep(10)
            print('emulator: clearing override on sensor 1')
            client.publish('emulation/sensor/1/control', json.dumps({"clear_override": True}))

            # publish additional synthetic telemetry to topic sensors/99/telemetry
            synthetic = {
                "sensor_id": 99,
                "ts": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                "value": round(random.uniform(0, 100), 2)
            }
            client.publish('sensors/99/telemetry', json.dumps(synthetic))
            print('emulator published synthetic telemetry', synthetic)

            time.sleep(20)
    except KeyboardInterrupt:
        pass
    finally:
        client.loop_stop()
        client.disconnect()

if __name__ == '__main__':
    run()
