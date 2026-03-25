import os
import time
import json
import random
from datetime import datetime

import paho.mqtt.client as mqtt

SENSOR_ID = int(os.getenv("SENSOR_ID", "1"))
MQTT_BROKER = os.getenv("MQTT_BROKER", "mosquitto")
INTERVAL = int(os.getenv("INTERVAL", "5"))

TOPIC = f"sensors/{SENSOR_ID}/telemetry"
CONTROL_TOPIC = f"emulation/sensor/{SENSOR_ID}/control"

client = mqtt.Client(client_id=f"sensor-{SENSOR_ID}")

state = {
    "interval": INTERVAL,
    "override": None,
}

def on_connect(client, userdata, flags, rc):
    print(f"sensor {SENSOR_ID} connected to broker {MQTT_BROKER} with rc={rc}")
    # subscribe to its control topic so an emulator can change behavior
    client.subscribe(CONTROL_TOPIC)

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        if "interval" in payload:
            new_i = int(payload["interval"])
            state["interval"] = new_i
            print(f"sensor {SENSOR_ID} interval set to {new_i} via control")
        if "override" in payload:
            state["override"] = payload["override"]
            print(f"sensor {SENSOR_ID} override set to {state['override']}")
        if payload.get("clear_override"):
            state["override"] = None
            print(f"sensor {SENSOR_ID} override cleared")
    except Exception as e:
        print("sensor control message error:", e)

client.on_connect = on_connect
client.on_message = on_message

print(f"Connecting to MQTT broker {MQTT_BROKER}:1883")
client.connect(MQTT_BROKER, 1883)
client.loop_start()

try:
    while True:
        if state["override"] is not None:
            value = float(state["override"])
        else:
            value = round(random.uniform(10.0, 100.0), 2)

        payload = {
            "sensor_id": SENSOR_ID,
            "ts": datetime.utcnow().isoformat() + "Z",
            "value": value,
        }
        client.publish(TOPIC, json.dumps(payload))
        print(f"Published to {TOPIC}: {payload} (interval={state['interval']})")
        time.sleep(state["interval"])
except KeyboardInterrupt:
    client.loop_stop()
    client.disconnect()
