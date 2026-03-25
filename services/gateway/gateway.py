import os
import json
import time
import threading
from urllib.parse import urlparse

import paho.mqtt.client as mqtt
from pymodbus.client.sync import ModbusTcpClient

MQTT_BROKER = os.getenv("MQTT_BROKER", "mosquitto")
MAPPING = os.getenv("MODBUS_MAPPING", "{}")

try:
    MODBUS_MAP = json.loads(MAPPING)
except Exception:
    MODBUS_MAP = {}

def map_sensor_to_modbus(sensor_id: str):
    # Look up mapping; fall back to simple round-robin if missing
    if sensor_id in MODBUS_MAP:
        hostport = MODBUS_MAP[sensor_id]
        host, port = hostport.split(":")
        return host, int(port)
    # fallback algorithm: map by sensor id
    n = int(sensor_id)
    idx = (n - 1) // 3 + 1
    return f"modbus_slave_{idx}", 1501 + idx

def on_connect(client, userdata, flags, rc):
    print("gateway connected to mqtt broker", MQTT_BROKER, rc)
    client.subscribe("sensors/+/telemetry")

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        sensor_id = str(payload.get("sensor_id"))
        value = payload.get("value")
        if sensor_id is None or value is None:
            return
        host, port = map_sensor_to_modbus(sensor_id)
        print(f"Gateway mapping sensor {sensor_id} -> {host}:{port} value={value}")
        # connect to modbus and write to register (scale to int)
        scaled = int(float(value) * 10)
        client_mod = ModbusTcpClient(host, port=port)
        if client_mod.connect():
            client_mod.write_register(address=int(sensor_id), value=scaled, unit=1)
            client_mod.close()
        else:
            print(f"Failed to connect to modbus {host}:{port}")
    except Exception as e:
        print("gateway error handling message:", e)

def run():
    client = mqtt.Client(client_id="gateway")
    client.on_connect = on_connect
    client.on_message = on_message
    print("Gateway connecting to MQTT broker", MQTT_BROKER)
    client.connect(MQTT_BROKER, 1883)
    client.loop_forever()

if __name__ == '__main__':
    run()
