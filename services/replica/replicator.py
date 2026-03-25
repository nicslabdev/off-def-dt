import os
import time
import threading
import json
import traceback

import paho.mqtt.client as mqtt
from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes
from pymodbus.client.sync import ModbusTcpClient

# Replicator: one-way mirror from the isolated (source) broker to the replica (destination) broker.
# Configuration via environment variables:
# - SRC_BROKER (default: mosquitto_isolated)
# - SRC_PORT (default: 1883)
# - DST_BROKER (default: replica_mosquitto)
# - DST_PORT (default: 1883)
# - TOPICS (comma-separated MQTT topic filters, default: sensors/#)

SRC_BROKER = os.getenv('SRC_BROKER', 'mosquitto_isolated')
SRC_PORT = int(os.getenv('SRC_PORT', '1883'))
DST_BROKER = os.getenv('DST_BROKER', 'replica_mosquitto')
DST_PORT = int(os.getenv('DST_PORT', '1883'))
TOPICS = os.getenv('TOPICS', 'sensors/#')
REPL_ID = os.getenv('REPL_ID', 'replicator')
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL', '5'))
MIRROR_MODE = os.getenv('MIRROR_MODE', 'src2dst')  # options: src2dst, dst2src, both, disabled
CONFLICT_POLICY = os.getenv('CONFLICT_POLICY', 'replica')  # 'replica' or 'source'

# Modbus source and replica mapping. Format: host:port pairs comma separated.
# Defaults map the three modbus slaves to replica ports.
MODBUS_SRC = os.getenv('MODBUS_SRC', 'modbus_slave_1:1502,modbus_slave_2:1503,modbus_slave_3:1504')
MODBUS_DST = os.getenv('MODBUS_DST', 'replica_modbus_slave_1:2502,replica_modbus_slave_2:2503,replica_modbus_slave_3:2504')

def parse_hostport_list(s):
    pairs = []
    for item in s.split(','):
        item = item.strip()
        if not item:
            continue
        if ':' in item:
            host, port = item.split(':', 1)
            pairs.append((host, int(port)))
        else:
            pairs.append((item, 502))
    return pairs

MODBUS_SRC_LIST = parse_hostport_list(MODBUS_SRC)
MODBUS_DST_LIST = parse_hostport_list(MODBUS_DST)

print(f"replicator starting: {SRC_BROKER}:{SRC_PORT} -> {DST_BROKER}:{DST_PORT}, topics={TOPICS}")

dst_client = mqtt.Client(client_id=f'replicator-dst-{REPL_ID}', protocol=mqtt.MQTTv5)
src_client = mqtt.Client(client_id=f'replicator-src-{REPL_ID}', protocol=mqtt.MQTTv5)

def on_dst_connect(c, userdata, flags, rc, properties=None):
    # properties is optional and present for MQTT v5 callbacks
    print('replicator: connected to dst broker', DST_BROKER, rc)


def on_dst_disconnect(c, userdata, rc, properties=None):
    # properties is optional and present for MQTT v5 callbacks
    print('replicator: disconnected from dst broker', DST_BROKER, rc)

def on_src_connect(c, userdata, flags, rc, properties=None):
    # properties is optional and present for MQTT v5 callbacks
    print('replicator: connected to src broker', SRC_BROKER, rc)
    # subscribe to configured topics
    for t in TOPICS.split(','):
        t = t.strip()
        if t:
            print('replicator: subscribing to', t)
            c.subscribe(t)

def has_replicated_marker(msg):
    try:
        props = getattr(msg, 'properties', None)
        if props and getattr(props, 'UserProperty', None):
            for k, v in props.UserProperty:
                if k == 'replicated-by':
                    return True
    except Exception:
        pass
    return False


def forward_message(to_client, msg):
    try:
        # attach replication marker using MQTT v5 properties
        props = Properties(PacketTypes.PUBLISH)
        props.UserProperty = [('replicated-by', REPL_ID)]
        print(f"replicator: forwarding topic={msg.topic} len={len(msg.payload)} to {to_client._client_id}")
        to_client.publish(msg.topic, payload=msg.payload, qos=getattr(msg, 'qos', 0), properties=props)
    except Exception:
        print('replicator: error forwarding message')
        traceback.print_exc()


def on_src_message(client, userdata, msg):
    try:
        # don't forward messages that already carry a replication marker
        if has_replicated_marker(msg):
            # skip to avoid loops
            return
        # forward only when modes allow
        if MIRROR_MODE in ('src2dst', 'both'):
            forward_message(dst_client, msg)
    except Exception:
        print('replicator: error in src->dst')
        traceback.print_exc()


def on_dst_message(client, userdata, msg):
    try:
        if has_replicated_marker(msg):
            return
        # forward back only when modes allow
        if MIRROR_MODE in ('dst2src', 'both'):
            forward_message(src_client, msg)
    except Exception:
        print('replicator: error in dst->src')
        traceback.print_exc()

dst_client.on_connect = on_dst_connect
src_client.on_connect = on_src_connect
src_client.on_message = on_src_message
dst_client.on_message = on_dst_message

def on_src_disconnect(c, userdata, rc, properties=None):
    # properties is optional and present for MQTT v5 callbacks
    print('replicator: disconnected from src broker', SRC_BROKER, rc)

dst_client.on_disconnect = on_dst_disconnect
src_client.on_disconnect = on_src_disconnect

def run():
    try:
        # tune keepalive and reconnect behaviour to avoid broker timeouts
        dst_client.reconnect_delay_set(min_delay=1, max_delay=120)
        dst_client.connect(DST_BROKER, DST_PORT, keepalive=120)
    except Exception as e:
        print('replicator: dst connect exception', e)
    try:
        src_client.reconnect_delay_set(min_delay=1, max_delay=120)
        src_client.connect(SRC_BROKER, SRC_PORT, keepalive=120)
    except Exception as e:
        print('replicator: src connect exception', e)

    dst_client.loop_start()
    src_client.loop_start()

    # start modbus sync thread with bidirectional sync and simple conflict handling
    def modbus_sync_loop():
        # last_snapshot keeps the last-seen register list per pair (from last sync)
        last_snapshot = [None] * len(MODBUS_SRC_LIST)

        def read_regs(host, port):
            client_mb = ModbusTcpClient(host, port=port)
            try:
                if not client_mb.connect():
                    print(f"replicator: failed to connect to modbus {host}:{port}")
                    client_mb.close()
                    return None
                rr = client_mb.read_holding_registers(0, 100, unit=1)
                client_mb.close()
                if not rr or getattr(rr, 'registers', None) is None:
                    return None
                return list(rr.registers)
            except Exception:
                print(f"replicator: exception reading modbus {host}:{port}")
                traceback.print_exc()
                try:
                    client_mb.close()
                except Exception:
                    pass
                return None

        def write_regs(host, port, regs):
            client_mb = ModbusTcpClient(host, port=port)
            try:
                if not client_mb.connect():
                    print(f"replicator: failed to connect to modbus for write {host}:{port}")
                    client_mb.close()
                    return False
                CHUNK = 100
                success = True
                for i in range(0, len(regs), CHUNK):
                    chunk = regs[i:i+CHUNK]
                    wr = client_mb.write_registers(i, chunk, unit=1)
                    if getattr(wr, 'isError', lambda: False)():
                        print(f"replicator: error writing registers to {host}:{port} at {i}")
                        success = False
                client_mb.close()
                return success
            except Exception:
                print(f"replicator: exception writing modbus {host}:{port}")
                traceback.print_exc()
                try:
                    client_mb.close()
                except Exception:
                    pass
                return False

        while True:
            try:
                for idx, src in enumerate(MODBUS_SRC_LIST):
                    try:
                        dst = MODBUS_DST_LIST[idx] if idx < len(MODBUS_DST_LIST) else None
                        if not dst:
                            continue
                        src_host, src_port = src
                        dst_host, dst_port = dst

                        regs_src = read_regs(src_host, src_port) or []
                        regs_dst = read_regs(dst_host, dst_port) or []

                        # normalize lengths
                        n = max(len(regs_src), len(regs_dst))
                        regs_src += [0] * (n - len(regs_src))
                        regs_dst += [0] * (n - len(regs_dst))

                        prev = last_snapshot[idx]
                        if prev is None:
                            # initial sync: prefer source->dst
                            if regs_src:
                                if write_regs(dst_host, dst_port, regs_src):
                                    last_snapshot[idx] = list(regs_src)
                                    print(f"replicator: initial sync src->dst for {src_host}->{dst_host}")
                                else:
                                    last_snapshot[idx] = list(regs_src)
                            else:
                                last_snapshot[idx] = list(regs_dst)
                            continue

                        # detect changes relative to prev
                        src_changed = regs_src != prev
                        dst_changed = regs_dst != prev

                        if not src_changed and not dst_changed:
                            # nothing changed
                            continue

                        if src_changed and not dst_changed:
                            # source changed -> push to dst
                            if write_regs(dst_host, dst_port, regs_src):
                                last_snapshot[idx] = list(regs_src)
                                print(f"replicator: pushed src->{dst_host} for pair {idx}")
                            else:
                                print(f"replicator: failed to push src->{dst_host} for pair {idx}")
                            continue

                        if dst_changed and not src_changed:
                            # replica changed -> push to source
                            if write_regs(src_host, src_port, regs_dst):
                                last_snapshot[idx] = list(regs_dst)
                                print(f"replicator: pushed dst->{src_host} for pair {idx}")
                            else:
                                print(f"replicator: failed to push dst->{src_host} for pair {idx}")
                            continue

                        # both changed -> conflict
                        print(f"replicator: conflict detected on pair {idx}; resolving using policy={CONFLICT_POLICY}")
                        if CONFLICT_POLICY == 'replica':
                            # replica wins
                            if write_regs(src_host, src_port, regs_dst):
                                last_snapshot[idx] = list(regs_dst)
                                print(f"replicator: conflict resolved dst->{src_host} (replica wins)")
                            else:
                                print(f"replicator: failed to resolve conflict dst->{src_host}")
                        else:
                            # source wins
                            if write_regs(dst_host, dst_port, regs_src):
                                last_snapshot[idx] = list(regs_src)
                                print(f"replicator: conflict resolved src->{dst_host} (source wins)")
                            else:
                                print(f"replicator: failed to resolve conflict src->{dst_host}")
                    except Exception as e:
                        print(f"Error: {e}")
                time.sleep(POLL_INTERVAL)
            except Exception:
                print('replicator: modbus sync loop outer error')
                traceback.print_exc()
                time.sleep(POLL_INTERVAL)

    t = threading.Thread(target=modbus_sync_loop, daemon=True)
    t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        src_client.loop_stop()
        dst_client.loop_stop()
        src_client.disconnect()
        dst_client.disconnect()

if __name__ == '__main__':
    run()
