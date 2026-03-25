#!/usr/bin/env python3
"""Simple MQTT traffic generator used by experiments.

Publishes synthetic telemetry messages to a broker until duration expires.
Designed to be executed inside a container attached to the target Docker network.
"""
import argparse
import time
import json
import random
import paho.mqtt.publish as publish


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--broker', required=True)
    p.add_argument('--port', type=int, default=1883)
    p.add_argument('--duration', type=int, default=30)
    p.add_argument('--rate', type=float, default=1.0, help='messages per second per sensor')
    p.add_argument('--sensors', type=int, default=5)
    p.add_argument('--topic-prefix', default='sensors')
    args = p.parse_args()

    end = time.time() + args.duration
    seq = 0
    sids = list(range(1, args.sensors + 1))
    interval = 1.0 / max(1.0, args.rate)
    while time.time() < end:
        for sid in sids:
            payload = json.dumps({'sensor_id': sid, 'ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'value': round(random.uniform(0, 100), 2), 'seq': seq})
            publish.single(f'{args.topic_prefix}/{sid}/telemetry', payload, hostname=args.broker, port=args.port)
            seq += 1
        time.sleep(interval)


if __name__ == '__main__':
    main()
