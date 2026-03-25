#!/usr/bin/env python3
"""
Convert a PCAP with MQTT traffic into a JSON-lines replay file the attacker can use.

The attacker expects each line to be a JSON object with at least these fields:
  - ts (float): original packet timestamp (unix epoch)
  - topic (str): MQTT topic
  - payload (str): UTF-8 decoded payload when possible; otherwise prefix with "BASE64::" and base64 payload

This script prefers to use `tshark` (faster and more robust). If tshark isn't available
it will try to parse packets with Scapy's MQTT contrib layer.

Example:
  python tools/pcap_to_mqtt_replay.py pcaps/attack_mqtt_replay.pcap -o data/mqtt_replay.jsonl

If you plan to use the generated file inside the attacker container, either copy it to
the project's `data/` directory or mount your host `./data` into the attacker container
so the attacker can read `/data/mqtt_replay.jsonl`.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import base64
import re
from typing import Iterable


HEX_RE = re.compile(r'^[0-9a-fA-F]+$')


def parse_with_tshark(pcap: str) -> Iterable[dict]:
    """Yield dicts (ts, topic, payload) for MQTT PUBLISH frames using tshark.

    Requires tshark to be installed and in PATH.
    """
    # fields: frame.time_epoch, mqtt.topic, mqtt.payload
    cmd = [
        'tshark', '-r', pcap,
        '-Y', 'mqtt.msgtype == 3',
        '-T', 'fields',
        '-e', 'frame.time_epoch',
        '-e', 'mqtt.topic',
        '-e', 'mqtt.payload',
        '-E', 'separator=|',
        '-E', 'occurrence=f'
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip('\n')
        if not line:
            continue
        parts = line.split('|')
        # tshark may omit fields; pad
        while len(parts) < 3:
            parts.append('')
        ts_s, topic, payload_s = parts[:3]
        try:
            ts = float(ts_s) if ts_s else 0.0
        except Exception:
            ts = 0.0
        # payload_s: sometimes ascii, sometimes hex (no prefix). Detect hex
        payload = ''
        if payload_s:
            ps = payload_s.strip()
            # If it looks like hex (even length, only hex chars) try to decode
            if HEX_RE.match(ps) and (len(ps) % 2 == 0):
                try:
                    payload_bytes = bytes.fromhex(ps)
                except Exception:
                    payload_bytes = ps.encode('utf-8', errors='replace')
            else:
                # treat as raw text
                payload_bytes = ps.encode('utf-8', errors='replace')
            # try utf-8
            try:
                payload = payload_bytes.decode('utf-8')
            except Exception:
                payload = 'BASE64::' + base64.b64encode(payload_bytes).decode('ascii')
        yield {'ts': ts, 'topic': topic, 'payload': payload}


def parse_with_scapy(pcap: str) -> Iterable[dict]:
    """Yield dicts (ts, topic, payload) using scapy's MQTT contrib layer.

    This is a best-effort fallback.
    """
    try:
        from scapy.all import rdpcap
        from scapy.contrib.mqtt import MQTT
    except Exception as e:
        raise RuntimeError('Scapy MQTT contrib not available or failed to import: ' + str(e))

    pkts = rdpcap(pcap)
    for pkt in pkts:
        # Scapy packet time is in pkt.time
        try:
            if not pkt.haslayer(MQTT):
                continue
            m = pkt[MQTT]
            # Different scapy versions expose fields differently; try common names
            topic = getattr(m, 'topic', None) or getattr(m, 'Topic', None) or ''
            # payload / msg may be available as payload or msg
            payload_bytes = None
            if hasattr(m, 'payload') and m.payload is not None:
                # m.payload might be a bytes-like or str
                p = m.payload
                if isinstance(p, bytes):
                    payload_bytes = p
                else:
                    try:
                        payload_bytes = bytes(str(p), 'utf-8')
                    except Exception:
                        payload_bytes = None
            if payload_bytes is None:
                # try raw TCP load
                raw = bytes(pkt.payload.payload) if pkt.payload and pkt.payload.payload else b''
                payload_bytes = raw
            try:
                payload = payload_bytes.decode('utf-8')
            except Exception:
                payload = 'BASE64::' + base64.b64encode(payload_bytes).decode('ascii')
            ts = float(getattr(pkt, 'time', 0.0))
            yield {'ts': ts, 'topic': topic, 'payload': payload}
        except Exception:
            continue


def write_jsonl(items: Iterable[dict], out_path: str):
    with open(out_path, 'w') as fh:
        for it in items:
            fh.write(json.dumps(it, separators=(',', ':')) + '\n')


def main():
    p = argparse.ArgumentParser(description='Extract MQTT PUBLISH messages from PCAP to JSON-lines replay file')
    p.add_argument('pcap', help='Input PCAP file')
    p.add_argument('-o', '--out', default='data/mqtt_replay.jsonl', help='Output JSON-lines file (default: data/mqtt_replay.jsonl)')
    p.add_argument('--prefer-tshark', action='store_true', help='Prefer tshark even if scapy is available')
    args = p.parse_args()

    pcap = args.pcap
    out = args.out

    use_tshark = shutil.which('tshark') is not None
    if args.prefer_tshark and not use_tshark:
        print('tshark requested but not found in PATH', file=sys.stderr)
    if use_tshark:
        try:
            items = list(parse_with_tshark(pcap))
            if not items:
                print('tshark found no MQTT PUBLISH frames, falling back to scapy', file=sys.stderr)
                items = list(parse_with_scapy(pcap))
        except Exception as e:
            print('tshark parsing failed:', e, file=sys.stderr)
            print('falling back to scapy...', file=sys.stderr)
            items = list(parse_with_scapy(pcap))
    else:
        items = list(parse_with_scapy(pcap))

    if not items:
        print('no MQTT publish messages found in', pcap, file=sys.stderr)
        sys.exit(2)

    # Normalize: ensure keys exist and sort by ts
    cleaned = []
    for it in items:
        ts = float(it.get('ts', 0.0) or 0.0)
        topic = it.get('topic') or ''
        payload = it.get('payload') if it.get('payload') is not None else ''
        cleaned.append({'ts': ts, 'topic': topic, 'payload': payload})
    cleaned.sort(key=lambda x: x['ts'])

    # Ensure output directory exists
    import os
    os.makedirs(os.path.dirname(out) or '.', exist_ok=True)
    write_jsonl(cleaned, out)
    print(f'Wrote {len(cleaned)} messages to {out}')


if __name__ == '__main__':
    main()
