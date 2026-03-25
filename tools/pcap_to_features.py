#!/usr/bin/env python3
"""Simple PCAP -> windowed feature extractor using scapy.

Produces CSV with one row per time window and a small set of numeric features.

This is intentionally lightweight for a PoC and focuses on network-level aggregates.
"""
import argparse
import csv
import os
from collections import defaultdict

try:
    from scapy.all import rdpcap, TCP, UDP, IP
except Exception as e:
    rdpcap = None


def extract_windows(pcap_path, window_size=10.0):
    """Read pcap and return a list of feature dicts, one per window.

    Features: total_pkts, total_bytes, unique_src, unique_dst, tcp_syn_count,
    udp_count, avg_pkt_len
    """
    if rdpcap is None:
        raise RuntimeError('scapy.rdpcap not available; install scapy')
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(pcap_path)
    pkts = rdpcap(pcap_path)
    if not pkts:
        return []
    start_ts = float(pkts[0].time)
    windows = []
    current_window = defaultdict(int)
    srcs = set()
    dsts = set()
    pkt_lengths = []
    # MQTT-specific accumulators (per-window)
    mqtt_pkt_count = 0
    mqtt_bytes = 0
    mqtt_payload_lengths = []
    mqtt_endpoints = set()
    window_start = start_ts
    for pkt in pkts:
        ts = float(pkt.time)
        # advance window if packet beyond current window
        while ts >= window_start + window_size:
            # finalize current window
            total_pkts = current_window.get('total_pkts', 0)
            total_bytes = current_window.get('total_bytes', 0)
            avg_len = (sum(pkt_lengths) / len(pkt_lengths)) if pkt_lengths else 0
            windows.append({
                'start_ts': window_start,
                'end_ts': window_start + window_size,
                'total_pkts': total_pkts,
                'total_bytes': total_bytes,
                'unique_src': len(srcs),
                'unique_dst': len(dsts),
                'tcp_syn_count': current_window.get('tcp_syn_count', 0),
                'udp_count': current_window.get('udp_count', 0),
                'avg_pkt_len': avg_len,
                # MQTT-aware features
                'mqtt_msg_count': mqtt_pkt_count,
                'mqtt_bytes': mqtt_bytes,
                'avg_mqtt_payload_len': (sum(mqtt_payload_lengths) / len(mqtt_payload_lengths)) if mqtt_payload_lengths else 0,
                'unique_mqtt_endpoints': len(mqtt_endpoints),
            })
            # reset
            window_start += window_size
            current_window = defaultdict(int)
            srcs = set()
            dsts = set()
            pkt_lengths = []
            # reset mqtt accumulators
            mqtt_pkt_count = 0
            mqtt_bytes = 0
            mqtt_payload_lengths = []
            mqtt_endpoints = set()
        # accumulate
        current_window['total_pkts'] += 1
        try:
            l = len(pkt)
        except Exception:
            l = 0
        current_window['total_bytes'] += l
        pkt_lengths.append(l)
        if IP in pkt:
            srcs.add(pkt[IP].src)
            dsts.add(pkt[IP].dst)
        if TCP in pkt:
            flags = pkt[TCP].flags
            # SYN flag (0x02)
            if int(flags) & 0x02:
                current_window['tcp_syn_count'] += 1
        if UDP in pkt:
            current_window['udp_count'] += 1

        # detect MQTT by TCP port 1883 (treat any TCP packet with sport/dport 1883 as MQTT)
        try:
            if TCP in pkt and (int(pkt[TCP].sport) == 1883 or int(pkt[TCP].dport) == 1883):
                # only count MQTT when the TCP segment carries application payload
                try:
                    pl = len(bytes(pkt[TCP].payload))
                except Exception:
                    pl = 0
                if pl > 0:
                    mqtt_pkt_count += 1
                    mqtt_bytes += pl
                    if IP in pkt:
                        mqtt_endpoints.add((pkt[IP].src, pkt[IP].dst))
                    mqtt_payload_lengths.append(pl)
        except Exception:
            # non-IP/TCP packet or parsing issue; ignore MQTT checks
            pass

    # finalize last partial window
    if current_window.get('total_pkts', 0) or pkt_lengths:
        total_pkts = current_window.get('total_pkts', 0)
        total_bytes = current_window.get('total_bytes', 0)
        avg_len = (sum(pkt_lengths) / len(pkt_lengths)) if pkt_lengths else 0
        windows.append({
            'start_ts': window_start,
            'end_ts': window_start + window_size,
            'total_pkts': total_pkts,
            'total_bytes': total_bytes,
            'unique_src': len(srcs),
            'unique_dst': len(dsts),
            'tcp_syn_count': current_window.get('tcp_syn_count', 0),
            'udp_count': current_window.get('udp_count', 0),
                'avg_pkt_len': avg_len,
                # MQTT-aware features for last partial window
                'mqtt_msg_count': mqtt_pkt_count,
                'mqtt_bytes': mqtt_bytes,
                'avg_mqtt_payload_len': (sum(mqtt_payload_lengths) / len(mqtt_payload_lengths)) if mqtt_payload_lengths else 0,
                'unique_mqtt_endpoints': len(mqtt_endpoints),
        })

    return windows


def write_csv(rows, out_path):
    if not rows:
        print('no windows to write')
        return
    keys = list(rows[0].keys())
    with open(out_path, 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=keys)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('pcap')
    p.add_argument('out_csv')
    p.add_argument('--window', type=float, default=10.0)
    args = p.parse_args()
    rows = extract_windows(args.pcap, window_size=args.window)
    write_csv(rows, args.out_csv)
    print('wrote', len(rows), 'windows to', args.out_csv)


if __name__ == '__main__':
    main()
