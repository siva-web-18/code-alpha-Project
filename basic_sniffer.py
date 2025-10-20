#!/usr/bin/env python3
"""
basic_sniffer.py

Simple packet sniffer using Scapy.

Features:
 - Capture live packets on a given interface (or default).
 - Optional BPF filter (like "tcp and port 80").
 - Optional packet count limit.
 - Optional save to pcap file.
 - Parse & display Ethernet, IP, TCP, UDP, ICMP headers and printable payload.

Requirements:
  - scapy
Run as root/Administrator (Linux: sudo; Windows: Run VS Code or terminal as Administrator and have Npcap installed)
"""

import argparse
import sys
import time
from scapy.all import sniff, wrpcap, Ether, IP, IPv6, TCP, UDP, ICMP, Raw, conf

def format_payload(payload_bytes, max_len=256):
    """Return small hex+ascii representation of payload bytes."""
    if not payload_bytes:
        return ""
    b = bytes(payload_bytes)[:max_len]
    hex_view = b.hex()
    printable = ''.join((chr(c) if 32 <= c < 127 else '.') for c in b)
    return f"Payload ({len(payload_bytes)} bytes, showing up to {max_len}):\nHEX: {hex_view}\nASCII: {printable}"

def process_packet(pkt):
    """Pretty print packet details."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(pkt.time)) if hasattr(pkt, 'time') else ""
    print(f"\n=== Packet captured at {ts} ===")

    # Link layer
    if Ether in pkt:
        eth = pkt[Ether]
        print(f"[Ether] src={eth.src} dst={eth.dst} type=0x{eth.type:04x}")

    # Network layer
    if IP in pkt:
        ip = pkt[IP]
        print(f"[IP] ver=4 src={ip.src} dst={ip.dst} proto={ip.proto} ttl={ip.ttl} len={ip.len}")
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        print(f"[IPv6] src={ip6.src} dst={ip6.dst} nh={ip6.nh} hlim={ip6.hlim} plen={ip6.plen}")
    else:
        if pkt.payload:
            print(f"[Other] Layer: {pkt.payload.name}")

    # Transport layer
    if TCP in pkt:
        tcp = pkt[TCP]
        flags = tcp.sprintf("%flags%")
        print(f"[TCP] sport={tcp.sport} dport={tcp.dport} seq={tcp.seq} ack={tcp.ack} flags={flags} window={tcp.window} options={tcp.options}")
    elif UDP in pkt:
        udp = pkt[UDP]
        print(f"[UDP] sport={udp.sport} dport={udp.dport} len={udp.len}")
    elif ICMP in pkt:
        icmp = pkt[ICMP]
        print(f"[ICMP] type={icmp.type} code={icmp.code} id={getattr(icmp, 'id', '')} seq={getattr(icmp, 'seq', '')}")

    # Payload
    if Raw in pkt:
        raw = pkt[Raw].load
        print(format_payload(raw, max_len=512))
    else:
        # try bytes of payload if present
        try:
            pbytes = bytes(pkt.payload)
            if pbytes:
                print(format_payload(pbytes, max_len=512))
        except Exception:
            pass

    # One-line summary
    print("Summary:", pkt.summary())
    print("=" * 60)

def build_sniff_kwargs(args):
    sniff_kwargs = {
        "prn": lambda p: (process_packet(p), captured.append(p))[0],
        "store": True,
        "count": args.count if args.count > 0 else 0,
    }
    # Only pass iface/filter if specified (scapy handles defaults)
    if args.interface:
        sniff_kwargs["iface"] = args.interface
    if args.filter:
        sniff_kwargs["filter"] = args.filter
    if args.promisc:
        sniff_kwargs["promisc"] = True
    return sniff_kwargs

def parse_args():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer (Scapy)")
    parser.add_argument("-i", "--interface", help="interface to sniff on (default: scapy default)", default=None)
    parser.add_argument("-c", "--count", help="number of packets to capture (0 = unlimited)", type=int, default=0)
    parser.add_argument("-f", "--filter", help='BPF filter (e.g., "tcp and port 80")', default=None)
    parser.add_argument("-w", "--write", help="save captured packets to pcap file (e.g., out.pcap)", default=None)
    parser.add_argument("--promisc", help="enable promiscuous mode", action="store_true")
    return parser.parse_args()

def main():
    global captured
    captured = []
    args = parse_args()

    if args.interface:
        conf.iface = args.interface

    print(f"Scapy iface={conf.iface}  (promisc={'on' if args.promisc else 'off'})")
    if args.filter:
        print(f"Using BPF filter: {args.filter}")
    if args.count <= 0:
        print("Packet count: unlimited (Ctrl+C to stop)")
    else:
        print(f"Packet count limit: {args.count}")

    sniff_kwargs = build_sniff_kwargs(args)
    # remove keys with None or empty strings
    sniff_kwargs = {k: v for k, v in sniff_kwargs.items() if v is not None and v != ""}

    try:
        sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        print("\nUser canceled capture (Ctrl+C)")
    except Exception as e:
        print("Error during sniffing:", e)
        sys.exit(1)

    if args.write:
        try:
            wrpcap(args.write, captured)
            print(f"Saved {len(captured)} packets to {args.write}")
        except Exception as e:
            print("Failed to write pcap:", e)

    print("Done.")

if __name__ == "__main__":
    main()
