#!/usr/bin/env python3
"""Fast Sniffer - Command-line interface for network packet capture."""

import ipaddress
import sys

from capture import FastSniffer, get_local_ips, init_feature_names
from capture import utils


def main():
    """Command-line interface"""
    if len(sys.argv) < 2:
        local_ips = get_local_ips()
        if local_ips:
            print(
                f"Usage: python {sys.argv[0]} <interface|ip_filter> [--print] [--stats] [--header short|cic2017]",
                file=sys.stderr,
            )
            print(f"Available IPs: {', '.join(local_ips)}", file=sys.stderr)
            print(f"Example (filter by IP): python {sys.argv[0]} {local_ips[0]}", file=sys.stderr)
            print(f"Example (interface): python {sys.argv[0]} \\\\Device\\\\NPF_...", file=sys.stderr)
        else:
            print(
                f"Usage: python {sys.argv[0]} <interface|ip_filter> [--print] [--stats] [--header short|cic2017]",
                file=sys.stderr,
            )
            print("⚠️ Could not detect any local IPs. Please specify manually.", file=sys.stderr)
        sys.exit(1)
    
    bind_ip = sys.argv[1].strip()
    debug_print = "--print" in sys.argv[2:]
    stats = "--stats" in sys.argv[2:]

    # Optional header style selection (default: short)
    header_style = "short"
    if "--header" in sys.argv[2:]:
        idx = sys.argv.index("--header")
        if idx + 1 >= len(sys.argv):
            raise ValueError("Missing value after --header (expected: short|cic2017)")
        header_style = str(sys.argv[idx + 1]).strip().lower()
    if header_style not in ("short", "cic2017"):
        raise ValueError(f"Invalid --header value: {header_style} (expected: short|cic2017)")
    utils.CSV_HEADER_STYLE = header_style  # type: ignore[assignment]
    print(f"[DEBUG] CSV header style: {utils.CSV_HEADER_STYLE}", file=sys.stderr)

    # Accept either:
    # - IPv4 address (used as capture filter: host <ip>)
    # - pcap device name from pcapy.findalldevs()
    try:
        ipaddress.IPv4Address(bind_ip)
    except ValueError:
        pass
    
    # Init feature names
    init_feature_names()
    
    # Create and start sniffer
    sniffer = FastSniffer(bind_ip, debug_print=debug_print, stats=stats)
    
    try:
        sniffer.start()
    except KeyboardInterrupt:
        print("\n🛑 Stopping sniffer...", file=sys.stderr)
        sniffer.stop()
        print("✅ Sniffer stopped.", file=sys.stderr)


if __name__ == "__main__":
    main()
