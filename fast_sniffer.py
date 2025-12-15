#!/usr/bin/env python3
"""
Fast Sniffer - Command-line interface for network packet capture
Uses raw socket for high-performance packet sniffing
"""

import sys
from capture import FastSniffer, get_local_ips, validate_ip, init_feature_names


def main():
    """Command-line interface"""
    if len(sys.argv) < 2:
        local_ips = get_local_ips()
        if local_ips:
            print(f"Usage: python {sys.argv[0]} <bind_ip> [--print] [--stats]", file=sys.stderr)
            print(f"Available IPs: {', '.join(local_ips)}", file=sys.stderr)
            print(f"Example: python {sys.argv[0]} {local_ips[0]}", file=sys.stderr)
        else:
            print(f"Usage: python {sys.argv[0]} <bind_ip> [--print] [--stats]", file=sys.stderr)
            print("⚠️ Could not detect any local IPs. Please specify manually.", file=sys.stderr)
        sys.exit(1)
    
    bind_ip = sys.argv[1].strip()
    debug_print = "--print" in sys.argv[2:]
    stats = "--stats" in sys.argv[2:]
    
    # Validate IP
    is_valid, error_msg = validate_ip(bind_ip)
    if not is_valid:
        print(f"❌ IP Validation Error: {error_msg}", file=sys.stderr)
        print("⚠️ Lưu ý: Trên Windows, cần quyền Admin để sử dụng raw socket", file=sys.stderr)
        sys.exit(1)
    
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
