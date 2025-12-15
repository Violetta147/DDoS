import time
import socket
import sys
from typing import List, Tuple
import ipaddress
from .flow import Flow


_ANSI_RESET = "\x1b[0m"
_ANSI_GREEN = "\x1b[32m"
_ANSI_CYAN = "\x1b[36m"
_ANSI_YELLOW = "\x1b[33m"
_ANSI_WHITE = "\x1b[37m"


def _format_hhmmss_us(ts: float) -> str:
    local = time.localtime(ts)
    us = int((ts - int(ts)) * 1_000_000)
    return (
        f"{local.tm_hour:02d}:{local.tm_min:02d}:{local.tm_sec:02d}."
        f"{us:06d}"
    )


def _tcp_flags_to_names(tcp_flags: int) -> List[str]:
    names: List[str] = []
    if tcp_flags & 0x02:
        names.append("SYN")
    if tcp_flags & 0x10:
        names.append("ACK")
    if tcp_flags & 0x01:
        names.append("FIN")
    if tcp_flags & 0x04:
        names.append("RST")
    if tcp_flags & 0x08:
        names.append("PSH")
    if tcp_flags & 0x20:
        names.append("URG")
    if tcp_flags & 0x40:
        names.append("ECE")
    if tcp_flags & 0x80:
        names.append("CWR")
    return names


def print_wireshark_style(
    no: int,
    ts: float,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    proto: int,
    payload_len: int,
    flags: int,
) -> None:
    """Print one-line packet summary (Wireshark/tshark-like) for debug.

    This is intentionally separate from the hot path.
    """
    if proto == 6:
        proto_name = "TCP"
        color = _ANSI_GREEN
        info = ", ".join(_tcp_flags_to_names(flags))
        info_col = f"[{info}]" if info else "[.]"
    elif proto == 17:
        proto_name = "UDP"
        color = _ANSI_CYAN
        info_col = "[.]" if flags == 0 else f"[0x{flags:02x}]"
    else:
        proto_name = str(proto)
        color = _ANSI_YELLOW
        info_col = "[.]" if flags == 0 else f"[0x{flags:02x}]"

    time_col = _format_hhmmss_us(ts)
    src_col = f"{src_ip}:{src_port}"
    dst_col = f"{dst_ip}:{dst_port}"
    addr_col = f"{src_col} -> {dst_col}"

    # Fixed-width columns (tshark-like): No | Time | Source -> Dest | Proto | Len | Info
    line = (
        f"{no:>6d} "
        f"{time_col:<15} "
        f"{addr_col:<45} "
        f"{proto_name:<4} "
        f"{payload_len:>5d} "
        f"{info_col}"
    )
    print(f"{color}{line}{_ANSI_RESET}", file=sys.stderr, flush=True)

# FEATURE_NAMES sẽ được tạo tự động từ Flow.to_features()
FEATURE_NAMES = None

# Cache cho local IPs để tránh detect lại nhiều lần
_local_ips_cache = None
_local_ips_cache_time = 0
_CACHE_TIMEOUT = 30  # Cache trong 30 giây


def init_feature_names():
    """Khởi tạo FEATURE_NAMES từ Flow.to_features()"""
    global FEATURE_NAMES
    if FEATURE_NAMES is not None:
        return
    
    # Tạo dummy flow để lấy tất cả feature names
    dummy_flow = Flow(time.time(), "192.168.1.1", "192.168.1.2", 12345, 80, 6)  # protocol=6 (TCP)
    now = time.time()
    # Feature-name init is not a hot path; use primitive update directly.
    dummy_flow.update_primitives(now, payload_len=100, header_len=40, tcp_flags=0, protocol=6, is_forward=True)
    dummy_flow.update_primitives(now + 0.001, payload_len=200, header_len=40, tcp_flags=0, protocol=6, is_forward=False)
    dummy_flow.last_time = dummy_flow.start_time + 0.001
    
    features = dummy_flow.to_features()
    # Order features according to FlowFeature enum order (not sorted alphabetically)
    # Protocol (6) first, then Flow Duration (8) through Idle Min (84)
    feature_order = [
        "Protocol",  # 6
        "Flow Duration",  # 8
        "Total Fwd Packets",  # 9
        "Total Backward Packets",  # 10
        "Total Length of Fwd Packets",  # 11
        "Total Length of Bwd Packets",  # 12
        "Fwd Packet Length Max",  # 13
        "Fwd Packet Length Min",  # 14
        "Fwd Packet Length Mean",  # 15
        "Fwd Packet Length Std",  # 16
        "Bwd Packet Length Max",  # 17
        "Bwd Packet Length Min",  # 18
        "Bwd Packet Length Mean",  # 19
        "Bwd Packet Length Std",  # 20
        "Flow Bytes/s",  # 21
        "Flow Packets/s",  # 22
        "Flow IAT Mean",  # 23
        "Flow IAT Std",  # 24
        "Flow IAT Max",  # 25
        "Flow IAT Min",  # 26
        "Fwd IAT Total",  # 27
        "Fwd IAT Mean",  # 28
        "Fwd IAT Std",  # 29
        "Fwd IAT Max",  # 30
        "Fwd IAT Min",  # 31
        "Bwd IAT Total",  # 32
        "Bwd IAT Mean",  # 33
        "Bwd IAT Std",  # 34
        "Bwd IAT Max",  # 35
        "Bwd IAT Min",  # 36
        "Fwd PSH Flags",  # 37
        "Bwd PSH Flags",  # 38
        "Fwd URG Flags",  # 39
        "Bwd URG Flags",  # 40
        "Fwd Header Length",  # 41
        "Bwd Header Length",  # 42
        "Fwd Packets/s",  # 43
        "Bwd Packets/s",  # 44
        "Packet Length Min",  # 45
        "Packet Length Max",  # 46
        "Packet Length Mean",  # 47
        "Packet Length Std",  # 48
        "Packet Length Variance",  # 49
        "FIN Flag Count",  # 50
        "SYN Flag Count",  # 51
        "RST Flag Count",  # 52
        "PSH Flag Count",  # 53
        "ACK Flag Count",  # 54
        "URG Flag Count",  # 55
        "CWR Flag Count",  # 56
        "ECE Flag Count",  # 57
        "Down/Up Ratio",  # 58
        "Average Packet Size",  # 59
        "Fwd Segment Size Avg",  # 60
        "Bwd Segment Size Avg",  # 61
        "Fwd Bytes/Bulk Avg",  # 63 (62 is duplicate)
        "Fwd Packet/Bulk Avg",  # 64
        "Fwd Bulk Rate Avg",  # 65
        "Bwd Bytes/Bulk Avg",  # 66
        "Bwd Packet/Bulk Avg",  # 67
        "Bwd Bulk Rate Avg",  # 68
        "Subflow Fwd Packets",  # 69
        "Subflow Fwd Bytes",  # 70
        "Subflow Bwd Packets",  # 71
        "Subflow Bwd Bytes",  # 72
        "FWD Init Win Bytes",  # 73
        "Bwd Init Win Bytes",  # 74
        "Fwd Act Data Pkts",  # 75
        "Fwd Seg Size Min",  # 76
        "Active Mean",  # 77
        "Active Std",  # 78
        "Active Max",  # 79
        "Active Min",  # 80
        "Idle Mean",  # 81
        "Idle Std",  # 82
        "Idle Max",  # 83
        "Idle Min",  # 84
        # Additional features for compatibility with older CSV files
        "Fwd RST Flags",  # Forward RST flags count
        "Bwd RST Flags",  # Backward RST flags count
        "ICMP Code",  # ICMP code (0 for TCP/UDP)
        "ICMP Type",  # ICMP type (0 for TCP/UDP)
        "Total TCP Flow Time",  # Same as Flow Duration for TCP
    ]
    # Filter to only include features that exist in the flow
    FEATURE_NAMES = [name for name in feature_order if name in features]
    print(f"[DEBUG] Initialized {len(FEATURE_NAMES)} features from Flow.to_features()", file=sys.stderr)


def get_local_ips(use_cache: bool = True) -> List[str]:
    """Lấy danh sách tất cả IP addresses của máy (có cache)"""
    global _local_ips_cache, _local_ips_cache_time
    
    # Kiểm tra cache
    if use_cache and _local_ips_cache is not None:
        if time.time() - _local_ips_cache_time < _CACHE_TIMEOUT:
            return _local_ips_cache.copy()
    
    ips = []
    try:
        # Lấy hostname
        hostname = socket.gethostname()
        # Lấy tất cả IP addresses
        for addr_info in socket.getaddrinfo(hostname, None):
            ip = addr_info[4][0]
            # Chỉ lấy IPv4, bỏ qua loopback
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                if not ip_obj.is_loopback:
                    ips.append(ip)
            except (ValueError, ipaddress.AddressValueError):
                continue
    except Exception:
        pass
    
    # Fallback: Thử kết nối để lấy IP chính (với timeout)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)  # Timeout 0.5s để tránh block
        s.connect(("8.8.8.8", 80))
        main_ip = s.getsockname()[0]
        s.close()
        if main_ip not in ips:
            ips.insert(0, main_ip)
    except Exception:
        pass
    
    result = list(dict.fromkeys(ips))  # Remove duplicates while keeping order
    _local_ips_cache = result
    _local_ips_cache_time = time.time()
    return result.copy()


def validate_ip(ip: str, local_ips: List[str] = None) -> Tuple[bool, str]:
    """Validate IP address và kiểm tra xem có phải IP của máy không"""
    if not ip or not ip.strip():
        return False, "IP address không được để trống"
    
    ip = ip.strip()
    
    # Kiểm tra format IP
    try:
        ip_obj = ipaddress.IPv4Address(ip)
    except (ValueError, ipaddress.AddressValueError):
        return False, f"'{ip}' không phải là địa chỉ IPv4 hợp lệ"
    
    # Trên Windows, raw socket KHÔNG hỗ trợ bind 0.0.0.0
    # Phải dùng IP cụ thể của interface
    if ip == "0.0.0.0":
        if local_ips is None:
            local_ips = get_local_ips(use_cache=True)
        if not local_ips:
            return False, "Không tìm thấy IP nào. Windows raw socket cần IP cụ thể, không hỗ trợ 0.0.0.0"
        return False, f"Windows raw socket không hỗ trợ 0.0.0.0.\nHãy dùng IP cụ thể: {', '.join(local_ips)}"
    
    # Kiểm tra xem IP có phải của máy không (dùng cache nếu có)
    if local_ips is None:
        local_ips = get_local_ips(use_cache=True)
    
    if ip not in local_ips:
        return False, f"IP '{ip}' không phải là IP của máy này.\nIP có sẵn: {', '.join(local_ips) if local_ips else 'Không tìm thấy'}"
    
    return True, "OK"

