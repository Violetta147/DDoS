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
    # Order columns to match the user-provided 1..83 CSV schema exactly.
    # Note: "CWE Flag Count" is a non-standard label used by some datasets.
    feature_order = [
        "Flow ID",  # 1
        "Src IP",  # 2
        "Src Port",  # 3
        "Dst IP",  # 4
        "Dst Port",  # 5
        "Protocol",  # 6
        "Timestamp",  # 7
        "Flow Duration",  # 8
        "Tot Fwd Pkts",  # 9
        "Tot Bwd Pkts",  # 10
        "TotLen Fwd Pkts",  # 11
        "TotLen Bwd Pkts",  # 12
        "Fwd Pkt Len Max",  # 13
        "Fwd Pkt Len Min",  # 14
        "Fwd Pkt Len Mean",  # 15
        "Fwd Pkt Len Std",  # 16
        "Bwd Pkt Len Max",  # 17
        "Bwd Pkt Len Min",  # 18
        "Bwd Pkt Len Mean",  # 19
        "Bwd Pkt Len Std",  # 20
        "Flow Byts/s",  # 21
        "Flow Pkts/s",  # 22
        "Flow IAT Mean",  # 23
        "Flow IAT Std",  # 24
        "Flow IAT Max",  # 25
        "Flow IAT Min",  # 26
        "Fwd IAT Tot",  # 27
        "Fwd IAT Mean",  # 28
        "Fwd IAT Std",  # 29
        "Fwd IAT Max",  # 30
        "Fwd IAT Min",  # 31
        "Bwd IAT Tot",  # 32
        "Bwd IAT Mean",  # 33
        "Bwd IAT Std",  # 34
        "Bwd IAT Max",  # 35
        "Bwd IAT Min",  # 36
        "Fwd PSH Flags",  # 37
        "Bwd PSH Flags",  # 38
        "Fwd URG Flags",  # 39
        "Bwd URG Flags",  # 40
        "Fwd Header Len",  # 41
        "Bwd Header Len",  # 42
        "Fwd Pkts/s",  # 43
        "Bwd Pkts/s",  # 44
        "Pkt Len Min",  # 45
        "Pkt Len Max",  # 46
        "Pkt Len Mean",  # 47
        "Pkt Len Std",  # 48
        "Pkt Len Var",  # 49
        "FIN Flag Cnt",  # 50
        "SYN Flag Cnt",  # 51
        "RST Flag Cnt",  # 52
        "PSH Flag Cnt",  # 53
        "ACK Flag Cnt",  # 54
        "URG Flag Cnt",  # 55
        "CWE Flag Count",  # 56
        "ECE Flag Cnt",  # 57
        "Down/Up Ratio",  # 58
        "Pkt Size Avg",  # 59
        "Fwd Seg Size Avg",  # 60
        "Bwd Seg Size Avg",  # 61
        "Fwd Byts/b Avg",  # 62
        "Fwd Pkts/b Avg",  # 63
        "Fwd Blk Rate Avg",  # 64
        "Bwd Byts/b Avg",  # 65
        "Bwd Pkts/b Avg",  # 66
        "Bwd Blk Rate Avg",  # 67
        "Subflow Fwd Pkts",  # 68
        "Subflow Fwd Byts",  # 69
        "Subflow Bwd Pkts",  # 70
        "Subflow Bwd Byts",  # 71
        "Init Fwd Win Byts",  # 72
        "Init Bwd Win Byts",  # 73
        "Fwd Act Data Pkts",  # 74
        "Fwd Seg Size Min",  # 75
        "Active Mean",  # 76
        "Active Std",  # 77
        "Active Max",  # 78
        "Active Min",  # 79
        "Idle Mean",  # 80
        "Idle Std",  # 81
        "Idle Max",  # 82
        "Idle Min",  # 83
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

