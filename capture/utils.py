import time
import socket
import sys
from typing import List, Tuple
import ipaddress
from .flow import Flow

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
    dummy_flow.update(100, 40, time.time(), True, 0)
    dummy_flow.update(200, 40, time.time() + 0.001, False, 0)
    dummy_flow.last_time = dummy_flow.start_time + 0.001
    
    features = dummy_flow.to_features()
    FEATURE_NAMES = sorted(list(features.keys()))  # Sort để consistent
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

