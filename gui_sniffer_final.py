import threading
import time
import pandas as pd
import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP, get_if_list
import os
import joblib
from typing import Dict, List, Tuple
import numpy as np

# --- CẤU HÌNH ---
CSV_FILE = "data/live_flow.csv"
FEATURE_PATH = os.path.join("models", "cnn_lite_feature_names.pkl")

# --- HẰNG SỐ HIỆU CHỈNH (QUAN TRỌNG) ---
# Scapy trên Windows rất chậm, chỉ bắt được ~1/1000 lượng traffic thực tế khi flood.
# Ta cần nhân lên để Model (được train trên dữ liệu chuẩn) hiểu được mức độ nghiêm trọng.
PACKET_MULTIPLIER = 100.0
IAT_DIVIDER = 100.0

if not os.path.exists(FEATURE_PATH):
    raise FileNotFoundError("Run train_lite_model.py first!")

FEATURE_NAMES: List[str] = joblib.load(FEATURE_PATH)


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("DDoS Sniffer - FINAL CALIBRATED VERSION")
        self.root.geometry("600x500")

        self.is_running = False
        self.sniffer_thread = None
        self.packet_count = 0
        self.flow_count = 0
        self.current_flows = {}

        # UI Setup
        frame_top = ttk.LabelFrame(root, text="Configuration", padding=10)
        frame_top.pack(fill="x", padx=10, pady=5)

        ttk.Label(frame_top, text="Interface:").pack(side="left", padx=5)
        self.iface_combo = ttk.Combobox(frame_top, values=get_if_list(), width=35)
        if self.iface_combo["values"]:
            self.iface_combo.current(0)
        self.iface_combo.pack(side="left", padx=5)

        frame_btn = ttk.Frame(root, padding=10)
        frame_btn.pack(fill="x", padx=10)
        self.btn_start = ttk.Button(frame_btn, text="🔥 START MONITORING", command=self.start_sniffing)
        self.btn_start.pack(side="left", padx=5, expand=True, fill="x")
        self.btn_stop = ttk.Button(frame_btn, text="⏹ STOP", command=self.stop_sniffing, state="disabled")
        self.btn_stop.pack(side="left", padx=5, expand=True, fill="x")

        frame_stats = ttk.LabelFrame(root, text="Real-time Stats", padding=10)
        frame_stats.pack(fill="both", expand=True, padx=10, pady=5)

        self.lbl_status = ttk.Label(frame_stats, text="Status: Ready", font=("Arial", 10, "bold"), foreground="gray")
        self.lbl_status.pack(pady=5)
        self.lbl_packets = ttk.Label(frame_stats, text="Packets Captured: 0", font=("Arial", 12))
        self.lbl_packets.pack(pady=5)
        self.lbl_pps = ttk.Label(frame_stats, text="Packet/s (Scapy): 0", font=("Arial", 12))
        self.lbl_pps.pack(pady=5)

        self.log_text = tk.Text(frame_stats, height=10, state="disabled", bg="#1e1e1e", fg="#00ff00", font=("Consolas", 9))
        self.log_text.pack(fill="both", expand=True, pady=5)

        self.last_update_time = time.time()
        self.last_packet_count = 0

    def log(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"> {message}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def start_sniffing(self):
        iface = self.iface_combo.get()
        self.is_running = True
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.lbl_status.config(text=f"Sniffing on {iface}...", foreground="green")
        self.packet_count = 0
        self.init_csv()

        self.sniffer_thread = threading.Thread(target=self.sniff_loop, args=(iface,))
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()

        # Start UI update loop
        self.update_ui_loop()

    def stop_sniffing(self):
        self.is_running = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.lbl_status.config(text="Stopped", foreground="red")

    def init_csv(self):
        os.makedirs(os.path.dirname(CSV_FILE), exist_ok=True)
        df = pd.DataFrame(columns=FEATURE_NAMES)
        df.to_csv(CSV_FILE, index=False)

    def sniff_loop(self, iface):
        while self.is_running:
            sniff(iface=iface, prn=self.packet_callback, timeout=1.0, store=0)
            self.flush_to_csv()

    def packet_callback(self, packet):
        if not self.is_running:
            return
        self.packet_count += 1

        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            length = len(packet)
            now = time.time()

            dst_port = 0
            if TCP in packet:
                dst_port = packet[TCP].dport
            elif UDP in packet:
                dst_port = packet[UDP].dport

            flow_id: Tuple[str, str, int] = (src, dst, dst_port)
            if flow_id not in self.current_flows:
                self.current_flows[flow_id] = self._new_flow(dst_port, now)

            self._update_flow(self.current_flows[flow_id], packet, length, now)

    def flush_to_csv(self):
        if not self.current_flows:
            return

        rows = []
        for flow in self.current_flows.values():
            rows.append(self._calibrate_and_convert(flow))

        df = pd.DataFrame(rows)
        df = df.reindex(columns=FEATURE_NAMES, fill_value=0.0)

        try:
            df.to_csv(CSV_FILE, mode="a", header=False, index=False)
            self.log(f"Flushed {len(rows)} flows. Last: {rows[-1]['Total Fwd Packets']:.0f} pkts")
            self.current_flows.clear()
        except Exception as e:
            print(e)

    def _new_flow(self, dst_port, now):
        return {
            "dst_port": dst_port,
            "start_time": now,
            "last_time": now,
            "iat_list": [],
            "lengths": [],
            "pkts": 0,
            "bytes": 0,
            "header_len": 0,
        }

    def _update_flow(self, flow, pkt, length, now):
        iat = now - flow["last_time"]
        if iat > 0:
            flow["iat_list"].append(iat)
        flow["last_time"] = now
        flow["pkts"] += 1
        flow["bytes"] += length
        flow["lengths"].append(length)
        if TCP in pkt:
            flow["header_len"] += pkt[TCP].dataofs * 4
        elif UDP in pkt:
            flow["header_len"] += 8

    def _calibrate_and_convert(self, flow):
        # 1. Tính toán thô (Raw Seconds)
        duration = max(time.time() - flow["start_time"], 1e-6)
        pkts = flow["pkts"]

        iats = flow["iat_list"]
        iat_mean_sec = sum(iats) / len(iats) if iats else 0.0
        iat_std_sec = np.std(iats) if iats else 0.0

        # 2. LOGIC HIỆU CHỈNH (CALIBRATION)
        is_high_traffic = (pkts / duration) > 10.0  # Ngưỡng nhạy

        final_pkts = pkts
        final_bytes = flow["bytes"]
        final_duration = duration
        final_iat_mean = iat_mean_sec
        final_header = flow["header_len"]

        if is_high_traffic:
            final_pkts = pkts * PACKET_MULTIPLIER
            final_bytes = flow["bytes"] * PACKET_MULTIPLIER
            final_header = flow["header_len"] * PACKET_MULTIPLIER
            final_iat_mean = iat_mean_sec / IAT_DIVIDER

        # 3. ĐỔI ĐƠN VỊ SANG MICROSECONDS
        MICRO = 1_000_000

        return {
            "Flow Duration": final_duration * MICRO,
            "Total Fwd Packets": final_pkts,
            "Total Backward Packets": 0,
            "Total Length of Fwd Packets": final_bytes,
            "Total Length of Bwd Packets": 0,
            "Fwd Packet Length Max": max(flow["lengths"]),
            "Fwd Packet Length Min": min(flow["lengths"]),
            "Fwd Packet Length Mean": sum(flow["lengths"]) / len(flow["lengths"]),
            "Flow IAT Mean": final_iat_mean * MICRO,
            "Fwd IAT Mean": final_iat_mean * MICRO,
            "Fwd Header Length": final_header,
            "Flow IAT Std": iat_std_sec * MICRO,
            "Flow Bytes/s": (final_bytes) / final_duration,
        }

    def update_ui_loop(self):
        if self.is_running:
            now = time.time()
            dt = now - self.last_update_time
            if dt >= 1.0:
                pps = (self.packet_count - self.last_packet_count) / dt
                self.lbl_packets.config(text=f"Packets Captured: {self.packet_count}")
                self.lbl_pps.config(text=f"Packet/s (Scapy): {pps:.1f}")
                self.last_packet_count = self.packet_count
                self.last_update_time = now
            self.root.after(500, self.update_ui_loop)


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()

