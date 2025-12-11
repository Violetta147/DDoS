import threading
import time
import pandas as pd
import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP, get_if_list
import os
import joblib
from typing import Dict, List, Tuple

CSV_FILE = "data/live_flow.csv"
FEATURE_PATH = os.path.join("models", "cnn_lite_feature_names.pkl")

if not os.path.exists(FEATURE_PATH):
    raise FileNotFoundError("Feature names not found: models/cnn_lite_feature_names.pkl. Run train_lite_model.py first.")

FEATURE_NAMES: List[str] = joblib.load(FEATURE_PATH)

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("CICFlowMeter (Python Edition) - Realtime Sniffer")
        self.root.geometry("600x450")
        
        # Biến trạng thái
        self.is_running = False
        self.sniffer_thread = None
        self.packet_count = 0
        self.flow_count = 0
        self.current_flows = {}
        
        # --- GIAO DIỆN ---
        # 1. Chọn Card mạng
        frame_top = ttk.LabelFrame(root, text="Configuration", padding=10)
        frame_top.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(frame_top, text="Select Interface:").pack(side="left", padx=5)
        self.iface_combo = ttk.Combobox(frame_top, values=get_if_list(), width=30)
        if self.iface_combo['values']:
            self.iface_combo.current(0)
        self.iface_combo.pack(side="left", padx=5)
        
        # 2. Nút bấm
        frame_btn = ttk.Frame(root, padding=10)
        frame_btn.pack(fill="x", padx=10)
        
        self.btn_start = ttk.Button(frame_btn, text="▶ START", command=self.start_sniffing)
        self.btn_start.pack(side="left", padx=5, expand=True, fill="x")
        
        self.btn_stop = ttk.Button(frame_btn, text="⏹ STOP", command=self.stop_sniffing, state="disabled")
        self.btn_stop.pack(side="left", padx=5, expand=True, fill="x")
        
        # 3. Bảng thống kê (Dashboard)
        frame_stats = ttk.LabelFrame(root, text="Live Statistics", padding=10)
        frame_stats.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.lbl_status = ttk.Label(frame_stats, text="Status: Ready", font=("Arial", 10, "bold"), foreground="gray")
        self.lbl_status.pack(pady=5)
        
        self.lbl_packets = ttk.Label(frame_stats, text="Total Packets Captured: 0", font=("Arial", 12))
        self.lbl_packets.pack(pady=5)
        
        self.lbl_flows = ttk.Label(frame_stats, text="Active Flows Extracted: 0", font=("Arial", 12))
        self.lbl_flows.pack(pady=5)
        
        self.log_text = tk.Text(frame_stats, height=10, state="disabled", bg="#f0f0f0", font=("Consolas", 9))
        self.log_text.pack(fill="both", expand=True, pady=5)

    def log(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def start_sniffing(self):
        iface = self.iface_combo.get()
        if not iface:
            messagebox.showerror("Error", "Please select a network interface!")
            return
            
        self.is_running = True
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.lbl_status.config(text=f"Status: Sniffing on {iface}...", foreground="green")
        self.packet_count = 0
        self.flow_count = 0
        self.init_csv()
        
        # Chạy luồng bắt gói tin
        self.sniffer_thread = threading.Thread(target=self.sniff_loop, args=(iface,))
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.is_running = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.lbl_status.config(text="Status: Stopped", foreground="red")
        self.log("--- Capture Stopped ---")

    def init_csv(self):
        os.makedirs(os.path.dirname(CSV_FILE), exist_ok=True)
        df = pd.DataFrame(columns=FEATURE_NAMES)
        df.to_csv(CSV_FILE, index=False)
        self.log(f"Debug: Initialized CSV with {len(FEATURE_NAMES)} columns at {CSV_FILE}")

    def sniff_loop(self, iface):
        self.log(f"Started capturing on {iface} (capture-only)...")
        
        while self.is_running:
            sniff(iface=iface, prn=self.packet_callback, timeout=1, store=0)
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
                self.current_flows[flow_id] = self._new_flow_record(dst_port, now)
            
            flow = self.current_flows[flow_id]
            self._update_flow(flow, packet, length, now)
            
            if self.packet_count % 10 == 0:
                self.root.after(0, self.update_labels)

    def flush_to_csv(self):
        if not self.current_flows:
            return
        rows = [self._flow_to_row_lite(flow) for flow in self.current_flows.values()]
        df = pd.DataFrame(rows)
        df = df.reindex(columns=FEATURE_NAMES, fill_value=0.0)
        try:
            write_header = not os.path.exists(CSV_FILE) or os.path.getsize(CSV_FILE) == 0
            os.makedirs(os.path.dirname(CSV_FILE), exist_ok=True)
            df.to_csv(CSV_FILE, mode="a", header=write_header, index=False)
            self.flow_count += len(rows)
            self.log(f"Debug: Flushed {len(rows)} flows to CSV.")
            self.current_flows.clear()
        except Exception as exc:
            self.log(f"Error writing CSV: {exc}")

    def update_labels(self):
        self.lbl_packets.config(text=f"Total Packets Captured: {self.packet_count}")
        self.lbl_flows.config(text=f"Active Flows Extracted: {self.flow_count}")

    def _new_flow_record(self, dst_port: int, now_ts: float) -> Dict[str, object]:
        return {
            "dst_port": dst_port,
            "start_time": now_ts,
            "last_packet_time": now_ts,
            "iat_list": [],
            "packet_lengths": [],
            "flags": {"syn": 0, "fin": 0, "rst": 0, "psh": 0, "ack": 0, "urg": 0, "ece": 0},
            "total_fwd_packets": 0,
            "total_bwd_packets": 0,
            "total_len_fwd": 0,
            "total_len_bwd": 0,
            "fwd_header_len_total": 0,
            "bwd_header_len_total": 0,
            "init_win_fwd": 0,
            "init_win_bwd": 0,
        }

    def _update_flow(self, flow: Dict[str, object], packet, length: int, now_ts: float) -> None:
        time_delta = now_ts - float(flow["last_packet_time"])
        if time_delta > 0:
            flow["iat_list"].append(time_delta)
        flow["last_packet_time"] = now_ts

        flow["total_fwd_packets"] += 1
        flow["total_len_fwd"] += length
        flow["packet_lengths"].append(length)

        if TCP in packet:
            tcp_seg = packet[TCP]
            flags = tcp_seg.flags
            # TCP flags bits are stable; increment when present
            if flags & 0x02:
                flow["flags"]["syn"] += 1
            if flags & 0x01:
                flow["flags"]["fin"] += 1
            if flags & 0x04:
                flow["flags"]["rst"] += 1
            if flags & 0x08:
                flow["flags"]["psh"] += 1
            if flags & 0x10:
                flow["flags"]["ack"] += 1
            if flags & 0x20:
                flow["flags"]["urg"] += 1
            if flags & 0x40:
                flow["flags"]["ece"] += 1
            flow["fwd_header_len_total"] += int(tcp_seg.dataofs) * 4
            if flow["init_win_fwd"] == 0:
                flow["init_win_fwd"] = int(tcp_seg.window)

    def _flow_to_row_lite(self, flow: Dict[str, object]) -> Dict[str, float]:
        duration = max(time.time() - float(flow["start_time"]), 1e-6)
        lengths = flow["packet_lengths"]
        pkt_min = min(lengths) if lengths else 0.0
        pkt_max = max(lengths) if lengths else 0.0
        pkt_mean = sum(lengths) / len(lengths) if lengths else 0.0

        iats = flow["iat_list"]
        iat_mean = sum(iats) / len(iats) if iats else 0.0
        iat_std = pd.Series(iats).std(ddof=0) if iats else 0.0

        flow_bytes_s = (flow["total_len_fwd"] + flow["total_len_bwd"]) / duration

        base_values = {
            "Flow Duration": duration,
            "Total Fwd Packets": flow["total_fwd_packets"],
            "Total Backward Packets": flow["total_bwd_packets"],
            "Total Length of Fwd Packets": flow["total_len_fwd"],
            "Total Length of Bwd Packets": flow["total_len_bwd"],
            "Fwd Packet Length Max": pkt_max,
            "Fwd Packet Length Min": pkt_min if flow["total_fwd_packets"] else 0.0,
            "Fwd Packet Length Mean": pkt_mean,
            "Flow IAT Mean": iat_mean,
            "Fwd IAT Mean": iat_mean,
            "Fwd Header Length": flow["fwd_header_len_total"],
            "Flow IAT Std": iat_std,
            "Flow Bytes/s": flow_bytes_s,
        }

        return base_values

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()