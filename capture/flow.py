import time
import pandas as pd
from typing import Dict


class Flow:
    """Flow class để lưu trữ thông tin flow (bidirectional)"""
    def __init__(self, start_time, src_addr, dst_addr, src_port, dst_port, protocol):
        self.start_time = start_time
        self.last_time = start_time
        # Forward direction (src -> dst)
        self.fwd_pkts = 0
        self.fwd_bytes = 0
        self.fwd_lengths = []
        self.fwd_iats = []
        self.fwd_header_len = 0
        self.fwd_last_time = start_time
        # Backward direction (dst -> src)
        self.bwd_pkts = 0
        self.bwd_bytes = 0
        self.bwd_lengths = []
        self.bwd_iats = []
        self.bwd_header_len = 0
        self.bwd_last_time = start_time
        # Flow-level IAT (giữa mọi packet liên tiếp, không phân biệt direction)
        self.flow_iats = []
        self.flow_last_time = start_time
        # Flow metadata để xác định direction
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol  # 6=TCP, 17=UDP
        self.flushed = False
        self.is_terminated = False  # Flag để đánh dấu flow đã kết thúc (FIN packet)
        # TCP Flags counters
        self.fwd_fin_flags = 0
        self.bwd_fin_flags = 0
        self.fwd_syn_flags = 0
        self.bwd_syn_flags = 0
        self.fwd_rst_flags = 0
        self.bwd_rst_flags = 0
        self.fwd_psh_flags = 0
        self.bwd_psh_flags = 0
        self.fwd_ack_flags = 0
        self.bwd_ack_flags = 0
        self.fwd_urg_flags = 0
        self.bwd_urg_flags = 0
        self.fwd_cwr_flags = 0
        self.bwd_cwr_flags = 0
        self.fwd_ece_flags = 0
        self.bwd_ece_flags = 0
        # Subflow tracking (snapshot của flow tại một thời điểm)
        self.subflow_fwd_packets = 0
        self.subflow_fwd_bytes = 0
        self.subflow_bwd_packets = 0
        self.subflow_bwd_bytes = 0

    def reset_counters(self, new_start_time):
        """Reset counters sau khi flush snapshot (để tiếp tục tracking flow active)"""
        self.start_time = new_start_time
        self.fwd_pkts = 0
        self.fwd_bytes = 0
        self.fwd_lengths = []
        self.fwd_iats = []
        self.fwd_header_len = 0
        self.fwd_last_time = new_start_time
        self.bwd_pkts = 0
        self.bwd_bytes = 0
        self.bwd_lengths = []
        self.bwd_iats = []
        self.bwd_header_len = 0
        self.bwd_last_time = new_start_time
        self.flow_iats = []
        self.flow_last_time = new_start_time
        # Reset flags counters
        self.fwd_fin_flags = 0
        self.bwd_fin_flags = 0
        self.fwd_syn_flags = 0
        self.bwd_syn_flags = 0
        self.fwd_rst_flags = 0
        self.bwd_rst_flags = 0
        self.fwd_psh_flags = 0
        self.bwd_psh_flags = 0
        self.fwd_ack_flags = 0
        self.bwd_ack_flags = 0
        self.fwd_urg_flags = 0
        self.bwd_urg_flags = 0
        self.fwd_cwr_flags = 0
        self.bwd_cwr_flags = 0
        self.fwd_ece_flags = 0
        self.bwd_ece_flags = 0
        # Reset subflow (snapshot sẽ được update khi flush)
        self.subflow_fwd_packets = 0
        self.subflow_fwd_bytes = 0
        self.subflow_bwd_packets = 0
        self.subflow_bwd_bytes = 0

    def update(self, length, header_len, now, is_forward: bool, tcp_flags: int = 0):
        """Update flow với packet, is_forward=True nếu packet đi từ src->dst
        length: total packet length (bao gồm cả IP header)
        header_len: total header length (IP + TCP/UDP)
        tcp_flags: TCP flags byte (chỉ có ý nghĩa với TCP packets)
        """
        # Flow-level IAT: tính giữa mọi packet liên tiếp (không phân biệt direction)
        flow_iat = (now - self.flow_last_time) * 1_000_000  # Microseconds
        if self.fwd_pkts + self.bwd_pkts > 0:  # Không tính IAT cho packet đầu tiên
            self.flow_iats.append(flow_iat)
        self.flow_last_time = now
        
        if is_forward:
            # Forward direction IAT
            iat = (now - self.fwd_last_time) * 1_000_000  # Microseconds
            if self.fwd_pkts > 0:
                self.fwd_iats.append(iat)
            self.fwd_last_time = now
            self.fwd_pkts += 1
            self.fwd_bytes += length
            self.fwd_lengths.append(length)
            self.fwd_header_len += header_len
        else:
            # Backward direction IAT
            iat = (now - self.bwd_last_time) * 1_000_000  # Microseconds
            if self.bwd_pkts > 0:
                self.bwd_iats.append(iat)
            self.bwd_last_time = now
            self.bwd_pkts += 1
            self.bwd_bytes += length
            self.bwd_lengths.append(length)
            self.bwd_header_len += header_len
        
        # Track TCP flags (chỉ với TCP packets, tcp_flags > 0)
        if tcp_flags > 0:
            if is_forward:
                if tcp_flags & 0x01:  # FIN
                    self.fwd_fin_flags += 1
                if tcp_flags & 0x02:  # SYN
                    self.fwd_syn_flags += 1
                if tcp_flags & 0x04:  # RST
                    self.fwd_rst_flags += 1
                if tcp_flags & 0x08:  # PSH
                    self.fwd_psh_flags += 1
                if tcp_flags & 0x10:  # ACK
                    self.fwd_ack_flags += 1
                if tcp_flags & 0x20:  # URG
                    self.fwd_urg_flags += 1
                if tcp_flags & 0x40:  # ECE
                    self.fwd_ece_flags += 1
                if tcp_flags & 0x80:  # CWR
                    self.fwd_cwr_flags += 1
            else:
                if tcp_flags & 0x01:  # FIN
                    self.bwd_fin_flags += 1
                if tcp_flags & 0x02:  # SYN
                    self.bwd_syn_flags += 1
                if tcp_flags & 0x04:  # RST
                    self.bwd_rst_flags += 1
                if tcp_flags & 0x08:  # PSH
                    self.bwd_psh_flags += 1
                if tcp_flags & 0x10:  # ACK
                    self.bwd_ack_flags += 1
                if tcp_flags & 0x20:  # URG
                    self.bwd_urg_flags += 1
                if tcp_flags & 0x40:  # ECE
                    self.bwd_ece_flags += 1
                if tcp_flags & 0x80:  # CWR
                    self.bwd_cwr_flags += 1
        
        self.last_time = now

    def to_features(self) -> Dict[str, float]:
        duration = (self.last_time - self.start_time) * 1_000_000  # Microseconds
        if duration <= 0:
            duration = 1.0  # Tránh chia cho 0
        
        # Forward IAT stats
        fwd_iat_total = sum(self.fwd_iats) if self.fwd_iats else 0
        fwd_mean_iat = fwd_iat_total / len(self.fwd_iats) if self.fwd_iats else 0.0
        fwd_std_iat = pd.Series(self.fwd_iats).std() if len(self.fwd_iats) > 1 else 0.0
        fwd_iat_max = max(self.fwd_iats) if self.fwd_iats else 0
        fwd_iat_min = min(self.fwd_iats) if self.fwd_iats else 0
        
        # Backward IAT stats
        bwd_iat_total = sum(self.bwd_iats) if self.bwd_iats else 0
        bwd_mean_iat = bwd_iat_total / len(self.bwd_iats) if self.bwd_iats else 0.0
        bwd_std_iat = pd.Series(self.bwd_iats).std() if len(self.bwd_iats) > 1 else 0.0
        bwd_iat_max = max(self.bwd_iats) if self.bwd_iats else 0
        bwd_iat_min = min(self.bwd_iats) if self.bwd_iats else 0
        
        # Flow-level IAT: giữa mọi packet liên tiếp (không phân biệt direction)
        flow_mean_iat = sum(self.flow_iats) / len(self.flow_iats) if self.flow_iats else 0.0
        flow_std_iat = pd.Series(self.flow_iats).std() if len(self.flow_iats) > 1 else 0.0
        flow_iat_max = max(self.flow_iats) if self.flow_iats else 0
        flow_iat_min = min(self.flow_iats) if self.flow_iats else 0
        
        total_bytes = self.fwd_bytes + self.bwd_bytes
        total_packets = self.fwd_pkts + self.bwd_pkts
        
        # All packet lengths (forward + backward)
        all_lengths = self.fwd_lengths + self.bwd_lengths
        
        # Forward packet statistics
        fwd_pkt_len_std = pd.Series(self.fwd_lengths).std() if len(self.fwd_lengths) > 1 else 0.0
        
        # Backward packet statistics
        bwd_pkt_len_mean = sum(self.bwd_lengths) / len(self.bwd_lengths) if self.bwd_lengths else 0.0
        bwd_pkt_len_max = max(self.bwd_lengths) if self.bwd_lengths else 0
        bwd_pkt_len_min = min(self.bwd_lengths) if self.bwd_lengths else 0
        bwd_pkt_len_std = pd.Series(self.bwd_lengths).std() if len(self.bwd_lengths) > 1 else 0.0
        
        # Packet length statistics (all packets)
        pkt_len_mean = sum(all_lengths) / len(all_lengths) if all_lengths else 0.0
        pkt_len_min = min(all_lengths) if all_lengths else 0
        pkt_len_max = max(all_lengths) if all_lengths else 0
        pkt_len_std = pd.Series(all_lengths).std() if len(all_lengths) > 1 else 0.0
        pkt_len_var = pd.Series(all_lengths).var() if len(all_lengths) > 1 else 0.0
        
        # Forward segment size (payload = total - header)
        avg_fwd_header_per_pkt = self.fwd_header_len / self.fwd_pkts if self.fwd_pkts > 0 else 0
        fwd_segment_size_avg = (sum(self.fwd_lengths) / len(self.fwd_lengths) if self.fwd_lengths else 0.0) - avg_fwd_header_per_pkt if self.fwd_pkts > 0 else 0.0
        fwd_segment_size_min = min([l - avg_fwd_header_per_pkt for l in self.fwd_lengths]) if self.fwd_lengths and self.fwd_pkts > 0 else 0
        
        # Backward segment size (payload = total - header)
        avg_bwd_header_per_pkt = self.bwd_header_len / self.bwd_pkts if self.bwd_pkts > 0 else 0
        bwd_segment_size_avg = bwd_pkt_len_mean - avg_bwd_header_per_pkt if self.bwd_pkts > 0 else 0.0
        
        # Active/Idle time statistics
        # Active time: simplified as flow duration (time from start to last packet)
        # Idle time: IAT between packets (already in flow_iats)
        active_mean = duration  # Simplified: active time = flow duration
        active_std = 0.0  # Single value, no std
        active_max = duration
        active_min = duration
        
        # Idle time = IAT (time between packets)
        idle_mean = flow_mean_iat  # Same as Flow IAT Mean
        idle_std = flow_std_iat  # Same as Flow IAT Std
        idle_max = flow_iat_max  # Same as Flow IAT Max
        idle_min = flow_iat_min  # Same as Flow IAT Min
        
        # TCP flag counts
        fin_flag_count = self.fwd_fin_flags + self.bwd_fin_flags
        syn_flag_count = self.fwd_syn_flags + self.bwd_syn_flags
        rst_flag_count = self.fwd_rst_flags + self.bwd_rst_flags
        psh_flag_count = self.fwd_psh_flags + self.bwd_psh_flags
        ack_flag_count = self.fwd_ack_flags + self.bwd_ack_flags
        urg_flag_count = self.fwd_urg_flags + self.bwd_urg_flags
        cwr_flag_count = self.fwd_cwr_flags + self.bwd_cwr_flags
        ece_flag_count = self.fwd_ece_flags + self.bwd_ece_flags
        
        # Rates
        flow_packets_per_s = (total_packets * 1_000_000) / duration if duration > 0 else 0.0
        fwd_packets_per_s = (self.fwd_pkts * 1_000_000) / duration if duration > 0 else 0.0
        bwd_packets_per_s = (self.bwd_pkts * 1_000_000) / duration if duration > 0 else 0.0
        
        # Ratios
        down_up_ratio = self.bwd_bytes / self.fwd_bytes if self.fwd_bytes > 0 else 0.0
        avg_packet_size = pkt_len_mean  # Same as Packet Length Mean
        
        # Subflow bytes (snapshot tại thời điểm flush)
        # Nếu chưa có snapshot, dùng current values
        if self.subflow_fwd_bytes == 0 and self.subflow_bwd_bytes == 0:
            self.subflow_fwd_packets = self.fwd_pkts
            self.subflow_fwd_bytes = self.fwd_bytes
            self.subflow_bwd_packets = self.bwd_pkts
            self.subflow_bwd_bytes = self.bwd_bytes
        
        # Fwd Act Data Pkts (packets có data, không phải chỉ header)
        # Simplified: packets có length > header length
        fwd_act_data_pkts = sum(1 for l in self.fwd_lengths if l > avg_fwd_header_per_pkt) if self.fwd_pkts > 0 else 0
        
        # Bulk transfer features (simplified - không có thông tin đầy đủ về bulk transfers)
        # Fwd Bytes/Bulk Avg, Fwd Packet/Bulk Avg, Fwd Bulk Rate Avg
        # Bwd Bytes/Bulk Avg, Bwd Packet/Bulk Avg, Bwd Bulk Rate Avg
        # Đặt giá trị mặc định = 0 vì không có thông tin đầy đủ
        
        # Init Win Bytes (không có thông tin từ raw socket, đặt = 0)
        fwd_init_win_bytes = 0
        bwd_init_win_bytes = 0
        
        # Total TCP Flow Time (chỉ với TCP, = Flow Duration)
        total_tcp_flow_time = duration
        
        # ICMP Code/Type (không xử lý ICMP, đặt = 0)
        icmp_code = 0
        icmp_type = 0
        
        return {
            # Basic features (đã có)
            "Flow Duration": duration,
            "Total Fwd Packets": self.fwd_pkts,
            "Total Backward Packets": self.bwd_pkts,
            "Total Length of Fwd Packets": self.fwd_bytes,
            "Total Length of Bwd Packets": self.bwd_bytes,
            "Fwd Packet Length Max": max(self.fwd_lengths) if self.fwd_lengths else 0,
            "Fwd Packet Length Min": min(self.fwd_lengths) if self.fwd_lengths else 0,
            "Fwd Packet Length Mean": sum(self.fwd_lengths) / len(self.fwd_lengths) if self.fwd_lengths else 0,
            "Fwd Packet Length Std": fwd_pkt_len_std,
            "Bwd Packet Length Max": bwd_pkt_len_max,
            "Bwd Packet Length Min": bwd_pkt_len_min,
            "Bwd Packet Length Mean": bwd_pkt_len_mean,
            "Bwd Packet Length Std": bwd_pkt_len_std,
            "Flow Bytes/s": (total_bytes * 1_000_000) / duration,
            "Flow Packets/s": flow_packets_per_s,
            "Flow IAT Mean": flow_mean_iat,
            "Flow IAT Std": flow_std_iat,
            "Flow IAT Max": flow_iat_max,
            "Flow IAT Min": flow_iat_min,
            "Fwd IAT Total": fwd_iat_total,
            "Fwd IAT Mean": fwd_mean_iat,
            "Fwd IAT Std": fwd_std_iat,
            "Fwd IAT Max": fwd_iat_max,
            "Fwd IAT Min": fwd_iat_min,
            "Bwd IAT Total": bwd_iat_total,
            "Bwd IAT Mean": bwd_mean_iat,
            "Bwd IAT Std": bwd_std_iat,
            "Bwd IAT Max": bwd_iat_max,
            "Bwd IAT Min": bwd_iat_min,
            "Fwd PSH Flags": self.fwd_psh_flags,
            "Bwd PSH Flags": self.bwd_psh_flags,
            "Fwd URG Flags": self.fwd_urg_flags,
            "Bwd URG Flags": self.bwd_urg_flags,
            "Fwd RST Flags": self.fwd_rst_flags,
            "Bwd RST Flags": self.bwd_rst_flags,
            "Fwd Header Length": self.fwd_header_len,
            "Bwd Header Length": self.bwd_header_len,
            "Fwd Packets/s": fwd_packets_per_s,
            "Bwd Packets/s": bwd_packets_per_s,
            "Packet Length Min": pkt_len_min,
            "Packet Length Max": pkt_len_max,
            "Packet Length Mean": pkt_len_mean,
            "Packet Length Std": pkt_len_std,
            "Packet Length Variance": pkt_len_var,
            "FIN Flag Count": fin_flag_count,
            "SYN Flag Count": syn_flag_count,
            "RST Flag Count": rst_flag_count,
            "PSH Flag Count": psh_flag_count,
            "ACK Flag Count": ack_flag_count,
            "URG Flag Count": urg_flag_count,
            "CWR Flag Count": cwr_flag_count,
            "ECE Flag Count": ece_flag_count,
            "Down/Up Ratio": down_up_ratio,
            "Average Packet Size": avg_packet_size,
            "Fwd Segment Size Avg": fwd_segment_size_avg,
            "Bwd Segment Size Avg": bwd_segment_size_avg,
            "Fwd Bytes/Bulk Avg": 0,  # Không có thông tin đầy đủ
            "Fwd Packet/Bulk Avg": 0,  # Không có thông tin đầy đủ
            "Fwd Bulk Rate Avg": 0,  # Không có thông tin đầy đủ
            "Bwd Bytes/Bulk Avg": 0,  # Không có thông tin đầy đủ
            "Bwd Packet/Bulk Avg": 0,  # Không có thông tin đầy đủ
            "Bwd Bulk Rate Avg": 0,  # Không có thông tin đầy đủ
            "Subflow Fwd Packets": self.subflow_fwd_packets,
            "Subflow Fwd Bytes": self.subflow_fwd_bytes,
            "Subflow Bwd Packets": self.subflow_bwd_packets,
            "Subflow Bwd Bytes": self.subflow_bwd_bytes,
            "FWD Init Win Bytes": fwd_init_win_bytes,
            "Bwd Init Win Bytes": bwd_init_win_bytes,
            "Fwd Act Data Pkts": fwd_act_data_pkts,
            "Fwd Seg Size Min": fwd_segment_size_min,
            "Active Mean": active_mean,
            "Active Std": active_std,
            "Active Max": active_max,
            "Active Min": active_min,
            "Idle Mean": idle_mean,
            "Idle Std": idle_std,
            "Idle Max": idle_max,
            "Idle Min": idle_min,
            "ICMP Code": icmp_code,
            "ICMP Type": icmp_type,
            "Total TCP Flow Time": total_tcp_flow_time,
            "Protocol": self.protocol  # 6=TCP, 17=UDP
        }

