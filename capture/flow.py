import time
import pandas as pd
from typing import Dict, List


class Flow:
    """Flow class để lưu trữ thông tin flow (bidirectional) - CICFlowMeter compatible"""
    def __init__(self, start_time, src_addr, dst_addr, src_port, dst_port, protocol, activity_timeout=1_000_000):
        self.start_time = start_time
        self.last_time = start_time
        self.activity_timeout = activity_timeout  # Default 1 second in microseconds
        
        # Forward direction (src -> dst) - using payload bytes (CICFlowMeter compatible)
        self.fwd_pkts = 0
        self.fwd_bytes = 0  # Payload bytes only
        self.fwd_payload_lengths = []  # Payload lengths for statistics
        self.fwd_iats = []
        self.fwd_header_len = 0
        self.fwd_last_time = start_time
        
        # Backward direction (dst -> src) - using payload bytes
        self.bwd_pkts = 0
        self.bwd_bytes = 0  # Payload bytes only
        self.bwd_payload_lengths = []  # Payload lengths for statistics
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
        self.is_terminated = False
        
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
        
        # Subflow detection (1-second gap threshold)
        self.sf_last_packet_ts = -1
        self.sf_count = 0
        self.sf_ac_helper = -1
        
        # Forward bulk transfer tracking
        self.fbulk_duration = 0
        self.fbulk_packet_count = 0
        self.fbulk_size_total = 0
        self.fbulk_state_count = 0
        self.fbulk_packet_count_helper = 0
        self.fbulk_start_helper = 0
        self.fbulk_size_helper = 0
        self.flast_bulk_ts = 0
        
        # Backward bulk transfer tracking
        self.bbulk_duration = 0
        self.bbulk_packet_count = 0
        self.bbulk_size_total = 0
        self.bbulk_state_count = 0
        self.bbulk_packet_count_helper = 0
        self.bbulk_start_helper = 0
        self.bbulk_size_helper = 0
        self.blast_bulk_ts = 0
        
        # Active/Idle period tracking
        self.start_active_time = start_time
        self.end_active_time = start_time
        self.active_periods = []  # List of active period durations (microseconds)
        self.idle_periods = []  # List of idle period durations (microseconds)
        
        # Forward-only data counters (CICFlowMeter compatible)
        self.act_data_pkt_forward = 0  # Packets with payload >= 1 byte
        self.min_seg_size_forward = None  # Minimum header bytes (not payload!)
        self.fwd_init_win_bytes = 0  # TCP window size (not available from raw socket)
        self.bwd_init_win_bytes = 0

    def reset_counters(self, new_start_time):
        """Reset counters sau khi flush snapshot (để tiếp tục tracking flow active)"""
        self.start_time = new_start_time
        self.fwd_pkts = 0
        self.fwd_bytes = 0
        self.fwd_payload_lengths = []
        self.fwd_iats = []
        self.fwd_header_len = 0
        self.fwd_last_time = new_start_time
        self.bwd_pkts = 0
        self.bwd_bytes = 0
        self.bwd_payload_lengths = []
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
        
        # Reset subflow
        self.sf_last_packet_ts = -1
        self.sf_count = 0
        self.sf_ac_helper = -1
        
        # Reset bulk
        self.fbulk_duration = 0
        self.fbulk_packet_count = 0
        self.fbulk_size_total = 0
        self.fbulk_state_count = 0
        self.fbulk_packet_count_helper = 0
        self.fbulk_start_helper = 0
        self.fbulk_size_helper = 0
        self.flast_bulk_ts = 0
        self.bbulk_duration = 0
        self.bbulk_packet_count = 0
        self.bbulk_size_total = 0
        self.bbulk_state_count = 0
        self.bbulk_packet_count_helper = 0
        self.bbulk_start_helper = 0
        self.bbulk_size_helper = 0
        self.blast_bulk_ts = 0
        
        # Reset active/idle
        self.start_active_time = new_start_time
        self.end_active_time = new_start_time
        self.active_periods = []
        self.idle_periods = []
        
        # Reset forward-only counters
        self.act_data_pkt_forward = 0
        self.min_seg_size_forward = None

    def _detect_update_subflows(self, packet_timestamp):
        """Detect subflows based on 1-second gap threshold (CICFlowMeter compatible)"""
        if self.sf_last_packet_ts == -1:
            self.sf_last_packet_ts = packet_timestamp
            self.sf_ac_helper = packet_timestamp
            return
        
        # Check if gap > 1 second (1,000,000 microseconds)
        gap = (packet_timestamp - self.sf_last_packet_ts) * 1_000_000
        if gap > 1_000_000:
            self.sf_count += 1
            # Update active/idle time when subflow detected
            self._update_active_idle_time(packet_timestamp)
            self.sf_ac_helper = packet_timestamp
        
        self.sf_last_packet_ts = packet_timestamp

    def _update_forward_bulk(self, payload_bytes, packet_timestamp):
        """Update forward bulk transfer tracking (CICFlowMeter compatible)"""
        if payload_bytes <= 0:
            return
        
        # Check if backward bulk interrupted forward bulk
        if self.blast_bulk_ts > self.fbulk_start_helper:
            self.fbulk_start_helper = 0
        
        if self.fbulk_start_helper == 0:
            # Start new potential bulk
            self.fbulk_start_helper = packet_timestamp
            self.fbulk_packet_count_helper = 1
            self.fbulk_size_helper = payload_bytes
            self.flast_bulk_ts = packet_timestamp
        else:
            # Check if gap > 1 second
            gap_seconds = ((packet_timestamp - self.flast_bulk_ts) * 1_000_000) / 1_000_000.0
            if gap_seconds > 1.0:
                # Reset bulk
                self.fbulk_start_helper = packet_timestamp
                self.flast_bulk_ts = packet_timestamp
                self.fbulk_packet_count_helper = 1
                self.fbulk_size_helper = payload_bytes
            else:
                # Add to bulk
                self.fbulk_packet_count_helper += 1
                self.fbulk_size_helper += payload_bytes
                
                # New bulk detected (4th packet)
                if self.fbulk_packet_count_helper == 4:
                    self.fbulk_state_count += 1
                    self.fbulk_packet_count += self.fbulk_packet_count_helper
                    self.fbulk_size_total += self.fbulk_size_helper
                    self.fbulk_duration += (packet_timestamp - self.fbulk_start_helper) * 1_000_000
                # Continuation of existing bulk (5th+ packet)
                elif self.fbulk_packet_count_helper > 4:
                    self.fbulk_packet_count += 1
                    self.fbulk_size_total += payload_bytes
                    self.fbulk_duration += (packet_timestamp - self.flast_bulk_ts) * 1_000_000
                
                self.flast_bulk_ts = packet_timestamp

    def _update_backward_bulk(self, payload_bytes, packet_timestamp):
        """Update backward bulk transfer tracking (CICFlowMeter compatible)"""
        if payload_bytes <= 0:
            return
        
        # Check if forward bulk interrupted backward bulk
        if self.flast_bulk_ts > self.bbulk_start_helper:
            self.bbulk_start_helper = 0
        
        if self.bbulk_start_helper == 0:
            # Start new potential bulk
            self.bbulk_start_helper = packet_timestamp
            self.bbulk_packet_count_helper = 1
            self.bbulk_size_helper = payload_bytes
            self.blast_bulk_ts = packet_timestamp
        else:
            # Check if gap > 1 second
            gap_seconds = ((packet_timestamp - self.blast_bulk_ts) * 1_000_000) / 1_000_000.0
            if gap_seconds > 1.0:
                # Reset bulk
                self.bbulk_start_helper = packet_timestamp
                self.blast_bulk_ts = packet_timestamp
                self.bbulk_packet_count_helper = 1
                self.bbulk_size_helper = payload_bytes
            else:
                # Add to bulk
                self.bbulk_packet_count_helper += 1
                self.bbulk_size_helper += payload_bytes
                
                # New bulk detected (4th packet)
                if self.bbulk_packet_count_helper == 4:
                    self.bbulk_state_count += 1
                    self.bbulk_packet_count += self.bbulk_packet_count_helper
                    self.bbulk_size_total += self.bbulk_size_helper
                    self.bbulk_duration += (packet_timestamp - self.bbulk_start_helper) * 1_000_000
                # Continuation of existing bulk (5th+ packet)
                elif self.bbulk_packet_count_helper > 4:
                    self.bbulk_packet_count += 1
                    self.bbulk_size_total += payload_bytes
                    self.bbulk_duration += (packet_timestamp - self.blast_bulk_ts) * 1_000_000
                
                self.blast_bulk_ts = packet_timestamp

    def _update_active_idle_time(self, current_timestamp):
        """Update active/idle period tracking (CICFlowMeter compatible)"""
        current_time_us = current_timestamp * 1_000_000
        end_active_time_us = self.end_active_time * 1_000_000
        start_active_time_us = self.start_active_time * 1_000_000
        
        gap = current_time_us - end_active_time_us
        if gap > self.activity_timeout:
            # Record active period if it exists
            if (end_active_time_us - start_active_time_us) > 0:
                self.active_periods.append(end_active_time_us - start_active_time_us)
            # Record idle period
            self.idle_periods.append(gap)
            # Reset active period
            self.start_active_time = current_timestamp
            self.end_active_time = current_timestamp
        else:
            # Extend active period
            self.end_active_time = current_timestamp

    def _end_active_idle_time(self, current_timestamp, flow_timeout):
        """Finalize active/idle periods on flow termination"""
        current_time_us = current_timestamp * 1_000_000
        end_active_time_us = self.end_active_time * 1_000_000
        start_active_time_us = self.start_active_time * 1_000_000
        
        # Record final active period
        if (end_active_time_us - start_active_time_us) > 0:
            self.active_periods.append(end_active_time_us - start_active_time_us)
        
        # Record final idle period if not terminated by flag
        if not self.is_terminated:
            flow_start_us = self.start_time * 1_000_000
            remaining_idle = (flow_timeout * 1_000_000) - (end_active_time_us - flow_start_us)
            if remaining_idle > 0:
                self.idle_periods.append(remaining_idle)

    def update(self, payload_len, header_len, now, is_forward: bool, tcp_flags: int = 0):
        """Update flow với packet (CICFlowMeter compatible)
        payload_len: payload bytes only (data, excluding headers)
        header_len: total header length (IP + TCP/UDP)
        now: current timestamp in seconds
        is_forward: True nếu packet đi từ flow_src -> flow_dst
        tcp_flags: TCP flags byte (chỉ có ý nghĩa với TCP packets)
        """
        now_us = now * 1_000_000  # Convert to microseconds for calculations
        
        # Update subflow detection
        self._detect_update_subflows(now)
        
        # Update bulk transfer tracking
        if is_forward:
            self._update_forward_bulk(payload_len, now)
        else:
            self._update_backward_bulk(payload_len, now)
        
        # Flow-level IAT: tính giữa mọi packet liên tiếp (không phân biệt direction)
        flow_iat = (now_us - (self.flow_last_time * 1_000_000))
        if self.fwd_pkts + self.bwd_pkts > 0:  # Không tính IAT cho packet đầu tiên
            self.flow_iats.append(flow_iat)
        self.flow_last_time = now
        
        if is_forward:
            # Forward direction IAT
            iat = (now_us - (self.fwd_last_time * 1_000_000))
            if self.fwd_pkts > 0:
                self.fwd_iats.append(iat)
            self.fwd_last_time = now
            self.fwd_pkts += 1
            self.fwd_bytes += payload_len  # Payload bytes only
            self.fwd_payload_lengths.append(payload_len)  # Payload for statistics
            self.fwd_header_len += header_len
            
            # Track Act_data_pkt_forward (payload >= 1 byte)
            if payload_len >= 1:
                self.act_data_pkt_forward += 1
            
            # Track min_seg_size_forward (minimum header bytes, not payload!)
            if self.min_seg_size_forward is None:
                self.min_seg_size_forward = header_len
            else:
                self.min_seg_size_forward = min(self.min_seg_size_forward, header_len)
        else:
            # Backward direction IAT
            iat = (now_us - (self.bwd_last_time * 1_000_000))
            if self.bwd_pkts > 0:
                self.bwd_iats.append(iat)
            self.bwd_last_time = now
            self.bwd_pkts += 1
            self.bwd_bytes += payload_len  # Payload bytes only
            self.bwd_payload_lengths.append(payload_len)  # Payload for statistics
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
        """Calculate all features matching CICFlowMeter FlowFeature enum order"""
        duration = (self.last_time - self.start_time) * 1_000_000  # Microseconds
        if duration <= 0:
            duration = 1.0  # Tránh chia cho 0
        
        # Finalize active/idle periods
        self._end_active_idle_time(self.last_time, 60.0)  # Default 60s timeout
        
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
        
        # Flow-level IAT
        flow_mean_iat = sum(self.flow_iats) / len(self.flow_iats) if self.flow_iats else 0.0
        flow_std_iat = pd.Series(self.flow_iats).std() if len(self.flow_iats) > 1 else 0.0
        flow_iat_max = max(self.flow_iats) if self.flow_iats else 0
        flow_iat_min = min(self.flow_iats) if self.flow_iats else 0
        
        total_bytes = self.fwd_bytes + self.bwd_bytes  # Payload bytes only
        total_packets = self.fwd_pkts + self.bwd_pkts
        
        # All payload lengths (forward + backward) - CICFlowMeter uses payload for statistics
        all_payload_lengths = self.fwd_payload_lengths + self.bwd_payload_lengths
        
        # Forward packet statistics (payload-based)
        fwd_pkt_len_mean = sum(self.fwd_payload_lengths) / len(self.fwd_payload_lengths) if self.fwd_payload_lengths else 0.0
        fwd_pkt_len_max = max(self.fwd_payload_lengths) if self.fwd_payload_lengths else 0
        fwd_pkt_len_min = min(self.fwd_payload_lengths) if self.fwd_payload_lengths else 0
        fwd_pkt_len_std = pd.Series(self.fwd_payload_lengths).std() if len(self.fwd_payload_lengths) > 1 else 0.0
        
        # Backward packet statistics (payload-based)
        bwd_pkt_len_mean = sum(self.bwd_payload_lengths) / len(self.bwd_payload_lengths) if self.bwd_payload_lengths else 0.0
        bwd_pkt_len_max = max(self.bwd_payload_lengths) if self.bwd_payload_lengths else 0
        bwd_pkt_len_min = min(self.bwd_payload_lengths) if self.bwd_payload_lengths else 0
        bwd_pkt_len_std = pd.Series(self.bwd_payload_lengths).std() if len(self.bwd_payload_lengths) > 1 else 0.0
        
        # Packet length statistics (all packets, payload-based)
        pkt_len_mean = sum(all_payload_lengths) / len(all_payload_lengths) if all_payload_lengths else 0.0
        pkt_len_min = min(all_payload_lengths) if all_payload_lengths else 0
        pkt_len_max = max(all_payload_lengths) if all_payload_lengths else 0
        pkt_len_std = pd.Series(all_payload_lengths).std() if len(all_payload_lengths) > 1 else 0.0
        pkt_len_var = pd.Series(all_payload_lengths).var() if len(all_payload_lengths) > 1 else 0.0
        
        # Forward segment size (payload average)
        fwd_segment_size_avg = fwd_pkt_len_mean if self.fwd_pkts > 0 else 0.0
        
        # Backward segment size (payload average)
        bwd_segment_size_avg = bwd_pkt_len_mean if self.bwd_pkts > 0 else 0.0
        
        # Fwd Seg Size Min (minimum header bytes, not payload!)
        fwd_seg_size_min = self.min_seg_size_forward if self.min_seg_size_forward is not None else 0
        
        # Active/Idle time statistics (from tracked periods)
        active_mean = sum(self.active_periods) / len(self.active_periods) if self.active_periods else 0.0
        active_std = pd.Series(self.active_periods).std() if len(self.active_periods) > 1 else 0.0
        active_max = max(self.active_periods) if self.active_periods else 0
        active_min = min(self.active_periods) if self.active_periods else 0
        
        idle_mean = sum(self.idle_periods) / len(self.idle_periods) if self.idle_periods else 0.0
        idle_std = pd.Series(self.idle_periods).std() if len(self.idle_periods) > 1 else 0.0
        idle_max = max(self.idle_periods) if self.idle_periods else 0
        idle_min = min(self.idle_periods) if self.idle_periods else 0
        
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
        avg_packet_size = pkt_len_mean  # Same as Packet Length Mean (payload-based)
        
        # Subflow features (calculated from sf_count, CICFlowMeter compatible)
        sf_count = max(self.sf_count, 1)  # At least 1 subflow
        subflow_fwd_packets = int(self.fwd_pkts / sf_count) if sf_count > 0 else self.fwd_pkts
        subflow_fwd_bytes = int(self.fwd_bytes / sf_count) if sf_count > 0 else self.fwd_bytes
        subflow_bwd_packets = int(self.bwd_pkts / sf_count) if sf_count > 0 else self.bwd_pkts
        subflow_bwd_bytes = int(self.bwd_bytes / sf_count) if sf_count > 0 else self.bwd_bytes
        
        # Bulk transfer features (CICFlowMeter compatible)
        fwd_bytes_bulk_avg = int(self.fbulk_size_total / self.fbulk_state_count) if self.fbulk_state_count > 0 else 0
        fwd_packet_bulk_avg = int(self.fbulk_packet_count / self.fbulk_state_count) if self.fbulk_state_count > 0 else 0
        fbulk_duration_seconds = self.fbulk_duration / 1_000_000.0 if self.fbulk_duration > 0 else 0.0
        fwd_bulk_rate_avg = int(self.fbulk_size_total / fbulk_duration_seconds) if fbulk_duration_seconds > 0 else 0
        
        bwd_bytes_bulk_avg = int(self.bbulk_size_total / self.bbulk_state_count) if self.bbulk_state_count > 0 else 0
        bwd_packet_bulk_avg = int(self.bbulk_packet_count / self.bbulk_state_count) if self.bbulk_state_count > 0 else 0
        bbulk_duration_seconds = self.bbulk_duration / 1_000_000.0 if self.bbulk_duration > 0 else 0.0
        bwd_bulk_rate_avg = int(self.bbulk_size_total / bbulk_duration_seconds) if bbulk_duration_seconds > 0 else 0
        
        # Total TCP Flow Time (same as Flow Duration)
        total_tcp_flow_time = duration
        
        # ICMP Code/Type (not processed, set = 0)
        icmp_code = 0
        icmp_type = 0
        
        # Return features in FlowFeature enum order
        # Note: Protocol (6) is included in metadata in CICFlowMeter but we include it in features
        # The 84 features start from Flow Duration (8) through Idle Min (84)
        return {
            # 6. Protocol (included for compatibility)
            "Protocol": self.protocol,
            # 8. Flow Duration
            "Flow Duration": duration,
            # 9-10. Total Fwd/Bwd Packets
            "Total Fwd Packets": self.fwd_pkts,
            "Total Backward Packets": self.bwd_pkts,
            # 11-12. Total Length of Fwd/Bwd Packets (payload bytes)
            "Total Length of Fwd Packets": self.fwd_bytes,
            "Total Length of Bwd Packets": self.bwd_bytes,
            # 13-16. Fwd Packet Length Max/Min/Mean/Std (payload-based)
            "Fwd Packet Length Max": fwd_pkt_len_max,
            "Fwd Packet Length Min": fwd_pkt_len_min,
            "Fwd Packet Length Mean": fwd_pkt_len_mean,
            "Fwd Packet Length Std": fwd_pkt_len_std,
            # 17-20. Bwd Packet Length Max/Min/Mean/Std (payload-based)
            "Bwd Packet Length Max": bwd_pkt_len_max,
            "Bwd Packet Length Min": bwd_pkt_len_min,
            "Bwd Packet Length Mean": bwd_pkt_len_mean,
            "Bwd Packet Length Std": bwd_pkt_len_std,
            # 21-22. Flow Bytes/s, Packets/s
            "Flow Bytes/s": (total_bytes * 1_000_000) / duration if duration > 0 else 0.0,
            "Flow Packets/s": flow_packets_per_s,
            # 23-26. Flow IAT Mean/Std/Max/Min
            "Flow IAT Mean": flow_mean_iat,
            "Flow IAT Std": flow_std_iat,
            "Flow IAT Max": flow_iat_max,
            "Flow IAT Min": flow_iat_min,
            # 27-31. Fwd IAT Total/Mean/Std/Max/Min
            "Fwd IAT Total": fwd_iat_total,
            "Fwd IAT Mean": fwd_mean_iat,
            "Fwd IAT Std": fwd_std_iat,
            "Fwd IAT Max": fwd_iat_max,
            "Fwd IAT Min": fwd_iat_min,
            # 32-36. Bwd IAT Total/Mean/Std/Max/Min
            "Bwd IAT Total": bwd_iat_total,
            "Bwd IAT Mean": bwd_mean_iat,
            "Bwd IAT Std": bwd_std_iat,
            "Bwd IAT Max": bwd_iat_max,
            "Bwd IAT Min": bwd_iat_min,
            # 37-40. Fwd/Bwd PSH/URG Flags
            "Fwd PSH Flags": self.fwd_psh_flags,
            "Bwd PSH Flags": self.bwd_psh_flags,
            "Fwd URG Flags": self.fwd_urg_flags,
            "Bwd URG Flags": self.bwd_urg_flags,
            # 41-42. Fwd/Bwd Header Length
            "Fwd Header Length": self.fwd_header_len,
            "Bwd Header Length": self.bwd_header_len,
            # 43-44. Fwd/Bwd Packets/s
            "Fwd Packets/s": fwd_packets_per_s,
            "Bwd Packets/s": bwd_packets_per_s,
            # 45-49. Packet Length Min/Max/Mean/Std/Variance (payload-based)
            "Packet Length Min": pkt_len_min,
            "Packet Length Max": pkt_len_max,
            "Packet Length Mean": pkt_len_mean,
            "Packet Length Std": pkt_len_std,
            "Packet Length Variance": pkt_len_var,
            # 50-57. Flag Counts
            "FIN Flag Count": fin_flag_count,
            "SYN Flag Count": syn_flag_count,
            "RST Flag Count": rst_flag_count,
            "PSH Flag Count": psh_flag_count,
            "ACK Flag Count": ack_flag_count,
            "URG Flag Count": urg_flag_count,
            "CWR Flag Count": cwr_flag_count,
            "ECE Flag Count": ece_flag_count,
            # 58-59. Down/Up Ratio, Average Packet Size
            "Down/Up Ratio": down_up_ratio,
            "Average Packet Size": avg_packet_size,
            # 60-61. Fwd/Bwd Segment Size Avg (payload average)
            "Fwd Segment Size Avg": fwd_segment_size_avg,
            "Bwd Segment Size Avg": bwd_segment_size_avg,
            # 63-65. Fwd Bytes/Bulk Avg, Packet/Bulk Avg, Bulk Rate Avg
            "Fwd Bytes/Bulk Avg": fwd_bytes_bulk_avg,
            "Fwd Packet/Bulk Avg": fwd_packet_bulk_avg,
            "Fwd Bulk Rate Avg": fwd_bulk_rate_avg,
            # 66-68. Bwd Bytes/Bulk Avg, Packet/Bulk Avg, Bulk Rate Avg
            "Bwd Bytes/Bulk Avg": bwd_bytes_bulk_avg,
            "Bwd Packet/Bulk Avg": bwd_packet_bulk_avg,
            "Bwd Bulk Rate Avg": bwd_bulk_rate_avg,
            # 69-72. Subflow Fwd/Bwd Packets/Bytes
            "Subflow Fwd Packets": subflow_fwd_packets,
            "Subflow Fwd Bytes": subflow_fwd_bytes,
            "Subflow Bwd Packets": subflow_bwd_packets,
            "Subflow Bwd Bytes": subflow_bwd_bytes,
            # 73-74. FWD/Bwd Init Win Bytes (not available from raw socket)
            "FWD Init Win Bytes": self.fwd_init_win_bytes,
            "Bwd Init Win Bytes": self.bwd_init_win_bytes,
            # 75-76. Fwd Act Data Pkts, Fwd Seg Size Min
            "Fwd Act Data Pkts": self.act_data_pkt_forward,
            "Fwd Seg Size Min": fwd_seg_size_min,
            # 77-80. Active Mean/Std/Max/Min
            "Active Mean": active_mean,
            "Active Std": active_std,
            "Active Max": active_max,
            "Active Min": active_min,
            # 81-84. Idle Mean/Std/Max/Min
            "Idle Mean": idle_mean,
            "Idle Std": idle_std,
            "Idle Max": idle_max,
            "Idle Min": idle_min,
            # Additional features for compatibility with older CSV files
            "Fwd RST Flags": self.fwd_rst_flags,  # Forward RST flags count
            "Bwd RST Flags": self.bwd_rst_flags,  # Backward RST flags count
            "ICMP Code": icmp_code,  # ICMP code (0 for TCP/UDP)
            "ICMP Type": icmp_type,  # ICMP type (0 for TCP/UDP)
            "Total TCP Flow Time": total_tcp_flow_time  # Same as Flow Duration for TCP
        }
