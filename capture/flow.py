import time
import datetime
from typing import Dict, Union
from .statistics import StatisticsAccumulator
from .flow_feature import FlowFeature



class Flow:
    """Flow class để lưu trữ thông tin flow (bidirectional) - CICFlowMeter compatible"""
    def __init__(self, start_time, src_addr, dst_addr, src_port, dst_port, protocol, activity_timeout=1_000_000):
        self.start_time = start_time
        self.last_time = start_time
        self.activity_timeout = activity_timeout  # Default 1 second in microseconds
        
        # Forward direction (src -> dst) - using payload bytes (CICFlowMeter compatible)
        self.fwd_pkts = 0
        self.fwd_bytes = 0  # Payload bytes only
        self.fwd_pkt_len_stats = StatisticsAccumulator()  # Payload lengths statistics
        self.fwd_iat_stats = StatisticsAccumulator()  # Forward IAT statistics
        self.fwd_header_len = 0
        self.fwd_last_time = start_time
        
        # Backward direction (dst -> src) - using payload bytes
        self.bwd_pkts = 0
        self.bwd_bytes = 0  # Payload bytes only
        self.bwd_pkt_len_stats = StatisticsAccumulator()  # Payload lengths statistics
        self.bwd_iat_stats = StatisticsAccumulator()  # Backward IAT statistics
        self.bwd_header_len = 0
        self.bwd_last_time = start_time
        
        # Flow-level IAT (giữa mọi packet liên tiếp, không phân biệt direction)
        self.flow_iat_stats = StatisticsAccumulator()  # Flow IAT statistics
        self.flow_last_time = start_time
        
        # Flow-level packet length statistics (all packets, payload-based) - CICFlowMeter compatible
        # Java uses a single flowLengthStats that tracks ALL packets together
        self.flow_length_stats = StatisticsAccumulator()  # All packet payload lengths
        
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
        self.active_stats = StatisticsAccumulator()  # Active period statistics
        self.idle_stats = StatisticsAccumulator()  # Idle period statistics
        
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
        self.fwd_pkt_len_stats.reset()
        self.fwd_iat_stats.reset()
        self.fwd_header_len = 0
        self.fwd_last_time = new_start_time
        self.bwd_pkts = 0
        self.bwd_bytes = 0
        self.bwd_pkt_len_stats.reset()
        self.bwd_iat_stats.reset()
        self.bwd_header_len = 0
        self.bwd_last_time = new_start_time
        self.flow_iat_stats.reset()
        self.flow_last_time = new_start_time
        self.flow_length_stats.reset()
        
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
        self.active_stats.reset()
        self.idle_stats.reset()
        
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
                self.active_stats.add_value(end_active_time_us - start_active_time_us)
            # Record idle period
            self.idle_stats.add_value(gap)
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
            self.active_stats.add_value(end_active_time_us - start_active_time_us)
        
        # Record final idle period if not terminated by flag
        if not self.is_terminated:
            flow_start_us = self.start_time * 1_000_000
            remaining_idle = (flow_timeout * 1_000_000) - (end_active_time_us - flow_start_us)
            if remaining_idle > 0:
                self.idle_stats.add_value(remaining_idle)

    def update_primitives(
        self,
        timestamp: float,
        payload_len: int,
        header_len: int,
        tcp_flags: int,
        protocol: int,
        is_forward: bool,
    ) -> None:
        """Hot-path update with primitives only (zero-allocation per packet)."""

        now_us = timestamp * 1_000_000  # Convert to microseconds for calculations
        
        # Update subflow detection
        self._detect_update_subflows(timestamp)
        
        # Update bulk transfer tracking
        if is_forward:
            self._update_forward_bulk(payload_len, timestamp)
        else:
            self._update_backward_bulk(payload_len, timestamp)
        
        # Flow-level IAT: tính giữa mọi packet liên tiếp (không phân biệt direction)
        flow_iat = (now_us - (self.flow_last_time * 1_000_000))
        if self.fwd_pkts + self.bwd_pkts > 0:  # Không tính IAT cho packet đầu tiên
            self.flow_iat_stats.add_value(flow_iat)
        self.flow_last_time = timestamp
        
        if is_forward:
            # Forward direction IAT
            iat = (now_us - (self.fwd_last_time * 1_000_000))
            if self.fwd_pkts > 0:
                self.fwd_iat_stats.add_value(iat)
            self.fwd_last_time = timestamp
            self.fwd_pkts += 1
            self.fwd_bytes += payload_len  # Payload bytes only
            self.fwd_pkt_len_stats.add_value(payload_len)  # Payload for statistics
            self.flow_length_stats.add_value(payload_len)  # Track in unified flow stats (CICFlowMeter compatible)
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
                self.bwd_iat_stats.add_value(iat)
            self.bwd_last_time = timestamp
            self.bwd_pkts += 1
            self.bwd_bytes += payload_len  # Payload bytes only
            self.bwd_pkt_len_stats.add_value(payload_len)  # Payload for statistics
            self.flow_length_stats.add_value(payload_len)  # Track in unified flow stats (CICFlowMeter compatible)
            self.bwd_header_len += header_len
        
        # Track TCP flags (only meaningful for TCP)
        if protocol == 6 and tcp_flags:
            fin = (tcp_flags & 0x01) != 0
            syn = (tcp_flags & 0x02) != 0
            rst = (tcp_flags & 0x04) != 0
            psh = (tcp_flags & 0x08) != 0
            ack = (tcp_flags & 0x10) != 0
            urg = (tcp_flags & 0x20) != 0
            ece = (tcp_flags & 0x40) != 0
            cwr = (tcp_flags & 0x80) != 0

            if is_forward:
                if fin:
                    self.fwd_fin_flags += 1
                if syn:
                    self.fwd_syn_flags += 1
                if rst:
                    self.fwd_rst_flags += 1
                if psh:
                    self.fwd_psh_flags += 1
                if ack:
                    self.fwd_ack_flags += 1
                if urg:
                    self.fwd_urg_flags += 1
                if ece:
                    self.fwd_ece_flags += 1
                if cwr:
                    self.fwd_cwr_flags += 1
            else:
                if fin:
                    self.bwd_fin_flags += 1
                if syn:
                    self.bwd_syn_flags += 1
                if rst:
                    self.bwd_rst_flags += 1
                if psh:
                    self.bwd_psh_flags += 1
                if ack:
                    self.bwd_ack_flags += 1
                if urg:
                    self.bwd_urg_flags += 1
                if ece:
                    self.bwd_ece_flags += 1
                if cwr:
                    self.bwd_cwr_flags += 1

        self.last_time = timestamp

    def update(self, packet, is_forward: bool):
        """Compatibility wrapper; avoid using this in the capture hot path."""
        self.update_primitives(
            timestamp=packet.timestamp,
            payload_len=packet.payload_len,
            header_len=packet.header_len,
            tcp_flags=packet.tcp_flags,
            protocol=packet.protocol,
            is_forward=is_forward,
        )

    def to_features(self) -> Dict[str, Union[str, int, float]]:
        """Calculate all flow fields for CSV export.

        Includes CICFlowMeter-style metadata columns (Flow ID, 5-tuple, Timestamp)
        plus the numeric feature set calculated by `FlowFeature`.
        """

        feat = FlowFeature.calculate(self)

        # CIC-like Flow ID format used by the provided datasets:
        #   srcIP-dstIP-srcPort-dstPort-proto
        flow_id = f"{self.src_addr}-{self.dst_addr}-{self.src_port}-{self.dst_port}-{self.protocol}"

        # Timestamp format observed in `data/wednesday.csv`: YYYY-MM-DD HH:MM:SS.ffffff
        ts = datetime.datetime.fromtimestamp(float(self.start_time))
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S.%f")

        meta: Dict[str, Union[str, int, float]] = {
            "Flow ID": flow_id,
            "Src IP": str(self.src_addr),
            "Src Port": int(self.src_port),
            "Dst IP": str(self.dst_addr),
            "Dst Port": int(self.dst_port),
            "Protocol": int(self.protocol),
            "Timestamp": ts_str,
        }

        # Do not mutate `feat`; merge into a new dict.
        return {**meta, **feat}
