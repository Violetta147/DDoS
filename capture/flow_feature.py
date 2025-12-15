"""FlowFeature class for calculating features from Flow state (CICFlowMeter compatible)"""
from typing import Dict


class FlowFeature:
    """Calculate features from Flow state - separated from Flow class for better architecture"""
    
    @staticmethod
    def calculate(flow) -> Dict[str, float]:
        """
        Calculate all features matching CICFlowMeter FlowFeature enum order
        
        Args:
            flow: Flow object containing all state information
            
        Returns:
            Dictionary of feature names to values (82 features total)
        """
        # Finalize active/idle periods before calculation
        flow._end_active_idle_time(flow.last_time, 60.0)  # Default 60s timeout
        
        # Calculate flow duration
        duration = (flow.last_time - flow.start_time) * 1_000_000  # Microseconds
        if duration <= 0:
            duration = 1.0  # Avoid division by zero
        
        # Forward IAT stats
        fwd_iat_total = flow.fwd_iat_stats.get_sum()
        fwd_mean_iat = flow.fwd_iat_stats.get_mean()
        fwd_std_iat = flow.fwd_iat_stats.get_std()
        fwd_iat_max = flow.fwd_iat_stats.get_max()
        fwd_iat_min = flow.fwd_iat_stats.get_min()
        
        # Backward IAT stats
        bwd_iat_total = flow.bwd_iat_stats.get_sum()
        bwd_mean_iat = flow.bwd_iat_stats.get_mean()
        bwd_std_iat = flow.bwd_iat_stats.get_std()
        bwd_iat_max = flow.bwd_iat_stats.get_max()
        bwd_iat_min = flow.bwd_iat_stats.get_min()
        
        # Flow-level IAT
        flow_mean_iat = flow.flow_iat_stats.get_mean()
        flow_std_iat = flow.flow_iat_stats.get_std()
        flow_iat_max = flow.flow_iat_stats.get_max()
        flow_iat_min = flow.flow_iat_stats.get_min()
        
        total_bytes = flow.fwd_bytes + flow.bwd_bytes  # Payload bytes only
        total_packets = flow.fwd_pkts + flow.bwd_pkts
        
        # Forward packet statistics (payload-based)
        fwd_pkt_len_mean = flow.fwd_pkt_len_stats.get_mean()
        fwd_pkt_len_max = flow.fwd_pkt_len_stats.get_max()
        fwd_pkt_len_min = flow.fwd_pkt_len_stats.get_min()
        fwd_pkt_len_std = flow.fwd_pkt_len_stats.get_std()
        
        # Backward packet statistics (payload-based)
        bwd_pkt_len_mean = flow.bwd_pkt_len_stats.get_mean()
        bwd_pkt_len_max = flow.bwd_pkt_len_stats.get_max()
        bwd_pkt_len_min = flow.bwd_pkt_len_stats.get_min()
        bwd_pkt_len_std = flow.bwd_pkt_len_stats.get_std()
        
        # Packet length statistics (all packets, payload-based)
        # Java uses a single flowLengthStats that tracks ALL packets together (CICFlowMeter compatible)
        # This is different from combining two separate statistics - we need unified tracking
        if flow.flow_length_stats.get_count() > 0:
            pkt_len_min = flow.flow_length_stats.get_min()
            pkt_len_max = flow.flow_length_stats.get_max()
            pkt_len_mean = flow.flow_length_stats.get_mean()
            pkt_len_std = flow.flow_length_stats.get_std()
            pkt_len_var = flow.flow_length_stats.get_variance()
        else:
            pkt_len_min = 0.0
            pkt_len_max = 0.0
            pkt_len_mean = 0.0
            pkt_len_std = 0.0
            pkt_len_var = 0.0
        
        # Forward segment size (payload average)
        fwd_segment_size_avg = fwd_pkt_len_mean if flow.fwd_pkts > 0 else 0.0
        
        # Backward segment size (payload average)
        bwd_segment_size_avg = bwd_pkt_len_mean if flow.bwd_pkts > 0 else 0.0
        
        # Fwd Seg Size Min (minimum header bytes, not payload!)
        fwd_seg_size_min = flow.min_seg_size_forward if flow.min_seg_size_forward is not None else 0
        
        # Active/Idle time statistics (from tracked periods)
        active_mean = flow.active_stats.get_mean()
        active_std = flow.active_stats.get_std()
        active_max = flow.active_stats.get_max()
        active_min = flow.active_stats.get_min()
        
        idle_mean = flow.idle_stats.get_mean()
        idle_std = flow.idle_stats.get_std()
        idle_max = flow.idle_stats.get_max()
        idle_min = flow.idle_stats.get_min()
        
        # TCP flag counts
        fin_flag_count = flow.fwd_fin_flags + flow.bwd_fin_flags
        syn_flag_count = flow.fwd_syn_flags + flow.bwd_syn_flags
        rst_flag_count = flow.fwd_rst_flags + flow.bwd_rst_flags
        psh_flag_count = flow.fwd_psh_flags + flow.bwd_psh_flags
        ack_flag_count = flow.fwd_ack_flags + flow.bwd_ack_flags
        urg_flag_count = flow.fwd_urg_flags + flow.bwd_urg_flags
        cwr_flag_count = flow.fwd_cwr_flags + flow.bwd_cwr_flags
        ece_flag_count = flow.fwd_ece_flags + flow.bwd_ece_flags
        
        # Rates
        flow_packets_per_s = (total_packets * 1_000_000) / duration if duration > 0 else 0.0
        fwd_packets_per_s = (flow.fwd_pkts * 1_000_000) / duration if duration > 0 else 0.0
        bwd_packets_per_s = (flow.bwd_pkts * 1_000_000) / duration if duration > 0 else 0.0
        
        # Ratios
        down_up_ratio = flow.bwd_bytes / flow.fwd_bytes if flow.fwd_bytes > 0 else 0.0
        avg_packet_size = pkt_len_mean  # Same as Packet Length Mean (payload-based)
        
        # Subflow features (calculated from sf_count, CICFlowMeter compatible)
        sf_count = max(flow.sf_count, 1)  # At least 1 subflow
        subflow_fwd_packets = int(flow.fwd_pkts / sf_count) if sf_count > 0 else flow.fwd_pkts
        subflow_fwd_bytes = int(flow.fwd_bytes / sf_count) if sf_count > 0 else flow.fwd_bytes
        subflow_bwd_packets = int(flow.bwd_pkts / sf_count) if sf_count > 0 else flow.bwd_pkts
        subflow_bwd_bytes = int(flow.bwd_bytes / sf_count) if sf_count > 0 else flow.bwd_bytes
        
        # Bulk transfer features (CICFlowMeter compatible)
        fwd_bytes_bulk_avg = int(flow.fbulk_size_total / flow.fbulk_state_count) if flow.fbulk_state_count > 0 else 0
        fwd_packet_bulk_avg = int(flow.fbulk_packet_count / flow.fbulk_state_count) if flow.fbulk_state_count > 0 else 0
        fbulk_duration_seconds = flow.fbulk_duration / 1_000_000.0 if flow.fbulk_duration > 0 else 0.0
        fwd_bulk_rate_avg = int(flow.fbulk_size_total / fbulk_duration_seconds) if fbulk_duration_seconds > 0 else 0
        
        bwd_bytes_bulk_avg = int(flow.bbulk_size_total / flow.bbulk_state_count) if flow.bbulk_state_count > 0 else 0
        bwd_packet_bulk_avg = int(flow.bbulk_packet_count / flow.bbulk_state_count) if flow.bbulk_state_count > 0 else 0
        bbulk_duration_seconds = flow.bbulk_duration / 1_000_000.0 if flow.bbulk_duration > 0 else 0.0
        bwd_bulk_rate_avg = int(flow.bbulk_size_total / bbulk_duration_seconds) if bbulk_duration_seconds > 0 else 0
        
        # Total TCP Flow Time (same as Flow Duration)
        total_tcp_flow_time = duration
        
        # ICMP Code/Type (not processed, set = 0)
        icmp_code = 0
        icmp_type = 0
        
        # Return features in FlowFeature enum order
        # Note: Protocol (6) is included in metadata in CICFlowMeter but we include it in features
        # The 82 features start from Protocol through Total TCP Flow Time
        return {
            # 6. Protocol (included for compatibility)
            "Protocol": flow.protocol,
            # 8. Flow Duration
            "Flow Duration": duration,
            # 9-10. Total Fwd/Bwd Packets
            "Total Fwd Packets": flow.fwd_pkts,
            "Total Backward Packets": flow.bwd_pkts,
            # 11-12. Total Length of Fwd/Bwd Packets (payload bytes)
            "Total Length of Fwd Packets": flow.fwd_bytes,
            "Total Length of Bwd Packets": flow.bwd_bytes,
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
            "Fwd PSH Flags": flow.fwd_psh_flags,
            "Bwd PSH Flags": flow.bwd_psh_flags,
            "Fwd URG Flags": flow.fwd_urg_flags,
            "Bwd URG Flags": flow.bwd_urg_flags,
            # 41-42. Fwd/Bwd Header Length
            "Fwd Header Length": flow.fwd_header_len,
            "Bwd Header Length": flow.bwd_header_len,
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
            "CWE Flag Count": cwr_flag_count,
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
            "FWD Init Win Bytes": flow.fwd_init_win_bytes,
            "Bwd Init Win Bytes": flow.bwd_init_win_bytes,
            # 75-76. Fwd Act Data Pkts, Fwd Seg Size Min
            "Fwd Act Data Pkts": flow.act_data_pkt_forward,
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
            "Fwd RST Flags": flow.fwd_rst_flags,  # Forward RST flags count
            "Bwd RST Flags": flow.bwd_rst_flags,  # Backward RST flags count
            "ICMP Code": icmp_code,  # ICMP code (0 for TCP/UDP)
            "ICMP Type": icmp_type,  # ICMP type (0 for TCP/UDP)
            "Total TCP Flow Time": total_tcp_flow_time  # Same as Flow Duration for TCP
        }

