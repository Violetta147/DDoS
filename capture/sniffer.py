import threading
import time
import socket
import struct
import os
import pandas as pd
import sys
import ipaddress
from typing import Dict
from .flow import Flow
from . import utils

# --- CẤU HÌNH ---
CSV_FILE = "data/live_flow.csv"


class FastSniffer:
    """Fast Sniffer sử dụng raw socket (nhanh hơn Scapy)"""
    def __init__(self, bind_ip):
        self.bind_ip = bind_ip
        self.flows = {}  # Key: (src, dst, sport, dport, proto)
        self.lock = threading.Lock()
        self.running = False
        self.sniffer_socket = None
        self.packet_count = 0

    def start(self):
        """Khởi động sniffer với raw socket"""
        # Validate IP trước (dùng cache để nhanh hơn)
        local_ips = utils.get_local_ips(use_cache=True)
        is_valid, error_msg = utils.validate_ip(self.bind_ip, local_ips=local_ips)
        if not is_valid:
            print(f"❌ IP Validation Error: {error_msg}", file=sys.stderr)
            print("⚠️ Lưu ý: Trên Windows, cần quyền Admin để sử dụng raw socket", file=sys.stderr)
            return
        
        try:
            self.sniffer_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self.sniffer_socket.bind((self.bind_ip, 0))
            self.sniffer_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # Set timeout để tránh blocking vô hạn và cho phép kiểm tra running flag
            self.sniffer_socket.settimeout(1.0)
            self.sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            self.running = True
            
            print(f"🚀 Fast Sniffer started on {self.bind_ip}", file=sys.stderr)
            print(f"✅ Socket bound, RCVALL enabled - Ready to capture packets", file=sys.stderr)
        except OSError as e:
            if e.winerror == 10022:  # Invalid argument (0.0.0.0 on Windows)
                error_msg = (
                    f"❌ Socket Error: Windows raw socket không hỗ trợ bind 0.0.0.0!\n"
                    f"Giải pháp: Dùng IP cụ thể: {', '.join(local_ips) if local_ips else 'Xem bằng: ipconfig'}\n"
                    f"⚠️ Lưu ý: Cần quyền Admin trên Windows!"
                )
            elif e.winerror == 10049:  # Address not valid
                error_msg = (
                    f"❌ Socket Error: IP '{self.bind_ip}' không hợp lệ!\n"
                    f"IP có sẵn: {', '.join(local_ips) if local_ips else 'Không tìm thấy'}\n"
                    f"⚠️ Lưu ý: Cần quyền Admin trên Windows!"
                )
            elif e.winerror == 10013:  # Permission denied
                error_msg = (
                    f"❌ Permission Error: Không có quyền truy cập raw socket!\n"
                    f"Giải pháp: Chạy chương trình với quyền Administrator (Right-click → Run as administrator)"
                )
            else:
                error_msg = f"❌ Socket Error: {e}\n⚠️ Cần quyền Admin để sử dụng raw socket trên Windows!"
            
            print(error_msg, file=sys.stderr)
            return
        except Exception as e:
            error_msg = f"❌ Unexpected Error: {e}\n⚠️ Cần quyền Admin để sử dụng raw socket!"
            print(error_msg, file=sys.stderr)
            return

        # Thread ghi CSV định kỳ
        threading.Thread(target=self._flush_loop, daemon=True).start()

        # Capture Loop
        while self.running:
            try:
                raw_buffer = self.sniffer_socket.recvfrom(65535)[0]
                self._process_packet(raw_buffer)
                self.packet_count += 1
            except socket.timeout:
                # Timeout is normal, continue
                continue
            except Exception as e:
                # Log other errors for debugging
                if self.packet_count == 0:
                    # Only log first error to avoid spam
                    print(f"⚠️ Capture error: {type(e).__name__}: {e}", file=sys.stderr)
                pass

        # Cleanup
        try:
            self.sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            self.sniffer_socket.close()
        except:
            pass

    def _process_packet(self, buffer):
        """Parse và xử lý packet"""
        try:
            # Parse IP Header (20 bytes)
            ip_header = buffer[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            
            protocol = iph[6]
            src_addr = socket.inet_ntoa(iph[8])
            dst_addr = socket.inet_ntoa(iph[9])
            
            # Chỉ xử lý TCP và UDP (skip ICMP và các protocol khác)
            # Vì DDoS detection chủ yếu dựa trên TCP/UDP flows
            if protocol not in (6, 17):  # 6=TCP, 17=UDP
                return  # Bỏ qua ICMP và các protocol khác
            
            total_len = len(buffer)
            
            # Parse TCP/UDP để lấy Port
            src_port = 0
            dst_port = 0
            transport_header_len = 0
            
            # TCP flags để detect FIN
            tcp_flags = 0
            if protocol == 6:  # TCP
                t = iph_length
                tcp_header = buffer[t:t+20]
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                src_port = tcph[0]
                dst_port = tcph[1]
                transport_header_len = (tcph[4] >> 4) * 4
                tcp_flags = tcph[5]  # TCP flags byte
            elif protocol == 17:  # UDP
                u = iph_length
                udph = struct.unpack('!HHHH', buffer[u:u+8])
                src_port = udph[0]
                dst_port = udph[1]
                transport_header_len = 8
            
            # Total header length = IP header + Transport header (TCP/UDP)
            header_len = iph_length + transport_header_len
            
            # Normalize flow key để bidirectional (best practice: integer-based comparison)
            # Convert IP addresses to integers để so sánh chính xác về mặt số học
            # Điều này đảm bảo A->B và B->A cùng một flow
            src_ip_int = int(ipaddress.IPv4Address(src_addr))
            dst_ip_int = int(ipaddress.IPv4Address(dst_addr))
            
            if src_ip_int < dst_ip_int or (src_ip_int == dst_ip_int and src_port < dst_port):
                flow_src_addr, flow_dst_addr = src_addr, dst_addr
                flow_src_port, flow_dst_port = src_port, dst_port
                is_forward = True
            else:
                flow_src_addr, flow_dst_addr = dst_addr, src_addr
                flow_src_port, flow_dst_port = dst_port, src_port
                is_forward = False
            
            flow_key = (flow_src_addr, flow_dst_addr, flow_src_port, flow_dst_port, protocol)
            now = time.time()
            
            with self.lock:
                is_new_flow = flow_key not in self.flows
                if is_new_flow:
                    # Activity timeout: 1 second = 1,000,000 microseconds (CICFlowMeter default)
                    self.flows[flow_key] = Flow(now, flow_src_addr, flow_dst_addr, flow_src_port, flow_dst_port, protocol, activity_timeout=1_000_000)
                    if len(self.flows) <= 10:
                        print(f"🆕 New flow: {flow_src_addr}:{flow_src_port} -> {flow_dst_addr}:{flow_dst_port} "
                              f"(protocol={protocol}, total flows={len(self.flows)})", file=sys.stderr)
                
                flow = self.flows[flow_key]
                
                # Detect TCP termination flags và flush ngay lập tức (event-driven)
                # FIN (bit 0): Normal connection termination
                # RST (bit 2): Abrupt connection termination
                should_flush_now = False
                tcp_flags_for_update = tcp_flags if protocol == 6 else 0
                if protocol == 6:
                    if tcp_flags & 0x01:  # FIN flag
                        flow.is_terminated = True
                        should_flush_now = True
                    if tcp_flags & 0x04:  # RST flag
                        if not flow.is_terminated:  # Chỉ flush nếu chưa terminated
                            flow.is_terminated = True
                            should_flush_now = True
                
                # Calculate payload length (CICFlowMeter compatible: payload bytes only)
                payload_len = total_len - header_len
                flow.update(payload_len, header_len, now, is_forward, tcp_flags=tcp_flags_for_update)
                
                # Flush ngay lập tức nếu flow terminated (event-driven, chuyên nghiệp)
                if should_flush_now:
                    self._flush_flow(flow_key, flow, "[FIN/RST]")
                    # Xóa flow sau khi flush
                    if flow_key in self.flows:
                        del self.flows[flow_key]
                
        except Exception as e:
            # Debug: Log exception để biết lỗi gì
            if self.packet_count % 1000 == 0:  # Log mỗi 1000 packets để tránh spam
                import traceback
                print(f"⚠️ Packet processing error: {type(e).__name__}: {e}", file=sys.stderr)
                print(f"   Traceback: {traceback.format_exc()[:200]}", file=sys.stderr)

    def _flush_flow(self, flow_key, flow, reason=""):
        """Flush một flow vào CSV (event-driven)"""
        try:
            # Update subflow snapshot trước khi tính features
            flow.subflow_fwd_packets = flow.fwd_pkts
            flow.subflow_fwd_bytes = flow.fwd_bytes
            flow.subflow_bwd_packets = flow.bwd_pkts
            flow.subflow_bwd_bytes = flow.bwd_bytes
            
            feat = flow.to_features()
            
            # Đảm bảo FEATURE_NAMES đã được init
            if utils.FEATURE_NAMES is None:
                utils.init_feature_names()
            
            row = {col: feat.get(col, 0) for col in utils.FEATURE_NAMES}
            
            df = pd.DataFrame([row])
            
            # Đảm bảo thư mục tồn tại
            os.makedirs(os.path.dirname(CSV_FILE), exist_ok=True)
            df.to_csv(CSV_FILE, mode='a', header=False, index=False)
            
            # Log large flows
            total_pkts = flow.fwd_pkts + flow.bwd_pkts
            if total_pkts > 10:
                # Flow Duration is in microseconds, convert to seconds for display
                duration_us = feat.get('Flow Duration', 0)
                duration_s = duration_us / 1_000_000.0
                print(f"🔍 Flushed flow: {flow.src_addr}:{flow.src_port} -> {flow.dst_addr}:{flow.dst_port} "
                      f"({total_pkts} pkts, {duration_s:.2f}s) {reason}", file=sys.stderr)
            
            return True
        except Exception as e:
            import traceback
            print(f"⚠️ Error flushing flow: {type(e).__name__}: {e}", file=sys.stderr)
            print(f"   Traceback: {traceback.format_exc()[:300]}", file=sys.stderr)
            return False

    def _flush_loop(self):
        """Check và flush flows timeout định kỳ (chỉ timeout theo protocol, không flush active flows)"""
        # Init CSV
        os.makedirs(os.path.dirname(CSV_FILE), exist_ok=True)
        
        # Đảm bảo FEATURE_NAMES đã được init
        if utils.FEATURE_NAMES is None:
            utils.init_feature_names()
        
        pd.DataFrame(columns=utils.FEATURE_NAMES).to_csv(CSV_FILE, index=False)
        print(f"📄 CSV initialized: {CSV_FILE} ({len(utils.FEATURE_NAMES)} features)", file=sys.stderr)
        
        # Timeout theo chuẩn protocol:
        # - Normal flows (có response): 60s (theo TCP keepalive)
        # - SYN-only flows (không có response): 300s (5 phút, đủ để detect SYN floods)
        FLOW_TIMEOUT = 60.0  # 60s cho normal flows (có backward packets)
        SYN_ONLY_TIMEOUT = 300.0  # 300s (5 phút) cho SYN-only flows
        CLEANUP_INTERVAL = 10.0  # Check timeout mỗi 10s (chỉ để cleanup, không flush active flows)
        
        while self.running:
            time.sleep(CLEANUP_INTERVAL)
            flows_to_delete = []
            
            with self.lock:
                current_time = time.time()
                
                # Chỉ flush flows timeout (theo protocol)
                # Flows terminated (FIN/RST) đã được flush ngay trong _process_packet
                for key, flow in list(self.flows.items()):
                    # Flush flows timeout (inactive quá lâu)
                    if flow.bwd_pkts == 0 and current_time - flow.last_time > SYN_ONLY_TIMEOUT:
                        # SYN-only flows timeout sau 5 phút
                        self._flush_flow(key, flow, "[SYN-only timeout]")
                        flows_to_delete.append(key)
                    elif flow.bwd_pkts > 0 and current_time - flow.last_time > FLOW_TIMEOUT:
                        # Normal flows timeout sau 60s
                        self._flush_flow(key, flow, "[Timeout]")
                        flows_to_delete.append(key)
                
                # Xóa flows đã timeout
                for k in flows_to_delete:
                    if k in self.flows:
                        del self.flows[k]
            
            # Log status định kỳ với debug info
            with self.lock:
                active_count = len(self.flows)
                total_packets_in_flows = sum(flow.fwd_pkts + flow.bwd_pkts for flow in self.flows.values())
                max_packets_in_flow = max((flow.fwd_pkts + flow.bwd_pkts for flow in self.flows.values()), default=0)
                # Debug: Log flow keys để xem tại sao chỉ có 1 flow
                if active_count > 0 and active_count <= 5:
                    flow_keys_debug = [f"{k[0]}:{k[2]}->{k[1]}:{k[3]}" for k in list(self.flows.keys())[:5]]
                    print(f"📊 Active: {active_count} flows | Captured: {self.packet_count:,} pkts | "
                          f"In-memory: {total_packets_in_flows:,} pkts | Max/flow: {max_packets_in_flow:,}", file=sys.stderr)
                    print(f"   Flow keys: {', '.join(flow_keys_debug)}", file=sys.stderr)
                elif active_count > 0:
                    print(f"📊 Active: {active_count} flows | Captured: {self.packet_count:,} pkts | "
                          f"In-memory: {total_packets_in_flows:,} pkts | Max/flow: {max_packets_in_flow:,}", file=sys.stderr)

    def stop(self):
        """Dừng sniffer"""
        self.running = False

