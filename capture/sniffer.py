import socket
import sys
import threading
import time

from . import utils
from .csv_writer import CSVWriter
from .flow import Flow
from .packet_parser import PacketScratch, parse_ipv4_tcp_udp_into

# --- CẤU HÌNH ---
CSV_FILE = "data/live_flow.csv"


_FLOW_ACTIVITY_TIMEOUT_US = 1_000_000
_FLOW_TIMEOUT_S = 60.0
_SYN_ONLY_TIMEOUT_S = 300.0
_CLEANUP_INTERVAL_S = 10.0


class FastSniffer:
    """Fast Sniffer sử dụng raw socket (nhanh hơn Scapy)"""
    def __init__(self, bind_ip, csv_file: str = CSV_FILE, debug_print: bool = False, stats: bool = False):
        self.bind_ip = bind_ip
        self.flows = {}  # Key: (src_ip_int, dst_ip_int, sport, dport, proto)
        self.lock = threading.Lock()
        self.running = False
        self.sniffer_socket = None
        self.packet_count = 0
        self.csv_writer = CSVWriter(csv_file, buffer_size=500)
        self._recv_buffer = bytearray(65535)
        self._recv_view = memoryview(self._recv_buffer)
        self._scratch = PacketScratch()
        self._debug_print = debug_print
        self._stats = stats

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

        stats_last_ts = time.monotonic()
        stats_pkts = 0
        stats_bytes = 0
        stats_proc_ns_total = 0
        stats_proc_samples = 0

        # Capture Loop
        while self.running:
            try:
                nbytes = self.sniffer_socket.recv_into(self._recv_buffer)
                if nbytes <= 0:
                    continue

                start_ns = 0
                if self._stats:
                    start_ns = time.perf_counter_ns()

                self._process_packet(self._recv_view[:nbytes])
                self.packet_count += 1

                if self._stats:
                    stats_pkts += 1
                    stats_bytes += nbytes
                    end_ns = time.perf_counter_ns()
                    stats_proc_ns_total += (end_ns - start_ns)
                    stats_proc_samples += 1

                    now_mono = time.monotonic()
                    if now_mono - stats_last_ts >= 1.0:
                        interval_s = now_mono - stats_last_ts
                        pps = stats_pkts / interval_s if interval_s > 0 else 0.0
                        mbps = (stats_bytes * 8.0) / (interval_s * 1_000_000.0) if interval_s > 0 else 0.0
                        avg_us = (
                            (stats_proc_ns_total / stats_proc_samples) / 1_000.0
                            if stats_proc_samples > 0
                            else 0.0
                        )
                        with self.lock:
                            flows_count = len(self.flows)
                        print(
                            f"[STATS] pps={pps:,.0f}  mbps={mbps:,.2f}  avg_proc_us={avg_us:,.2f}  flows={flows_count}",
                            file=sys.stderr,
                        )
                        stats_last_ts = now_mono
                        stats_pkts = 0
                        stats_bytes = 0
                        stats_proc_ns_total = 0
                        stats_proc_samples = 0
            except socket.timeout:
                # Timeout is normal, continue
                continue
            except Exception as e:
                # Avoid heavy logging in hot path; keep only first error.
                if self.packet_count == 0:
                    print(f"⚠️ Capture error: {type(e).__name__}: {e}", file=sys.stderr)

        # Cleanup
        try:
            self.sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            self.sniffer_socket.close()
        except:
            pass

        try:
            self.csv_writer.close()
        except Exception:
            pass

    def _process_packet(self, buffer: memoryview) -> None:
        """Parse và xử lý packet."""
        try:
            parse_ipv4_tcp_udp_into(buffer, self._scratch)

            now = time.time()

            if self._debug_print:
                utils.print_wireshark_style(
                    no=self.packet_count + 1,
                    ts=now,
                    src_ip=socket.inet_ntoa(self._scratch.src_ip_bytes),
                    src_port=self._scratch.src_port,
                    dst_ip=socket.inet_ntoa(self._scratch.dst_ip_bytes),
                    dst_port=self._scratch.dst_port,
                    proto=self._scratch.protocol,
                    payload_len=self._scratch.payload_len,
                    flags=self._scratch.tcp_flags,
                )

            if self._scratch.src_ip_int < self._scratch.dst_ip_int or (
                self._scratch.src_ip_int == self._scratch.dst_ip_int and self._scratch.src_port < self._scratch.dst_port
            ):
                flow_src_ip_int, flow_dst_ip_int = self._scratch.src_ip_int, self._scratch.dst_ip_int
                flow_src_ip_bytes, flow_dst_ip_bytes = self._scratch.src_ip_bytes, self._scratch.dst_ip_bytes
                flow_src_port, flow_dst_port = self._scratch.src_port, self._scratch.dst_port
                is_forward = True
            else:
                flow_src_ip_int, flow_dst_ip_int = self._scratch.dst_ip_int, self._scratch.src_ip_int
                flow_src_ip_bytes, flow_dst_ip_bytes = self._scratch.dst_ip_bytes, self._scratch.src_ip_bytes
                flow_src_port, flow_dst_port = self._scratch.dst_port, self._scratch.src_port
                is_forward = False

            flow_key = (flow_src_ip_int, flow_dst_ip_int, flow_src_port, flow_dst_port, self._scratch.protocol)

            # Determine termination flags without allocating objects
            tcp_flags = self._scratch.tcp_flags
            protocol = self._scratch.protocol
            fin = protocol == 6 and (tcp_flags & 0x01) != 0
            rst = protocol == 6 and (tcp_flags & 0x04) != 0

            flow_to_flush = None
            with self.lock:
                flow = self.flows.get(flow_key)
                if flow is None:
                    # Only convert IP bytes -> string when creating a new flow
                    flow_src_addr = socket.inet_ntoa(flow_src_ip_bytes)
                    flow_dst_addr = socket.inet_ntoa(flow_dst_ip_bytes)
                    flow = Flow(
                        now,
                        flow_src_addr,
                        flow_dst_addr,
                        flow_src_port,
                        flow_dst_port,
                        protocol,
                        activity_timeout=_FLOW_ACTIVITY_TIMEOUT_US,
                    )
                    self.flows[flow_key] = flow

                # Update flow under lock so flush thread never observes mid-update state.
                flow.update_primitives(
                    timestamp=now,
                    payload_len=self._scratch.payload_len,
                    header_len=self._scratch.header_len,
                    tcp_flags=tcp_flags,
                    protocol=protocol,
                    is_forward=is_forward,
                )

                # If terminating, remove from dict under lock and flush outside lock.
                if fin or rst:
                    flow.is_terminated = True
                    flow_to_flush = self.flows.pop(flow_key, None)

            if flow_to_flush is not None:
                self.csv_writer.write_flow(flow_to_flush, "[FIN/RST]")
                
        except Exception as e:
            # Debug: Log exception để biết lỗi gì
            if self.packet_count % 1000 == 0:  # Log mỗi 1000 packets để tránh spam
                import traceback
                print(f"⚠️ Packet processing error: {type(e).__name__}: {e}", file=sys.stderr)
                print(f"   Traceback: {traceback.format_exc()[:200]}", file=sys.stderr)


    def _flush_loop(self):
        """Check và flush flows timeout định kỳ (chỉ timeout theo protocol, không flush active flows)"""
        # Initialize CSV file
        self.csv_writer.initialize()

        while self.running:
            time.sleep(_CLEANUP_INTERVAL_S)
            flows_to_flush = []

            with self.lock:
                current_time = time.time()

                # Only flush timed-out flows.
                # FIN/RST terminated flows are flushed in _process_packet.
                for key, flow in list(self.flows.items()):
                    if flow.bwd_pkts == 0 and current_time - flow.last_time > _SYN_ONLY_TIMEOUT_S:
                        removed = self.flows.pop(key, None)
                        if removed is not None:
                            flows_to_flush.append((removed, "[SYN-only timeout]"))
                    elif flow.bwd_pkts > 0 and current_time - flow.last_time > _FLOW_TIMEOUT_S:
                        removed = self.flows.pop(key, None)
                        if removed is not None:
                            flows_to_flush.append((removed, "[Timeout]"))

            for flow, reason in flows_to_flush:
                self.csv_writer.write_flow(flow, reason)

            # Persisted + buffered writer: flush on interval to bound data loss
            self.csv_writer.flush()

    def stop(self):
        """Dừng sniffer"""
        self.running = False

