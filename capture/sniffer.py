import socket
import sys
import threading
import time
from typing import Optional

try:
    import pcapy
except Exception as e:  # pragma: no cover
    pcapy = None
    _PCAPY_IMPORT_ERROR = e

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
    """Fast Sniffer sử dụng libpcap (pcapy-ng) để capture tốc độ cao."""
    def __init__(self, bind_ip, csv_file: str = CSV_FILE, debug_print: bool = False, stats: bool = False):
        # Backward-compatible param name:
        # - If bind_ip is an IPv4 address: use it as a capture filter (host <ip>)
        # - Else: treat it as interface name (if it matches a device)
        self.bind_ip = bind_ip
        self.flows = {}  # Key: (src_ip_int, dst_ip_int, sport, dport, proto)
        self.lock = threading.Lock()
        self.running = False
        self.cap = None
        self.dev = None
        self._datalink = None
        self.packet_count = 0
        self.csv_writer = CSVWriter(csv_file, buffer_size=500)
        self._scratch = PacketScratch()
        self._debug_print = debug_print
        self._stats = stats

    def _probe_device_for_filter(self, dev: str, capture_filter: str) -> int:
        if pcapy is None:
            raise RuntimeError("pcapy-ng is not available")

        cap = self._open_pcap(dev)
        try:
            self._set_filter(cap, capture_filter)
        except Exception:
            return 0

        hits = 0
        # Probe for ~0.75s worst-case (15 * 50ms), only at startup.
        for _ in range(15):
            try:
                header, raw_data = cap.next()
                if header is None or raw_data is None:
                    continue
                if len(raw_data) > 0:
                    hits += 1
                    if hits >= 2:
                        break
            except Exception:
                return hits

        return hits

    def _select_device_and_filter(self) -> tuple[str, Optional[str]]:
        if pcapy is None:
            raise RuntimeError(
                f"pcapy-ng is not available: {type(_PCAPY_IMPORT_ERROR).__name__}: {_PCAPY_IMPORT_ERROR}"
            )

        devs = pcapy.findalldevs()
        if not devs:
            raise RuntimeError("No network devices found! (Check Npcap/libpcap installation)")

        # If user passed a device name, use it.
        if self.bind_ip in devs:
            return self.bind_ip, None

        # Else treat it as an IPv4 filter.
        capture_filter: Optional[str] = None
        try:
            import ipaddress

            ipaddress.IPv4Address(str(self.bind_ip))
            capture_filter = f"host {self.bind_ip}"
        except Exception:
            capture_filter = None

        if capture_filter is None:
            return devs[0], None

        # Try to select the correct device for the host filter by probing.
        best_dev = devs[0]
        best_hits = -1
        for dev in devs:
            try:
                hits = self._probe_device_for_filter(dev, capture_filter)
            except Exception:
                continue
            if hits > best_hits:
                best_dev = dev
                best_hits = hits
            if best_hits >= 2:
                break

        return best_dev, capture_filter

    def _open_pcap(self, dev: str) -> object:
        if pcapy is None:
            raise RuntimeError("pcapy-ng is not available")
        # Snaplen=65536, Promisc=1, Timeout=100ms
        return pcapy.open_live(dev, 65536, 1, 100)

    def _set_filter(self, cap: object, capture_filter: str) -> None:
        if capture_filter:
            cap.setfilter(capture_filter)

    def _ipv4_view_from_l2(self, raw_data: bytes, datalink: int) -> memoryview:
        mv = memoryview(raw_data)

        # DLT_EN10MB (Ethernet) = 1
        if datalink == 1:
            if len(mv) < 14:
                raise ValueError("frame too short for Ethernet")
            eth_type = (mv[12] << 8) | mv[13]
            offset = 14
            # VLAN tag
            if eth_type == 0x8100:
                if len(mv) < 18:
                    raise ValueError("frame too short for VLAN")
                eth_type = (mv[16] << 8) | mv[17]
                offset = 18
            if eth_type != 0x0800:
                raise ValueError("non-IPv4 ethertype")
            return mv[offset:]

        # DLT_LINUX_SLL (cooked capture) = 113
        if datalink == 113:
            if len(mv) < 16:
                raise ValueError("frame too short for Linux SLL")
            proto = (mv[14] << 8) | mv[15]
            if proto != 0x0800:
                raise ValueError("non-IPv4 SLL protocol")
            return mv[16:]

        # DLT_RAW = 12 (already IP)
        if datalink == 12:
            return mv

        # DLT_NULL = 0 (loopback), 4-byte family header
        if datalink == 0:
            if len(mv) < 4:
                raise ValueError("frame too short for NULL")
            return mv[4:]

        # Unknown: try as IP directly.
        return mv

    def start(self):
        """Khởi động sniffer với libpcap (pcapy-ng)."""
        try:
            self.dev, capture_filter = self._select_device_and_filter()
            self.cap = self._open_pcap(self.dev)
            self._datalink = int(self.cap.datalink())
            if capture_filter:
                self._set_filter(self.cap, capture_filter)
            self.running = True
            print(f"🚀 Sniffing on device: {self.dev}", file=sys.stderr)
            if capture_filter:
                print(f"🔎 Filter: {capture_filter}", file=sys.stderr)
        except Exception as e:
            print(f"❌ Pcap init error: {type(e).__name__}: {e}", file=sys.stderr)
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
                header, raw_data = self.cap.next()

                # Timeout returns None
                if header is None or raw_data is None:
                    continue
                if len(raw_data) <= 0:
                    continue

                start_ns = 0
                if self._stats:
                    start_ns = time.perf_counter_ns()

                try:
                    ip_view = self._ipv4_view_from_l2(raw_data, self._datalink if self._datalink is not None else 0)
                except Exception:
                    # Non-IPv4 or unsupported L2 frame
                    continue

                self._process_packet(ip_view)
                self.packet_count += 1

                if self._stats:
                    stats_pkts += 1
                    stats_bytes += len(raw_data)
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
            except Exception as e:
                # pcapy uses PcapError for driver issues
                if pcapy is not None and isinstance(e, getattr(pcapy, "PcapError", Exception)):
                    print(f"❌ Pcap Error: {e}", file=sys.stderr)
                    break

                # Avoid heavy logging in hot path; keep only first error.
                if self.packet_count == 0:
                    print(f"⚠️ Capture error: {type(e).__name__}: {e}", file=sys.stderr)

        # Cleanup
        self.running = False

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

