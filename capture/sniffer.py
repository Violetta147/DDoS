import socket
import sys
import threading
import time

try:
    import pcapy
except Exception as e:
    pcapy = None
    _PCAPY_IMPORT_ERROR = e

from .csv_writer import CSVWriter
from .flow import Flow
from .packet_parser import PacketScratch, parse_ipv4_tcp_udp_into

CSV_FILE = "data/live_flow.csv"

_FLOW_ACTIVITY_TIMEOUT_US = 1_000_000
_FLOW_TIMEOUT_S = 60.0
_SYN_FLUSH_PKT_THRESHOLD = 50
_CLEANUP_INTERVAL_S = 5.0


class FastSniffer:
    """Attack-aware flow sniffer (SYN-flood safe)"""

    def __init__(self, bind_ip=None, iface=None,
                 csv_file=CSV_FILE, debug_print=False, stats=False):

        self.bind_ip = bind_ip
        self.iface = iface

        self.flows = {}
        self.lock = threading.Lock()
        self.running = False

        self.cap = None
        self.dev = None
        self._datalink = None

        self.csv_writer = CSVWriter(csv_file, buffer_size=500)
        self._scratch = PacketScratch()

        self._debug_print = debug_print
        self._stats = stats

    # ---------------- PCAP ----------------

    def _open_pcap(self, dev):
        return pcapy.open_live(dev, 65536, 1, 100)

    def _select_device_and_filter(self):
        devs = pcapy.findalldevs()
        if not devs:
            raise RuntimeError("No capture devices found")

        # 1️⃣ Explicit interface
        if self.iface:
            for d in devs:
                if self.iface.lower() in d.lower():
                    filt = f"host {self.bind_ip}" if self.bind_ip else None
                    return d, filt
            raise RuntimeError(f"Interface not found: {self.iface}")

        # 2️⃣ bind_ip is device name
        if self.bind_ip and self.bind_ip in devs:
            return self.bind_ip, None

        # 3️⃣ bind_ip is IP → filter
        try:
            import ipaddress
            ipaddress.IPv4Address(self.bind_ip)
            return devs[0], f"host {self.bind_ip}"
        except Exception:
            pass

        # 4️⃣ fallback
        return devs[0], None

    # ---------------- START ----------------

    def start(self):
        try:
            self.dev, cap_filter = self._select_device_and_filter()
            self.cap = self._open_pcap(self.dev)
            self._datalink = int(self.cap.datalink())
            if cap_filter:
                self.cap.setfilter(cap_filter)
            self.running = True
        except Exception as e:
            print(f"❌ PCAP error: {e}", file=sys.stderr)
            return

        print(f"🚀 Sniffing on {self.dev}", file=sys.stderr)
        if cap_filter:
            print(f"🔎 Filter: {cap_filter}", file=sys.stderr)

        threading.Thread(target=self._flush_loop, daemon=True).start()

        while self.running:
            try:
                hdr, raw = self.cap.next()
                if not raw:
                    continue
                self._process_packet(raw)
            except Exception:
                break

        self._shutdown_flush()

    # ---------------- PACKET PROCESS ----------------

    def _process_packet(self, raw):
        try:
            parse_ipv4_tcp_udp_into(raw, self._scratch)
            now = time.time()

            key = (
                self._scratch.dst_ip_int,
                self._scratch.dst_port,
                self._scratch.protocol,
            )

            tcp_flags = self._scratch.tcp_flags
            proto = self._scratch.protocol

            is_syn_only = (
                proto == 6 and
                (tcp_flags & 0x02) and
                not (tcp_flags & 0x10)
            )

            flow_to_flush = None

            with self.lock:
                flow = self.flows.get(key)
                if not flow:
                    flow = Flow(
                        now,
                        "*",
                        socket.inet_ntoa(self._scratch.dst_ip_bytes),
                        0,
                        self._scratch.dst_port,
                        proto,
                        _FLOW_ACTIVITY_TIMEOUT_US,
                    )
                    self.flows[key] = flow

                flow.update_primitives(
                    now,
                    self._scratch.payload_len,
                    self._scratch.header_len,
                    tcp_flags,
                    proto,
                    True,
                )

                if is_syn_only and flow.total_pkts >= _SYN_FLUSH_PKT_THRESHOLD:
                    flow.is_terminated = True
                    flow_to_flush = self.flows.pop(key)

            if flow_to_flush:
                self.csv_writer.write_flow(flow_to_flush, "[SYN-FLOOD]")

        except Exception:
            pass

    # ---------------- FLUSH LOOP ----------------

    def _flush_loop(self):
        self.csv_writer.initialize()
        while self.running:
            time.sleep(_CLEANUP_INTERVAL_S)
            now = time.time()

            expired = []
            with self.lock:
                for k, f in list(self.flows.items()):
                    if now - f.last_time > _FLOW_TIMEOUT_S:
                        expired.append(self.flows.pop(k))

            for f in expired:
                self.csv_writer.write_flow(f, "[Timeout]")

            self.csv_writer.flush()

    # ---------------- SHUTDOWN ----------------

    def _shutdown_flush(self):
        with self.lock:
            flows = list(self.flows.values())
            self.flows.clear()

        for f in flows:
            self.csv_writer.write_flow(f, "[Shutdown]")

        self.csv_writer.flush()
        self.csv_writer.close()

    def stop(self):
        self.running = False
