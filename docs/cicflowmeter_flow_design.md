# CICFlowMeter Flow design

This note summarizes how the original CICFlowMeter `BasicFlow` class builds flow-level statistics and sketches a Python-friendly design that can be used in this repository to reproduce the same metrics.

## Flow identity and lifecycle

- A flow is keyed by the 5-tuple **(src ip, dst ip, src port, dst port, protocol)**.
- The first packet fixes the **forward** direction (src → dst); the opposite direction is **backward**.
- `start_time` is set on the first packet. `end_time` tracks the timestamp of the most recent packet.
- A flow is **terminated** when a timeout/inactivity threshold is exceeded (CICFlowMeter uses 120 s), or when FIN/RST closes a TCP session.

## State stored per flow (O(1) memory)

| Category | Stored fields |
| --- | --- |
| Timestamps | `start_time`, `end_time`, `last_flow_ts`, `last_fwd_ts`, `last_bwd_ts` |
| Counters | `fwd_pkt_cnt`, `bwd_pkt_cnt`, `fwd_bytes`, `bwd_bytes`, `fwd_hdr_bytes`, `bwd_hdr_bytes` |
| Length stats | For **flow**, **fwd**, **bwd**: `min_len`, `max_len`, `sum_len`, `sum_sq_len` (gives mean/std without keeping all packets) |
| Inter-arrival stats | Welford accumulators for **flow IAT**, **fwd IAT**, **bwd IAT** (`count`, `mean`, `M2`, plus `min`, `max`) |
| TCP flags | Counters for SYN/FIN/RST/PSH/ACK/URG/CWR/ECE; `fwd_psh`, `bwd_psh`, `fwd_urg`, `bwd_urg` |
| Bulk features | Per direction: `bulk_pkt_cnt`, `bulk_byte_cnt`, `bulk_start_ts`, `bulk_last_ts`, `bulk_rate`. CICFlowMeter starts a bulk when ≥ 4 packets of the same direction arrive within 1 s. |
| Subflow | With a 1 s slice size: `subflow_fwd_pkts`, `subflow_bwd_pkts`, `subflow_fwd_bytes`, `subflow_bwd_bytes` reset when the slice expires. |
| Active/Idle | Arrays (or running stats) of **active** and **idle** periods. An idle gap > 1 s closes an active period; the gap length is recorded as idle. |
| Misc | `init_fwd_win_bytes`, `init_bwd_win_bytes`, `fwd_act_data_pkts`, `fwd_seg_size_min`. |

All metrics in the CICFlowMeter CSV (e.g., Flow Duration, Packet Length Mean/Std, Flow IAT Mean/Std/Max/Min, PSH/URG counts, Down/Up Ratio, Avg Packet Size, Avg Fwd/Bwd Segment Size, Active/Idle Mean/Std/Max/Min, etc.) can be derived from these fields.

## Update algorithm (packet ingestion)

```python
# FWD/BWD are direction markers (e.g., 0/1 or "fwd"/"bwd").
# `packet` exposes: time, src, dst, payload_len, header_len, flags.
FWD, BWD = "fwd", "bwd"

def ingest(packet):
    ts = packet.time  # seconds as float
    direction = FWD if packet.src == flow.fwd_src else BWD

    if flow.start_time is None:
        flow.start_time = ts
        flow.fwd_src = packet.src  # locks forward direction

    # Flow-level IAT
    if flow.last_flow_ts is not None:
        flow.flow_iat.update(ts - flow.last_flow_ts)
    flow.last_flow_ts = ts
    flow.end_time = ts

    # Directional stats
    lens = packet.payload_len
    hdr = packet.header_len
    stats = flow.fwd if direction == FWD else flow.bwd
    stats.update_lengths(lens)
    stats.update_iat(ts)
    stats.pkt_cnt += 1
    stats.bytes += lens
    stats.hdr_bytes += hdr

    update_flags(packet.flags, direction)
    update_bulk(packet, direction, ts)     # start bulk when ≥ 4 pkts within 1 s
    update_subflow(packet, direction, ts)  # 1 s slice
    update_active_idle(ts)                 # idle gap > 1 s closes an active period
```

Each helper (`update_lengths`, `update_iat`, `update_flags`, `update_bulk`, `update_subflow`, `update_active_idle`) only touches the fields listed above, keeping memory constant regardless of packets processed.

## Metric derivation examples

- **Flow Duration** = `end_time - start_time`
- **Total Fwd/Backward Packets** = `fwd_pkt_cnt` / `bwd_pkt_cnt`
- **Total Length of Fwd/Bwd Packets** = `fwd_bytes` / `bwd_bytes`
- **Fwd/Bwd Packet Length Mean/Std/Min/Max** derived from the directional length accumulators.
- **Flow/ Fwd/ Bwd IAT Mean/Std/Min/Max** from their Welford accumulators.
- **Flow Bytes/s**, **Flow Packets/s**, **Fwd/Bwd Packets/s** divide totals by duration (protect against divide-by-zero).
- **TCP flag counts** come directly from the flag counters; **Down/Up Ratio** = `bwd_pkt_cnt / max(fwd_pkt_cnt, 1)`.
- **Avg Packet Size** = `(fwd_bytes + bwd_bytes) / (fwd_pkt_cnt + bwd_pkt_cnt)`.
- **Fwd/Bwd Segment Size Avg** = directional byte totals / packet totals.
- **Active/Idle Mean/Std/Min/Max** computed from the recorded active/idle intervals.

## Suggested Python class skeleton

```python
from dataclasses import dataclass, field
from typing import Optional, Tuple

FiveTuple = Tuple[str, str, int, int, int]  # (src_ip, dst_ip, src_port, dst_port, protocol)

# DirectionStats and OnlineStats are lightweight helpers that keep counters and online mean/std.

@dataclass
class Flow:
    key: FiveTuple
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    fwd: DirectionStats = field(default_factory=DirectionStats)
    bwd: DirectionStats = field(default_factory=DirectionStats)
    flow_iat: OnlineStats = field(default_factory=OnlineStats)
    active: OnlineStats = field(default_factory=OnlineStats)
    idle: OnlineStats = field(default_factory=OnlineStats)
    # plus bulk/subflow/flag counters...

    def ingest(self, packet: Packet):
        """Update the flow with one packet and keep all metrics derivable."""
        ...
```

Filling out the helpers described above will yield the full CICFlowMeter CSV feature set while keeping processing streaming-friendly for the live sniffer and detection pipeline in this repository.
