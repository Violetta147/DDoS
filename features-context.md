
# Flow Feature Calculation Reference (83-column schema)

This document describes **how each CSV column is computed in this repo**, based on:
- `capture/sniffer.py` (packet parsing → `payload_len`, `header_len`, `tcp_flags`)
- `capture/flow.py` (`Flow` state, directional counters, `to_features()` metadata)
- `capture/flow_feature.py` (`FlowFeature.calculate()` numeric features)
- `capture/utils.py:init_feature_names()` (canonical 83-column order)

## Conventions (important)
- **Units**:
	- Timestamps are `time.time()` seconds internally; exported `Timestamp` is formatted string.
	- Durations/IATs are **microseconds (µs)**.
	- `*Byts/s` and `*Pkts/s` use `duration` in µs.
- **Direction**: “Fwd/Bwd” is **flow-key direction** (normalized 5-tuple ordering), not necessarily client→server.
- **Bytes meaning**:
	- `TotLen * Pkts` and packet-length stats are **payload bytes only** (`payload_len`).
	- Header-length fields are sums of `header_len` per packet (`IP header + TCP/UDP header`).
- **TCP flags**: counts are summed across fwd+bwd unless stated otherwise.
    
---

## Metadata columns (from `capture/flow.py:Flow.to_features()`)

1) `Flow ID`
- Format: `{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}`

2) `Src IP`
- Flow source address string.

3) `Src Port`
- Flow source port integer.

4) `Dst IP`
- Flow destination address string.

5) `Dst Port`
- Flow destination port integer.

6) `Protocol`
- IP protocol number (TCP=6, UDP=17).

7) `Timestamp`
- Start time formatted as `YYYY-MM-DD HH:MM:SS.ffffff`.

---

## Core flow totals

8) `Flow Duration`
- `duration_us = (last_time - start_time) * 1_000_000`.
- If negative (clock/timestamp bug), the code raises.
- **Training alignment**: if computed duration is `0` (single-packet), export `-1` as a sentinel.

9) `Tot Fwd Pkts`
- `fwd_pkts` (count of forward packets in this flow).

10) `Tot Bwd Pkts`
- `bwd_pkts`.

11) `TotLen Fwd Pkts`
- `fwd_bytes` (sum of forward **payload_len**).

12) `TotLen Bwd Pkts`
- `bwd_bytes` (sum of backward **payload_len**).

---

## Packet length stats (payload bytes)

Forward payload length stats are computed over forward packets’ `payload_len`.

13) `Fwd Pkt Len Max`  = max(fwd payload_len)
14) `Fwd Pkt Len Min`  = min(fwd payload_len)
15) `Fwd Pkt Len Mean` = mean(fwd payload_len)
16) `Fwd Pkt Len Std`  = std(fwd payload_len)

Backward payload length stats:

17) `Bwd Pkt Len Max`
18) `Bwd Pkt Len Min`
19) `Bwd Pkt Len Mean`
20) `Bwd Pkt Len Std`

All-packets payload length stats (over both directions’ `payload_len`):

45) `Pkt Len Min`
46) `Pkt Len Max`
47) `Pkt Len Mean`
48) `Pkt Len Std`
49) `Pkt Len Var`

Notes:
- If a stat has no samples (e.g., no packets), it is 0.

---

## Rates

Let:
- `total_bytes = fwd_bytes + bwd_bytes`
- `total_pkts  = fwd_pkts + bwd_pkts`
- `duration_us = Flow Duration`

21) `Flow Byts/s`
- `(total_bytes * 1_000_000) / duration_us` if `duration_us > 0` else `0`.

22) `Flow Pkts/s`
- `(total_pkts * 1_000_000) / duration_us` if `duration_us > 0` else `0`.

43) `Fwd Pkts/s`
- `(fwd_pkts * 1_000_000) / duration_us` if `duration_us > 0` else `0`.

44) `Bwd Pkts/s`
- `(bwd_pkts * 1_000_000) / duration_us` if `duration_us > 0` else `0`.

---

## Inter-arrival times (IAT) in µs

Flow-level IAT is computed from successive packet timestamps in the flow.

23) `Flow IAT Mean`
24) `Flow IAT Std`
25) `Flow IAT Max`
26) `Flow IAT Min`

Forward-only IAT (successive forward packets):

27) `Fwd IAT Tot`  = sum(fwd IAT)
28) `Fwd IAT Mean`
29) `Fwd IAT Std`
30) `Fwd IAT Max`
31) `Fwd IAT Min`

Backward-only IAT:

32) `Bwd IAT Tot`
33) `Bwd IAT Mean`
34) `Bwd IAT Std`
35) `Bwd IAT Max`
36) `Bwd IAT Min`

Notes:
- The first packet in a (sub)sequence has no previous packet, so it contributes no IAT sample.

---

## Header lengths (IP+transport, bytes)

41) `Fwd Header Len`
- Sum of `header_len` for forward packets.

42) `Bwd Header Len`
- Sum of `header_len` for backward packets.

---

## Directional PSH/URG flags

37) `Fwd PSH Flags` = forward PSH count
38) `Bwd PSH Flags` = backward PSH count
39) `Fwd URG Flags` = forward URG count
40) `Bwd URG Flags` = backward URG count

---

## Combined TCP flag counts (fwd + bwd)

50) `FIN Flag Cnt` = fwd_FIN + bwd_FIN
51) `SYN Flag Cnt` = fwd_SYN + bwd_SYN
52) `RST Flag Cnt` = fwd_RST + bwd_RST
53) `PSH Flag Cnt` = fwd_PSH + bwd_PSH
54) `ACK Flag Cnt` = fwd_ACK + bwd_ACK
55) `URG Flag Cnt` = fwd_URG + bwd_URG
56) `CWE Flag Count` = fwd_CWR + bwd_CWR
57) `ECE Flag Cnt` = fwd_ECE + bwd_ECE

Notes:
- The CSV label is `CWE Flag Count`, but it is computed from the TCP **CWR** bit.

---

## Ratios and averages

58) `Down/Up Ratio`
- `bwd_bytes / fwd_bytes` if `fwd_bytes > 0` else `0`.

59) `Pkt Size Avg`
- Equals `Pkt Len Mean` (mean payload_len over all packets).

60) `Fwd Seg Size Avg`
- Mean forward payload_len (`Fwd Pkt Len Mean`) if `fwd_pkts > 0` else `0`.

61) `Bwd Seg Size Avg`
- Mean backward payload_len (`Bwd Pkt Len Mean`) if `bwd_pkts > 0` else `0`.

---

## Bulk transfer features (directional)

These are based on internal “bulk state” trackers.

62) `Fwd Byts/b Avg`
- `fbulk_size_total / fbulk_state_count` if `fbulk_state_count > 0` else `0`.

63) `Fwd Pkts/b Avg`
- `fbulk_packet_count / fbulk_state_count` if `fbulk_state_count > 0` else `0`.

64) `Fwd Blk Rate Avg`
- `fbulk_size_total / (fbulk_duration_us / 1_000_000)` if `fbulk_duration_us > 0` else `0`.

65) `Bwd Byts/b Avg`
66) `Bwd Pkts/b Avg`
67) `Bwd Blk Rate Avg`
- Same as above, using backward bulk counters.

---

## Subflow features

Subflows are tracked internally by `sf_count` (minimum 1).

68) `Subflow Fwd Pkts` = int(fwd_pkts / sf_count)
69) `Subflow Fwd Byts` = int(fwd_bytes / sf_count)
70) `Subflow Bwd Pkts` = int(bwd_pkts / sf_count)
71) `Subflow Bwd Byts` = int(bwd_bytes / sf_count)

---

## TCP/forward-only “init” and segment features

72) `Init Fwd Win Byts`
- Current implementation: `flow.fwd_init_win_bytes`.
- In this repo today, it defaults to 0 and is **not parsed from TCP window** yet.

73) `Init Bwd Win Byts`
- Current implementation: `flow.bwd_init_win_bytes`.
- Same note as above.

74) `Fwd Act Data Pkts`
- Count of forward packets where `payload_len >= 1`.

75) `Fwd Seg Size Min`
- Minimum observed forward `header_len` (IP+TCP header bytes). If none, 0.

---

## Active/Idle time features (µs)

The flow is split into active periods and idle periods using internal timers.

76) `Active Mean`
77) `Active Std`
78) `Active Max`
79) `Active Min`

80) `Idle Mean`
81) `Idle Std`
82) `Idle Max`
83) `Idle Min`

---

## Notes for matching training data

- Some CICFlowMeter-derived datasets encode unavailable fields as `-1`.
	- This repo currently uses `0` for `Init * Win Byts` (since it is not parsed).
- If you want a 1:1 match to a specific dataset, we should align **both**:
	- parsing (e.g., TCP window + window scale), and
	- missing-value semantics (`0` vs `-1`).

