#!/usr/bin/env python3
"""
B881 NR5G MAC UL TB Stats Parser (Multi-Carrier & Carrier Aggregation)
============================================================================
Extracts true Payload Throughput (TB New Tx Bytes), Retransmissions,
Carrier Aggregation parameters (Num Records, Carrier ID, DL/UL Config),
Physical Resource Allocations (PRB, MCS), and Downlink UCI Feedback (RI, CQI)
from 0xB881 log payloads. Automatically computes per-carrier deltas,
normalized per-slot metrics (PRB/Slot, Bytes/Slot, MCS/Slot), BLER (%),
and throughput for immediate PCAP correlation.

Reference: MobileInsight repository (dm_collector_c/nr_mac_ul_tb_stats.h)
"""

import sys, os, re, csv, struct, argparse, datetime
from dataclasses import dataclass, fields as dc_fields
from typing import List, Optional, Tuple, Dict

# ── Constants ─────────────────────────────────────────────────────────────────
LOG_CODE = 0xB881

# ── Data model ────────────────────────────────────────────────────────────────
@dataclass
class UlTbStatsRecord:
    timestamp:               datetime.datetime
    payload_idx:             int
    record_idx:              int
    version:                 str
    carrier_id:              int
    carrier_role:            str
    num_records:             int
    dl_config:               int
    ul_config:               int
    ml1_state_change:        int
    dl_dynamic_cfg_change:   int
    log_fields_change_bmask:  int

    # Raw Cumulative Baseband Counters
    new_tx_bytes:            int = 0
    retx_bytes:              int = 0
    num_mcs:                 int = 0
    num_prb:                 int = 0
    phr:                     int = 0
    total_power:             int = 0
    num_new_tx_tb:           int = 0
    num_retx_tb:             int = 0
    num_dtx:                 int = 0
    num_ri:                  int = 0
    ri:                      int = 0
    num_cqi:                 int = 0
    cqi:                     int = 0
    num_ulsch_sched:         int = 0
    num_no_ulsch_sched:      int = 0
    pcmax:                   int = 0
    pcmax_dbm:               float = 0.0
    flush_gap_count:         int = 0

    # Delta Metrics (per Telemetry Reporting Interval)
    delta_tx_bytes:          int = 0
    delta_retx_bytes:        int = 0
    throughput_mbps:         Optional[float] = None
    retx_ratio_pct:          float = 0.0
    delta_new_tx_tb:         int = 0
    delta_retx_tb:           int = 0
    delta_slots:             int = 0    # Total scheduled TBs / slots (New + ReTx)
    bler_pct:                float = 0.0
    delta_prb:               int = 0
    delta_mcs:               int = 0
    delta_ri:                int = 0
    avg_ri:                  Optional[float] = None
    avg_cqi:                 Optional[float] = None

    # Normalized Per-Slot Metrics
    prb_per_slot:            Optional[float] = None
    bytes_per_slot:          Optional[float] = None
    avg_mcs:                 Optional[float] = None

    def to_dict(self):
        d = {f.name: getattr(self, f.name) for f in dc_fields(self)}
        d['timestamp'] = self.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')
        return d

# ── Helpers ───────────────────────────────────────────────────────────────────
def u16(b: bytes, o: int) -> int:
    return b[o] | (b[o+1] << 8)

def u32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o+4], byteorder='little')

def u64(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o+8], byteorder='little')

def parse_qxdm_time(ts_bytes: bytes) -> datetime.datetime:
    """
    Converts 8-byte QXDM hardware timestamp into datetime (IST, UTC+5:30).
    Upper 48 bits = 1.25 ms ticks since CDMA epoch (Jan 6, 1980 00:00:00 UTC).
    Lower 16 bits = fractional component (1/65536 of a tick).
    """
    if len(ts_bytes) != 8:
        return datetime.datetime.now(datetime.timezone.utc)

    ts_int = int.from_bytes(ts_bytes, byteorder='little')
    integer_ticks = ts_int >> 16
    fractional_ticks = (ts_int & 0xFFFF) / 65536.0

    total_ticks = integer_ticks + fractional_ticks
    time_seconds = total_ticks * 1.25 / 1000.0

    cdma_epoch = datetime.datetime(1980, 1, 6, tzinfo=datetime.timezone.utc)
    utc_dt = cdma_epoch + datetime.timedelta(seconds=time_seconds)
    ist = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    return utc_dt.astimezone(ist)

# ── Payload parser ────────────────────────────────────────────────────────────
def parse_payload(payload: bytes, payload_idx: int, hw_timestamp: datetime.datetime) -> List[UlTbStatsRecord]:
    if len(payload) < 24:
        return []
    if u16(payload, 2) != LOG_CODE:
        return []

    minor_ver = u16(payload, 12)
    major_ver = u16(payload, 14)
    version_str = f"{major_ver}.{minor_ver}"

    # Extract Subpacket Header Fields according to MobileInsight NrMacUlTbStats_Fmt
    sleep                 = payload[16]
    beam_change           = payload[17]
    signal_change         = payload[18]
    dl_dynamic_cfg_change = 0
    dl_config             = 0
    ul_config_raw         = 0
    num_records           = 1
    log_fields_bmask      = 0

    if major_ver == 3 and minor_ver == 1:
        # v3.1 12-byte subpacket header (payload[12:24])
        # Byte 19 = Num Records (Component Carriers)
        num_records           = payload[19] if payload[19] > 0 else 1
        dl_dynamic_cfg_change = payload[20]
        dl_config             = payload[21]
        ul_config_raw         = payload[22]
        ul_config             = ul_config_raw & 0x0F
        ml1_state_change      = (ul_config_raw >> 4) & 0x0F
        log_fields_bmask      = payload[23]
        rec_offset_start      = 24
        rec_len               = 80
    elif major_ver == 2:
        # MobileInsight NrMacUlTbStats_Fmt (20-byte subpacket header)
        dl_dynamic_cfg_change = payload[19]
        dl_config             = payload[20]
        ul_config_raw         = payload[21]
        ul_config             = ul_config_raw & 0x0F
        ml1_state_change      = (ul_config_raw >> 4) & 0x0F
        log_fields_bmask      = u16(payload, 24) if len(payload) >= 26 else 0
        num_records           = payload[27] if len(payload) >= 28 and payload[27] > 0 else 1
        rec_offset_start      = 32
        rec_len               = 96 if minor_ver == 1 else 92
    else:
        num_records           = payload[19] if payload[19] > 0 else 1
        ul_config             = 0
        ml1_state_change      = 0
        rec_offset_start      = 24
        rec_len               = 80

    results: List[UlTbStatsRecord] = []
    O = rec_offset_start

    for rec_idx in range(num_records):
        if O + rec_len > len(payload):
            break

        # In Qualcomm Carrier Aggregation, each record corresponds to a Component Carrier
        carrier_id = rec_idx
        carrier_role = "PCC (PCell)" if carrier_id == 0 else f"SCC (SCell {carrier_id})"

        if major_ver == 3 and minor_ver == 1:
            new_tx      = u64(payload, O)
            retx        = u64(payload, O+8)
            num_mcs     = u64(payload, O+16)
            num_prb     = u64(payload, O+24)
            phr         = u64(payload, O+32)
            total_pwr   = u32(payload, O+40)
            num_new_tb  = u32(payload, O+44)
            num_retx_tb = u32(payload, O+48)
            num_ri      = u32(payload, O+52)
            ri          = u32(payload, O+56)
            num_cqi     = u32(payload, O+60)
            cqi         = u32(payload, O+64)
            ulsch_sched = u32(payload, O+68)
            no_sched    = u32(payload, O+72)
            pcmax_raw   = u16(payload, O+76)
            flush_gap   = u16(payload, O+78)
            num_dtx     = 0
        elif major_ver == 2 and minor_ver == 1:
            # v2.1 MobileInsight NrMacUlTbStatsRecord_v2_1
            new_tx      = u64(payload, O)
            retx        = u64(payload, O+8)
            num_mcs     = u64(payload, O+16)
            num_prb     = u64(payload, O+24)
            phr         = u64(payload, O+32)
            total_pwr   = u64(payload, O+40)
            num_new_tb  = u32(payload, O+48)
            num_retx_tb = u32(payload, O+52)
            num_ri      = u32(payload, O+56)
            ri          = u32(payload, O+60)
            num_cqi     = u32(payload, O+64)
            cqi         = u32(payload, O+68)
            sched_offset= 80
            ulsch_sched = u32(payload, O+sched_offset)
            no_sched    = u32(payload, O+sched_offset+4)
            pcmax_raw   = u16(payload, O+88)
            flush_gap   = u16(payload, O+90)
            num_dtx     = 0
        elif major_ver == 2 and minor_ver == 0:
            # v2.0 MobileInsight Records_v2_0
            new_tx      = u64(payload, O)
            retx        = u64(payload, O+8)
            num_mcs     = u64(payload, O+16)
            num_prb     = u64(payload, O+24)
            phr         = u64(payload, O+32)
            total_pwr   = u32(payload, O+40)
            num_new_tb  = u32(payload, O+44)
            num_retx_tb = u32(payload, O+48)
            num_dtx     = u32(payload, O+52)
            num_ri      = u32(payload, O+56)
            ri          = u32(payload, O+60)
            num_cqi     = u32(payload, O+64)
            cqi         = u32(payload, O+68)
            sched_offset= 80
            ulsch_sched = u32(payload, O+sched_offset)
            no_sched    = u32(payload, O+sched_offset+4)
            pcmax_raw   = u16(payload, O+88)
            flush_gap   = u16(payload, O+90)
        else:
            new_tx      = u64(payload, O)
            retx        = u64(payload, O+8)
            num_mcs     = u64(payload, O+16)
            num_prb     = u64(payload, O+24)
            phr         = u64(payload, O+32)
            total_pwr   = u32(payload, O+40)
            num_new_tb  = u32(payload, O+44)
            num_retx_tb = u32(payload, O+48)
            num_ri      = u32(payload, O+52)
            ri          = u32(payload, O+56)
            num_cqi     = u32(payload, O+60)
            cqi         = u32(payload, O+64)
            ulsch_sched = u32(payload, O+68)
            no_sched    = u32(payload, O+72)
            pcmax_raw   = u16(payload, O+76)
            flush_gap   = u16(payload, O+78)
            num_dtx     = 0

        # Pcmax is reported in 1/10th dBm (e.g. 250 -> 25.0 dBm)
        pcmax_dbm = pcmax_raw / 10.0 if pcmax_raw > 0 else 0.0

        results.append(UlTbStatsRecord(
            timestamp=hw_timestamp,
            payload_idx=payload_idx,
            record_idx=rec_idx,
            version=version_str,
            carrier_id=carrier_id,
            carrier_role=carrier_role,
            num_records=num_records,
            dl_config=dl_config,
            ul_config=ul_config,
            ml1_state_change=ml1_state_change,
            dl_dynamic_cfg_change=dl_dynamic_cfg_change,
            log_fields_change_bmask=log_fields_bmask,
            new_tx_bytes=new_tx,
            retx_bytes=retx,
            num_mcs=num_mcs,
            num_prb=num_prb,
            phr=phr,
            total_power=total_pwr,
            num_new_tx_tb=num_new_tb,
            num_retx_tb=num_retx_tb,
            num_dtx=num_dtx,
            num_ri=num_ri,
            ri=ri,
            num_cqi=num_cqi,
            cqi=cqi,
            num_ulsch_sched=ulsch_sched,
            num_no_ulsch_sched=no_sched,
            pcmax=pcmax_raw,
            pcmax_dbm=pcmax_dbm,
            flush_gap_count=flush_gap
        ))

        O += rec_len

    return results

def split_packets(raw: bytes) -> List[Tuple[bytes, datetime.datetime]]:
    packets, i = [], 0
    while i < len(raw) - 3:
        if raw[i+2] == 0x81 and raw[i+3] == 0xB8:
            pkt_len = raw[i] | (raw[i+1] << 8)
            if 32 <= pkt_len <= 4096 and i + pkt_len <= len(raw):
                pkt_data = raw[i : i + pkt_len]
                ts_bytes = pkt_data[4:12]
                hw_timestamp = parse_qxdm_time(ts_bytes)
                packets.append((pkt_data, hw_timestamp))
                i += pkt_len - 1
        i += 1
    return packets

def parse_stream(text: str, verbose: bool = True, limit: Optional[int] = None) -> List[UlTbStatsRecord]:
    tokens = re.findall(r'[0-9A-Fa-f]{2}', text)
    if not tokens:
        return []
    raw = bytes(int(t, 16) for t in tokens)

    all_results: List[UlTbStatsRecord] = []
    for idx, (pkt, hw_timestamp) in enumerate(split_packets(raw)):
        all_results.extend(parse_payload(pkt, idx, hw_timestamp))

    if not all_results:
        return []

    # Sort chronologically by timestamp and carrier ID
    all_results.sort(key=lambda x: (x.timestamp, x.carrier_id))

    # Compute deltas and per-slot normalized metrics independently PER CARRIER
    prev_per_carrier: Dict[int, UlTbStatsRecord] = {}

    for r in all_results:
        cid = r.carrier_id
        if cid in prev_per_carrier:
            prev = prev_per_carrier[cid]
            dt = (r.timestamp - prev.timestamp).total_seconds()

            # Guard against capture concatenations, packet resets, or clock jumps
            is_reset = (dt > 2.0 or dt < 0 or r.payload_idx < prev.payload_idx or r.new_tx_bytes < prev.new_tx_bytes)

            if not is_reset:
                # Scheduled Transport Blocks / Slots in this interval
                d_new_tb = r.num_new_tx_tb - prev.num_new_tx_tb
                r.delta_new_tx_tb = d_new_tb if d_new_tb >= 0 else 0

                d_retx_tb = r.num_retx_tb - prev.num_retx_tb
                r.delta_retx_tb = d_retx_tb if d_retx_tb >= 0 else 0

                total_slots = r.delta_new_tx_tb + r.delta_retx_tb
                r.delta_slots = total_slots
                r.bler_pct = (r.delta_retx_tb / total_slots * 100.0) if total_slots > 0 else 0.0

                # Payload Bytes & Throughput
                d_tx = r.new_tx_bytes - prev.new_tx_bytes
                r.delta_tx_bytes = d_tx if d_tx >= 0 else 0

                d_retx = r.retx_bytes - prev.retx_bytes
                r.delta_retx_bytes = d_retx if d_retx >= 0 else 0

                total_d_bytes = r.delta_tx_bytes + r.delta_retx_bytes
                r.retx_ratio_pct = (r.delta_retx_bytes / total_d_bytes * 100.0) if total_d_bytes > 0 else 0.0

                if dt > 0 and r.delta_tx_bytes > 0:
                    r.throughput_mbps = (r.delta_tx_bytes * 8) / (dt * 1e6)

                # PRB & MCS Deltas
                d_prb = r.num_prb - prev.num_prb
                r.delta_prb = d_prb if d_prb >= 0 else 0

                d_mcs = r.num_mcs - prev.num_mcs
                r.delta_mcs = d_mcs if d_mcs >= 0 else 0

                # Normalized Per-Slot Values (Strictly per scheduled grant/slot)
                if total_slots > 0:
                    r.prb_per_slot = r.delta_prb / total_slots
                    r.bytes_per_slot = r.delta_tx_bytes / total_slots
                    if r.delta_mcs > 0:
                        r.avg_mcs = r.delta_mcs / total_slots

                # RI Feedback
                d_ri = r.ri - prev.ri
                r.delta_ri = d_ri if d_ri >= 0 else 0
                d_num_ri = r.num_ri - prev.num_ri
                if d_num_ri > 0 and r.delta_ri > 0:
                    r.avg_ri = r.delta_ri / d_num_ri

                # CQI Feedback
                r.avg_cqi = float(r.cqi) if 0 < r.cqi <= 15 else None

        prev_per_carrier[cid] = r

    if verbose and all_results:
        print_records(all_results, limit=limit)
        print_carrier_summary(all_results)

    return all_results

def print_records(records: List[UlTbStatsRecord], limit: Optional[int] = None):
    print("\n" + "=" * 156)
    print("  B881 NR5G MAC UL TB Stats — Parsed Multi-Carrier Telemetry (with Normalized Per-Slot Allocations)")
    print("=" * 156)
    print(f"  {'Timestamp':<24} {'Delta Tx (B)':<13} {'Mbps':<8} {'ReTx (B)':<9} {'Slots':<6} {'PRB/Slot':<9} {'MCS/Slot':<6} {'B/Slot':<9}")
    print("  " + "-" * 152)

    display = records[:limit] if limit else records
    for r in display:
        ts_str = r.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        mbps_str = f"{r.throughput_mbps:.2f}" if r.throughput_mbps is not None else "-"
        prb_slot_str = f"{r.prb_per_slot:.1f}" if r.prb_per_slot is not None else "-"
        mcs_str = f"{r.avg_mcs:.1f}" if r.avg_mcs is not None else "-"
        b_slot_str = f"{r.bytes_per_slot:.1f}" if r.bytes_per_slot is not None else "-"
        ri_str = f"{r.avg_ri:.2f}" if r.avg_ri is not None else (f"{r.delta_ri}" if r.delta_ri > 0 else "-")
        cqi_str = f"{r.avg_cqi:.1f}" if r.avg_cqi is not None else f"{r.cqi}"
        pcmax_str = f"{r.pcmax_dbm:.1f}dBm" if r.pcmax_dbm > 0 else "-"
        slots_str = str(r.delta_slots) if r.delta_slots > 0 else "0"

        print(f"  {ts_str:<24} {r.delta_tx_bytes:<13,d} {mbps_str:<8} {r.delta_retx_bytes:<9,d} {slots_str:<6} {prb_slot_str:<9} {mcs_str:<6} {b_slot_str:<9}")
    print("=" * 156)

def print_carrier_summary(records: List[UlTbStatsRecord]):
    if not records:
        return
    cids = sorted(list(set(r.carrier_id for r in records)))
    print(f"\n--- Multi-Carrier / CA Performance Summary ({len(cids)} Component Carrier(s) Detected) ---")
    for cid in cids:
        c_recs = [r for r in records if r.carrier_id == cid]
        first, last = c_recs[0], c_recs[-1]
        dt = (last.timestamp - first.timestamp).total_seconds()
        
        # Aggregate delta sums to properly handle sessions with boundary resets
        total_d_tx = sum(r.delta_tx_bytes for r in c_recs)
        total_d_retx = sum(r.delta_retx_bytes for r in c_recs)
        total_new_tb = sum(r.delta_new_tx_tb for r in c_recs)
        total_retx_tb = sum(r.delta_retx_tb for r in c_recs)
        total_slots = total_new_tb + total_retx_tb
        total_prb = sum(r.delta_prb for r in c_recs)
        total_mcs = sum(r.delta_mcs for r in c_recs)
        
        bler = (total_retx_tb / total_slots * 100.0) if total_slots > 0 else 0.0
        avg_mbps = (total_d_tx * 8) / (dt * 1e6) if dt > 0 else 0.0
        avg_prb_slot = (total_prb / total_slots) if total_slots > 0 else 0.0
        avg_bytes_slot = (total_d_tx / total_slots) if total_slots > 0 else 0.0
        avg_mcs = (total_mcs / total_slots) if total_slots > 0 else 0.0
        
        d_ri = sum(r.delta_ri for r in c_recs)
        ri_updates = sum(1 for r in c_recs if r.delta_ri > 0)
        avg_ri = (d_ri / ri_updates) if ri_updates > 0 else 0.0
        
        valid_cqis = [r.cqi for r in c_recs if 0 < r.cqi <= 15]
        avg_cqi = (sum(valid_cqis) / len(valid_cqis)) if valid_cqis else 0.0

        role = "Primary Carrier (PCell)" if cid == 0 else f"Secondary Carrier (SCell {cid})"
        print(f"  Carrier ID {cid} [{role}]:")
        print(f"    Duration                : {dt:.2f} s ({len(c_recs):,} telemetry updates)")
        print(f"    New Tx Payload          : {total_d_tx / (1024**2):,.2f} MB ({total_d_tx:,} bytes)")
        print(f"    ReTx Payload            : {total_d_retx / (1024**2):,.2f} MB ({total_d_retx:,} bytes)")
        print(f"    Scheduled Slots / TBs   : {total_slots:,} (New: {total_new_tb:,}, ReTx: {total_retx_tb:,})")
        print(f"    Average PRB / Slot      : {avg_prb_slot:.2f} PRBs/slot")
        print(f"    Average Payload / Slot  : {avg_bytes_slot:.2f} Bytes/slot")
        print(f"    Average MCS             : {avg_mcs:.2f}")
        print(f"    Average Throughput      : {avg_mbps:.2f} Mbps")
        print()

def write_csv(results: List[UlTbStatsRecord], path: str):
    if not results: return
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].to_dict().keys()))
        w.writeheader()
        w.writerows(r.to_dict() for r in results)
    print(f"CSV saved → {path}")

# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Parse 0xB881 NR5G MAC UL TB Stats payloads with per-slot normalized metrics.")
    ap.add_argument("input", nargs="?", help="Hex text file (stdin if omitted)")
    ap.add_argument("--csv", metavar="FILE", help="Save results to CSV")
    ap.add_argument("--limit", type=int, default=None, help="Limit number of rows to print")
    args = ap.parse_args()

    if not args.input and sys.stdin.isatty():
        ap.print_help()
        sys.exit(1)

    text = open(args.input).read() if args.input else sys.stdin.read()
    results = parse_stream(text, limit=args.limit)

    if args.csv:
        write_csv(results, args.csv)

if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        try:
            sys.stderr.close()
        except Exception:
            pass
