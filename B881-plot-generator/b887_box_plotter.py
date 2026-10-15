#!/usr/bin/env python3
"""
B887 NR5G MAC PDSCH Status — Multi-version Parser (with Hardware Timestamps)
============================================================================
Extracts MCS, Resource Blocks, RV, and Absolute Timestamps from 0xB887 log payloads.
"""

import sys, re, csv, argparse, datetime
from dataclasses import dataclass, fields as dc_fields
from typing import List, Optional, Tuple

# ── Constants ─────────────────────────────────────────────────────────────────
LOG_CODE        = 0xB887

# Version 2 layout
V2_REC_HDR_LEN   = 10
V2_ENTRY_LEN     = 18
V2_REC_LEN       = V2_REC_HDR_LEN + V2_ENTRY_LEN   # 28

# Version 3 layout
V3_REC_HDR_LEN   = 10
V3_ENTRY_LEN     = 22
V3_REC_LEN       = V3_REC_HDR_LEN + V3_ENTRY_LEN   # 32

SCS_MAP = {0: "15kHz", 1: "30kHz", 2: "60kHz", 3: "120kHz"}

# ── Data model ────────────────────────────────────────────────────────────────
@dataclass
class PdschRecord:
    timestamp:   datetime.datetime  # Extracted from the hardware header
    payload_idx: int
    record_idx:  int
    version:     int     
    slot:        Optional[int]
    frame:       Optional[int]
    scs:         Optional[str]
    carrier_id:  Optional[int]
    pci:         int
    nr_arfcn:    int
    tb_size:     int
    mcs:         int
    num_rbs:     int
    rv:          int
    harq_id:     int
    k1:          int
    num_layers:  int

    def to_dict(self):
        return {f.name: getattr(self, f.name) for f in dc_fields(self)}

# ── Helpers ───────────────────────────────────────────────────────────────────
def u16(b, o): return b[o] | (b[o+1] << 8)
def u32(b, o): return b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24)

def parse_qxdm_time(ts_bytes: bytes) -> datetime.datetime:
    """
    Converts the 8-byte QXDM hardware timestamp into a standard Python datetime (IST, UTC+5:30).
    The QXDM timestamp is a 64-bit little-endian integer.
    Upper 48 bits = number of 1.25 ms ticks since CDMA epoch (Jan 6, 1980 00:00:00 UTC).
    Lower 16 bits = fractional component (1/65536th of a tick).
    """
    if len(ts_bytes) != 8:
        raise ValueError(f"Expected 8 bytes for QXDM timestamp, got {len(ts_bytes)}")
        
    ts_int = int.from_bytes(ts_bytes, byteorder='little')
    
    integer_ticks = ts_int >> 16
    fractional_ticks = (ts_int & 0xFFFF) / 65536.0
    
    total_ticks = integer_ticks + fractional_ticks
    time_seconds = (total_ticks * 1.25 / 1000.0)
    
    cdma_epoch = datetime.datetime(1980, 1, 6, tzinfo=datetime.timezone.utc)
    utc_dt = cdma_epoch + datetime.timedelta(seconds=time_seconds)
    ist = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    return utc_dt.astimezone(ist)

def extract_entry_fields(entry: bytes) -> Tuple[int, int, int, int, int, int, int, int, int]:
    pci        = u16(entry, 2) & 0x3FF
    nr_arfcn   = (u32(entry, 3) >> 2) & 0x3FFFFF
    tb_size    = (u32(entry, 6) >> 5) & 0x1FFFF
    mcs        = (u16(entry, 9) >> 2) & 0x1F
    num_rbs    = u16(entry, 10) & 0x1FF
    rv         = (entry[11] >> 1) & 0x3
    harq_id    = (entry[11] >> 3) & 0xF
    k1         = (u16(entry, 12) >> 6) & 0xF
    num_layers = ((entry[13] >> 5) & 0x7) + 1
    return pci, nr_arfcn, tb_size, mcs, num_rbs, rv, harq_id, k1, num_layers

# ── Per-version record parsers ────────────────────────────────────────────────
def parse_record(rec: bytes, payload_idx: int, rec_idx: int, version: int, hw_timestamp: datetime.datetime) -> PdschRecord:
    slot       = rec[0]
    mu         = rec[1] & 0x0F
    frame      = u16(rec, 2) & 0x3FF
    carrier_id = rec[5]
    entry      = rec[V2_REC_HDR_LEN:] if version == 2 else rec[V3_REC_HDR_LEN:]
    pci, nr_arfcn, tb, mcs, rbs, rv, harq, k1, num_layers = extract_entry_fields(entry)
    
    return PdschRecord(
        timestamp=hw_timestamp,
        payload_idx=payload_idx, record_idx=rec_idx, version=version,
        slot=slot, frame=frame,
        scs=SCS_MAP.get(mu, f"mu{mu}"),
        carrier_id=carrier_id, pci=pci, nr_arfcn=nr_arfcn,
        tb_size=tb, mcs=mcs, num_rbs=rbs, rv=rv, harq_id=harq, k1=k1,
        num_layers=num_layers,
    )

# ── Payload parser ────────────────────────────────────────────────────────────
def parse_payload(payload: bytes, payload_idx: int, hw_timestamp: datetime.datetime) -> List[PdschRecord]:
    if u16(payload, 2) != LOG_CODE:
        return []

    version_word = u32(payload, 12)
    major = version_word >> 16

    RECORDS_START = 0
    if major == 2:
        rec_len     = V2_REC_LEN      
        RECORDS_START = 27
    elif major == 3:
        rec_len     = V3_REC_LEN       
        RECORDS_START = 19
    else:
        rec_len     = V2_REC_LEN
        RECORDS_START = 27

    num_records = payload[RECORDS_START]

    available = (len(payload) - RECORDS_START) // rec_len
    num_records = min(num_records, available)

    results = []
    for rec_idx in range(num_records):
        base = RECORDS_START + 1 + rec_idx * rec_len
        rec  = payload[base : base + rec_len]
        if len(rec) < rec_len:
            break
        results.append(parse_record(rec, payload_idx, rec_idx, major, hw_timestamp))
    return results

# ── Stream splitter ───────────────────────────────────────────────────────────
def split_packets(raw: bytes) -> List[Tuple[bytes, datetime.datetime]]:
    """
    Find all B887 packet boundaries and extract the absolute timestamp from the header.
    """
    packets, i = [], 0
    while i < len(raw) - 3:
        # Hunt for the 87 B8 log code signature which follows length bytes
        if raw[i+2] == 0x87 and raw[i+3] == 0xB8:
            pkt_len = raw[i] | (raw[i+1] << 8)
            
            if 32 <= pkt_len <= 4096 and i + pkt_len <= len(raw):
                pkt_data = raw[i : i + pkt_len]
                
                # Extract the 8-byte QXDM hardware timestamp from offsets 4-11
                ts_bytes = pkt_data[4:12]
                hw_timestamp = parse_qxdm_time(ts_bytes)
                
                packets.append((pkt_data, hw_timestamp))
                i += pkt_len
                continue
        i += 1
    return packets

# ── Public API ────────────────────────────────────────────────────────────────
def parse_stream(text: str, verbose: bool = True) -> List[PdschRecord]:
    tokens = re.findall(r'[0-9A-Fa-f]{2}', text)
    if not tokens:
        if verbose: print("No hex data found.")
        return []

    raw = bytes(int(t, 16) for t in tokens)
    all_results: List[PdschRecord] = []
    
    for idx, (pkt, hw_timestamp) in enumerate(split_packets(raw)):
        all_results.extend(parse_payload(pkt, idx, hw_timestamp))

    if verbose:
        print_results(all_results)
    return all_results

# ── Formatters ────────────────────────────────────────────────────────────────
def _fmt(v) -> str:
    return str(v) if v is not None else "—"

def print_results(results: List[PdschRecord]):
    if not results:
        print("No B887 records found.")
        return

    COL = ("Timestamp", "Pkt", "Rec", "Ver", "Slot", "Frame", "SCS", "CID", "Phy Cell ID", "NR-ARFCN", "TB Size", "MCS", "Num RBs", "RV", "HARQ", "K1", "Layers")
    FMT = "{:<26} {:>4}  {:>4}  {:>3}  {:>5}  {:>6}  {:>7}  {:>4} {:>11} {:>10} {:>8}  {:>4}  {:>8}  {:>3}  {:>5}  {:>4}  {:>6}"
    SEP = "=" * 130

    print(f"\n{SEP}")
    print("  B887 NR5G MAC PDSCH — Parsed Records with Hardware Timestamps")
    print(SEP)
    print("  " + FMT.format(*COL))
    print("  " + FMT.format(*("-" * len(c) for c in COL)))
    for r in results:
        ts_str = r.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')
        print("  " + FMT.format(
            ts_str, r.payload_idx, r.record_idx, r.version,
            _fmt(r.slot), _fmt(r.frame), _fmt(r.scs),
            _fmt(r.carrier_id), r.pci, r.nr_arfcn, r.tb_size, r.mcs,
            r.num_rbs, r.rv, r.harq_id, r.k1, r.num_layers))

    mcs_vals = [r.mcs for r in results]
    by_ver = {}
    for r in results:
        by_ver.setdefault(r.version, []).append(r.mcs)

    rv_counts = {}
    for r in results:
        rv_counts[r.rv] = rv_counts.get(r.rv, 0) + 1
    retx_count = sum(cnt for rv, cnt in rv_counts.items() if rv > 0)

    print(f"\n  Total records : {len(results)} (Initial Tx: {rv_counts.get(0, 0)}, Retx: {retx_count})")
    if retx_count > 0:
        retx_breakdown = ", ".join(f"RV{k}={v}" for k, v in sorted(rv_counts.items()) if k > 0)
        print(f"  Retransmissions : {retx_breakdown}")
    for v, vals in sorted(by_ver.items()):
        print(f"  Version {v}     : {len(vals)} record(s), MCS in {sorted(set(vals))}")
    if mcs_vals:
        print(f"  Overall MCS   : min={min(mcs_vals)}, max={max(mcs_vals)}, "
              f"avg={sum(mcs_vals)/len(mcs_vals):.2f}")
    print(SEP + "\n")

def write_csv(results: List[PdschRecord], path: str):
    if not results: return
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].to_dict().keys()))
        w.writeheader()
        w.writerows(r.to_dict() for r in results)
    print(f"CSV saved → {path}")

# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Parse 0xB887 NR5G PDSCH payloads (with timestamps).")
    ap.add_argument("input", nargs="?", help="Hex text file (stdin if omitted)")
    ap.add_argument("--csv",      metavar="FILE", help="Save results to CSV")
    ap.add_argument("--mcs-only", action="store_true",
                    help="Print compact MCS-only output, one record per line")
    args = ap.parse_args()

    text = open(args.input).read() if args.input else sys.stdin.read()
    results = parse_stream(text, verbose=not args.mcs_only)

    if args.mcs_only:
        for r in results:
            ts_str = r.timestamp.strftime('%H:%M:%S.%f')
            print(f"time={ts_str} pkt={r.payload_idx} rec={r.record_idx} ver={r.version} "
                  f"slot={_fmt(r.slot)} frame={_fmt(r.frame)} MCS={r.mcs} RV={r.rv}")
    if args.csv:
        write_csv(results, args.csv)

if __name__ == "__main__":
    main()
