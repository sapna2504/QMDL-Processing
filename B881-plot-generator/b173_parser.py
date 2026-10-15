#!/usr/bin/env python3
"""
b173_parser.py
==============
Parser and Telemetry Extractor for Qualcomm DIAG Log Type 0xB173
(LTE ML1 PDSCH Stat Indication / Physical Downlink Shared Channel Statistics).

Decodes:
  - Hardware modem timestamps (UTC and local IST)
  - Frame & Subframe numbers (SFN 0-1023, Subframe 0-9)
  - Carrier Component info (PCC, SCC1..SCC4)
  - Multi-Layer / MIMO allocation (Rank 1, 2, 4)
  - Resource Blocks (Num RBs) per subframe and per transport block
  - Dual-Codeword Transport Blocks (TB 0, TB 1)
  - HARQ Process ID, Redundancy Version (RV 0-3), New Data Indicator (NDI)
  - CRC Pass/Fail results & BLER (Block Error Rate)
  - Transport Block Sizes (Bytes & Bits) & Physical Layer Throughput
  - Modulation & Coding Scheme (MCS 0-31) and Modulation Order (QPSK..256QAM)
  - RNTI Type (C-RNTI, RA-RNTI, SI-RNTI, etc.) and Soft Recombining flags

Input formats supported:
  - Raw binary QMDL files (.qmdl) directly (streaming extraction)
  - Directory containing QMDL files
  - Hex payload text files (SCAT/QXDM formatted payload lines) or stdin (-)

Outputs:
  - Clean per-transport-block time-series CSV (ready for Pandas / ML / plotting)
  - Comprehensive statistical summary report (console or text file)
"""

import os
import sys
import csv
import glob
import time
import struct
import argparse
import datetime
from collections import Counter, defaultdict
from dataclasses import dataclass, fields as dc_fields
from typing import List, Dict, Any, Optional, Tuple, Generator

# ── Protocol Constants & Mapping Tables ───────────────────────────────────────
LOG_CODE_0XB173 = 0xB173

CELL_INDEX_MAP = {
    0: "PCC",
    1: "SCC1",
    2: "SCC2",
    3: "SCC3",
    4: "SCC4",
    5: "SCC5",
    6: "SCC6",
    7: "SCC7",
}

RNTI_TYPE_MAP = {
    0: "C-RNTI",
    1: "RA-RNTI",
    2: "P-RNTI",
    3: "SI-RNTI",
    4: "SPS / Temp C-RNTI",
    5: "M-RNTI",
}

MODULATION_MAP = {
    # Qualcomm modulation enum (v24/v32/v36/v40/v48):
    2: "QPSK",
    4: "16QAM",
    6: "64QAM",
    8: "256QAM",
    # Legacy enum:
    0: "QPSK",
    1: "16QAM",
    3: "256QAM",
}


@dataclass
class PdschStatRecord:
    timestamp_utc: str
    timestamp_ist: str
    epoch_sec: float
    payload_idx: int
    record_idx: int
    version: int
    frame_num: int
    subframe_num: int
    serving_cell_idx: int
    serving_cell: str
    num_rbs_subframe: int
    num_layers: int
    num_tbs_present: int
    hsic_enabled: int
    tb_idx: int
    harq_id: int
    rv: int
    ndi: int
    crc_pass: int
    crc_status: str
    rnti_type_id: int
    rnti_type: str
    tb_size_bytes: int
    tb_size_bits: int
    mcs: int
    modulation: str
    tb_rbs: int
    did_recombining: int
    pmch_id: int
    area_id: int

    def to_dict(self) -> Dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in dc_fields(self)}


# ── Qualcomm Timestamp Decoding ───────────────────────────────────────────────
def parse_qualcomm_timestamp(ts_raw: int) -> Tuple[datetime.datetime, float]:
    """
    Decodes 64-bit Qualcomm hardware timestamp into UTC datetime and Unix epoch seconds.
    Upper 48 bits = 1.25 ms units since 1980-01-06 00:00:00 UTC (Qualcomm Epoch).
    Lower 16 bits = fractional chip units (1/40960 s).
    """
    epoch_base_sec = 315964800.0  # Jan 6, 1980 00:00:00 UTC
    if ts_raw <= 0:
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        return now_dt, now_dt.timestamp()

    ts_upper = ts_raw >> 16
    ts_lower = ts_raw & 0xFFFF
    sec = epoch_base_sec + (ts_upper * 0.00125) + (ts_lower / 40960000.0)

    # Sanity check: valid cellular era (2020 - 2035)
    if not (1577836800.0 < sec < 2051222400.0):
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        return now_dt, now_dt.timestamp()

    dt_utc = datetime.datetime.fromtimestamp(sec, tz=datetime.timezone.utc)
    return dt_utc, sec


# ── HDLC Framing Helper ───────────────────────────────────────────────────────
def unwrap_hdlc(data: bytes) -> bytes:
    """Unwraps Qualcomm HDLC escape sequences: 0x7D 0x5E -> 0x7E, 0x7D 0x5D -> 0x7D."""
    if b'\x7d' not in data:
        return data
    return data.replace(b'\x7d\x5e', b'\x7e').replace(b'\x7d\x5d', b'\x7d')


# ── 0xB173 Binary Payload Decoder ─────────────────────────────────────────────
def decode_b173_payload(
    payload: bytes,
    dt_utc: datetime.datetime,
    epoch_sec: float,
    payload_idx: int
) -> List[PdschStatRecord]:
    """
    Decodes the raw binary payload of a 0xB173 LTE ML1 PDSCH Stat Indication packet.
    Supports modern LTE-A format (v48, v40, v37, v36: 40 bytes/record)
    with backward-compatible support for v34, v32, v24, v16, v5.
    """
    if len(payload) < 4:
        return []

    version = payload[0]
    num_records = payload[1]

    # Target timezone for IST (UTC+5:30)
    ist_tz = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    dt_ist = dt_utc.astimezone(ist_tz)
    ts_utc_str = dt_utc.strftime("%Y-%m-%d %H:%M:%S.%f")
    ts_ist_str = dt_ist.strftime("%Y-%m-%d %H:%M:%S.%f")

    # Determine record layout based on version
    if version >= 36:
        rec_size = 40
        p1_size = 12
        tb_size = 12
    elif version == 34:
        rec_size = 32
        p1_size = 6
        tb_size = 12
    elif version in (32, 24):
        rec_size = 24
        p1_size = 6
        tb_size = 8
    else:  # v16, v5, legacy
        rec_size = 20
        p1_size = 6
        tb_size = 6

    records = []
    header_offset = 4  # 1B version, 1B num_records, 2B reserved/skip

    for r_idx in range(num_records):
        rec_start = header_offset + (r_idx * rec_size)
        rec_end = rec_start + rec_size
        if rec_end > len(payload):
            break

        rec = payload[rec_start:rec_end]

        # 1. Parse Subframe Level (P1)
        subfn_raw = struct.unpack('<H', rec[0:2])[0]
        subframe = subfn_raw & 0xF
        frame = (subfn_raw >> 4) & 0xFFF
        num_rbs_subframe = rec[2]
        num_layers = rec[3]
        num_tbs_present = rec[4]
        cell_raw = rec[5]
        serv_cell_idx = cell_raw & 0x7
        hsic_enabled = (cell_raw >> 3) & 0xF
        cell_name = CELL_INDEX_MAP.get(serv_cell_idx, f"SCC{serv_cell_idx}")

        # PMCH & Area ID from P2
        if version >= 36:
            pmch_id = rec[36]
            area_id = rec[37]
        else:
            pmch_id = rec[-2]
            area_id = rec[-1]

        # 2. Parse Transport Blocks (TB 0 and TB 1)
        actual_tb_count = min(num_tbs_present, 2)
        for tb_i in range(actual_tb_count):
            tb_offset = p1_size + (tb_i * tb_size)
            tb_bytes = rec[tb_offset : tb_offset + tb_size]

            harq_byte = tb_bytes[0]
            harq_id = harq_byte & 0xF
            rv = (harq_byte >> 4) & 0x3
            ndi = (harq_byte >> 6) & 0x1
            crc_pass = (harq_byte >> 7) & 0x1
            crc_str = "PASS" if crc_pass else "FAIL"

            if version >= 36:
                rnti_word = struct.unpack('<H', tb_bytes[1:3])[0]
                rnti_type_id = rnti_word & 0xF
                did_recombining = (rnti_word >> 10) & 0x1
                tb_size_bytes = struct.unpack('<H', tb_bytes[4:6])[0]
                mcs = tb_bytes[6]
                tb_rbs = tb_bytes[7]
                mod_val = tb_bytes[8]
            elif version in (34, 32, 24):
                rnti_byte = tb_bytes[1]
                rnti_type_id = rnti_byte & 0xF
                did_recombining = (rnti_byte >> 6) & 0x1
                tb_size_bytes = struct.unpack('<H', tb_bytes[2:4])[0] if version == 32 else struct.unpack('<H', tb_bytes[4:6])[0]
                mcs = tb_bytes[4] if version == 32 else tb_bytes[6]
                tb_rbs = tb_bytes[5] if version == 32 else tb_bytes[7]
                mod_val = tb_bytes[6] if version == 32 else tb_bytes[8]
            else:
                rnti_type_id = tb_bytes[1] & 0xF
                did_recombining = 0
                tb_size_bytes = struct.unpack('<H', tb_bytes[2:4])[0]
                mcs = tb_bytes[4]
                tb_rbs = tb_bytes[5]
                mod_val = 0

            mod_str = MODULATION_MAP.get(mod_val, f"Mod_{mod_val}")
            rnti_str = RNTI_TYPE_MAP.get(rnti_type_id, f"RNTI_{rnti_type_id}")
            tb_size_bits = tb_size_bytes * 8

            record = PdschStatRecord(
                timestamp_utc=ts_utc_str,
                timestamp_ist=ts_ist_str,
                epoch_sec=epoch_sec,
                payload_idx=payload_idx,
                record_idx=r_idx,
                version=version,
                frame_num=frame,
                subframe_num=subframe,
                serving_cell_idx=serv_cell_idx,
                serving_cell=cell_name,
                num_rbs_subframe=num_rbs_subframe,
                num_layers=num_layers,
                num_tbs_present=num_tbs_present,
                hsic_enabled=hsic_enabled,
                tb_idx=tb_i,
                harq_id=harq_id,
                rv=rv,
                ndi=ndi,
                crc_pass=crc_pass,
                crc_status=crc_str,
                rnti_type_id=rnti_type_id,
                rnti_type=rnti_str,
                tb_size_bytes=tb_size_bytes,
                tb_size_bits=tb_size_bits,
                mcs=mcs,
                modulation=mod_str,
                tb_rbs=tb_rbs,
                did_recombining=did_recombining,
                pmch_id=pmch_id,
                area_id=area_id,
            )
            records.append(record)

    return records


# ── Streaming QMDL / Payload Readers ──────────────────────────────────────────
def iter_b173_from_qmdl(filepath: str) -> Generator[Tuple[bytes, datetime.datetime, float, int], None, None]:
    """Streams and yields (payload, dt_utc, epoch_sec, packet_idx) for 0xB173 from a QMDL file."""
    chunk_size = 16 * 1024 * 1024
    remainder = b''
    packet_idx = 0

    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                if remainder:
                    parts = [remainder]
                else:
                    break
            else:
                buf = remainder + chunk
                parts = buf.split(b'\x7e')
                remainder = parts.pop()

            for p in parts:
                if len(p) < 18:
                    continue
                p = unwrap_hdlc(p)
                if len(p) < 18:
                    continue
                p = p[:-2]  # strip CRC

                cmd = p[0]
                # Nested Multi-SIM packet (0x98)
                if cmd == 0x98 and len(p) >= 24:
                    p = p[8:]
                    cmd = p[0]

                if cmd == 0x10 and len(p) >= 18:
                    log_code = struct.unpack('<H', p[6:8])[0]
                    if log_code == LOG_CODE_0XB173:
                        packet_idx += 1
                        ts_raw = struct.unpack('<Q', p[8:16])[0]
                        dt_utc, epoch_sec = parse_qualcomm_timestamp(ts_raw)
                        payload = p[16:]
                        yield payload, dt_utc, epoch_sec, packet_idx

            if not chunk:
                break


def iter_b173_from_text(f_in) -> Generator[Tuple[bytes, datetime.datetime, float, int], None, None]:
    """Reads hex payload lines (from text file or stdin) and yields payloads."""
    import re
    packet_idx = 0
    now_dt = datetime.datetime.now(datetime.timezone.utc)
    epoch_sec = now_dt.timestamp()

    for line in f_in:
        line_clean = line.strip()
        if not line_clean or line_clean.startswith('#'):
            continue
        hex_bytes = re.findall(r'\b[0-9a-fA-F]{2}\b', line_clean)
        if len(hex_bytes) >= 4:
            payload = bytes(int(h, 16) for h in hex_bytes)
            packet_idx += 1
            yield payload, now_dt, epoch_sec, packet_idx


# ── Statistics & Summary Generator ────────────────────────────────────────────
def compute_summary(records: List[PdschStatRecord]) -> str:
    """Computes comprehensive telemetry metrics and formats a clean report."""
    if not records:
        return "No 0xB173 PDSCH records found in input."

    total_tbs = len(records)
    total_passed = sum(1 for r in records if r.crc_pass == 1)
    total_failed = total_tbs - total_passed
    bler = (total_failed / max(1, total_tbs)) * 100.0

    total_bytes = sum(r.tb_size_bytes for r in records if r.crc_pass == 1)
    total_mb = total_bytes / (1024 * 1024)

    # Time span
    timestamps = [r.epoch_sec for r in records if r.epoch_sec > 0]
    if timestamps and max(timestamps) > min(timestamps):
        span_sec = max(timestamps) - min(timestamps)
        throughput_mbps = (total_bytes * 8.0) / span_sec / 1e6
        start_str = datetime.datetime.fromtimestamp(min(timestamps), tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        end_str = datetime.datetime.fromtimestamp(max(timestamps), tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        span_sec = 0.0
        throughput_mbps = 0.0
        start_str = "N/A"
        end_str = "N/A"

    # Aggregations
    mod_counts = Counter(r.modulation for r in records)
    layer_counts = Counter(r.num_layers for r in records)
    cell_counts = Counter(r.serving_cell for r in records)
    mcs_counts = Counter(r.mcs for r in records)
    rv_counts = Counter(r.rv for r in records)
    harq_counts = Counter(r.harq_id for r in records)

    # Per-cell breakdown
    cell_bytes = defaultdict(int)
    cell_tbs = defaultdict(int)
    cell_failed = defaultdict(int)
    for r in records:
        cell_tbs[r.serving_cell] += 1
        if r.crc_pass == 1:
            cell_bytes[r.serving_cell] += r.tb_size_bytes
        else:
            cell_failed[r.serving_cell] += 1

    lines = []
    lines.append("=" * 88)
    lines.append(" 0xB173 LTE ML1 PDSCH STAT INDICATION — TELEMETRY SUMMARY")
    lines.append("=" * 88)
    lines.append(f" Total Transport Blocks Decoded : {total_tbs:,}")
    lines.append(f" CRC Results (Pass / Fail)      : {total_passed:,} PASS | {total_failed:,} FAIL")
    lines.append(f" Block Error Rate (BLER)        : {bler:.2f}%")
    lines.append(f" Valid Decoded PDSCH Data Volume: {total_bytes:,} Bytes ({total_mb:.2f} MB)")
    if span_sec > 0:
        lines.append(f" Timeline Active Span           : {start_str}  -->  {end_str} ({span_sec:.2f} s)")
        lines.append(f" Average PDSCH DL Throughput    : {throughput_mbps:.2f} Mbps")
    lines.append("-" * 88)

    lines.append(" CARRIER AGGREGATION & CELL BREAKDOWN:")
    lines.append(f" {'Cell':<8} | {'Total TBs':<11} | {'Share (%)':<10} | {'DL Bytes':<14} | {'DL (MB)':<10} | {'BLER (%)':<9}")
    lines.append("-" * 72)
    for cell in sorted(cell_counts.keys()):
        c_cnt = cell_tbs[cell]
        c_share = (c_cnt / max(1, total_tbs)) * 100.0
        c_b = cell_bytes[cell]
        c_mb = c_b / (1024 * 1024)
        c_bler = (cell_failed[cell] / max(1, c_cnt)) * 100.0
        lines.append(f" {cell:<8} | {c_cnt:<11,d} | {c_share:>8.2f}% | {c_b:<14,d} | {c_mb:>8.2f} MB | {c_bler:>7.2f}%")
    lines.append("-" * 72)

    lines.append(" MODULATION DISTRIBUTION:")
    for mod in ["QPSK", "16QAM", "64QAM", "256QAM"]:
        cnt = mod_counts.get(mod, 0)
        pct = (cnt / max(1, total_tbs)) * 100.0
        lines.append(f"   {mod:<8} : {cnt:>8,d} ({pct:>5.2f}%)")

    lines.append(" MIMO LAYER (SPATIAL RANK) DISTRIBUTION:")
    for layer in sorted(layer_counts.keys()):
        cnt = layer_counts[layer]
        pct = (cnt / max(1, total_tbs)) * 100.0
        lines.append(f"   Rank {layer:<3} : {cnt:>8,d} ({pct:>5.2f}%)")

    lines.append(" TOP 10 SCHEDULED MCS INDICES:")
    for mcs_val, cnt in mcs_counts.most_common(10):
        pct = (cnt / max(1, total_tbs)) * 100.0
        lines.append(f"   MCS {mcs_val:>2}  : {cnt:>8,d} ({pct:>5.2f}%)")

    lines.append(" REDUNDANCY VERSION (RV) DISTRIBUTION:")
    for rv_val in sorted(rv_counts.keys()):
        cnt = rv_counts[rv_val]
        pct = (cnt / max(1, total_tbs)) * 100.0
        rv_label = "New Tx" if rv_val == 0 else f"ReTx (RV={rv_val})"
        lines.append(f"   RV {rv_val} ({rv_label:<14}) : {cnt:>8,d} ({pct:>5.2f}%)")

    lines.append("=" * 88)
    return "\n".join(lines)


# ── Main Entry Point ──────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Comprehensive parser for Qualcomm DIAG log type 0xB173 (LTE ML1 PDSCH Stat Indication).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Parse a QMDL file and export CSV to default name (<file>_b173_pdsch_stats.csv)
  python3 b173_parser.py loggers/vodafone_5g_toggle_off/diag_log_*.qmdl

  # Parse and specify custom CSV and text summary report paths
  python3 b173_parser.py loggers/vodafone_5g_toggle_off -o pdsch_stats.csv --summary summary.txt

  # Parse from raw hex payload text file or pipeline via stdin
  python3 qmdl_to_codes.py input.txt --code 0xb173 | python3 b173_parser.py - -o parsed_b173.csv
"""
    )
    parser.add_argument("input", help="Path to .qmdl file, directory containing QMDL files, hex text file, or '-' for stdin")
    parser.add_argument("-o", "--output", help="Output CSV path (default: <input_basename>_b173_pdsch_stats.csv)")
    parser.add_argument("-s", "--summary", help="Optional path to save ASCII summary report text file")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress console stdout printing")
    parser.add_argument("--include-rf", action="store_true", help="Include secondary RF modem files (mdm2)")

    args = parser.parse_args()

    records: List[PdschStatRecord] = []
    t0 = time.time()

    # 1. Handle STDIN / Text file mode
    if args.input == "-":
        if not args.quiet:
            print("[*] Reading 0xB173 payloads from STDIN...")
        for payload, dt_utc, epoch_sec, p_idx in iter_b173_from_text(sys.stdin):
            records.extend(decode_b173_payload(payload, dt_utc, epoch_sec, p_idx))

    elif os.path.isfile(args.input) and not args.input.endswith(".qmdl"):
        # Text payload file
        if not args.quiet:
            print(f"[*] Reading 0xB173 payloads from text file: {args.input}")
        with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
            for payload, dt_utc, epoch_sec, p_idx in iter_b173_from_text(f):
                records.extend(decode_b173_payload(payload, dt_utc, epoch_sec, p_idx))

    # 2. Handle Binary QMDL mode
    else:
        target = args.input.lstrip('@')
        qmdl_files = []
        if os.path.isfile(target):
            qmdl_files = [target]
        elif os.path.isdir(target):
            qmdl_files = sorted(glob.glob(os.path.join(target, "**", "*.qmdl"), recursive=True))
        else:
            qmdl_files = sorted(glob.glob(target, recursive=True))

        if not args.include_rf:
            qmdl_files = [f for f in qmdl_files if "mdm2" not in f]

        if not qmdl_files:
            print(f"[!] Error: No QMDL files found matching: {args.input}", file=sys.stderr)
            sys.exit(1)

        if not args.quiet:
            print(f"[*] Parsing 0xB173 records across {len(qmdl_files)} QMDL file(s)...")

        for fpath in qmdl_files:
            if not args.quiet:
                print(f"    - Processing: {fpath} ({os.path.getsize(fpath)/(1024*1024):.1f} MB)...")
            for payload, dt_utc, epoch_sec, p_idx in iter_b173_from_qmdl(fpath):
                records.extend(decode_b173_payload(payload, dt_utc, epoch_sec, p_idx))

    parse_time = time.time() - t0
    if not args.quiet:
        print(f"[*] Extracted {len(records):,} transport block records in {parse_time:.2f} seconds.")

    # 3. Determine output CSV filename
    if args.output:
        csv_path = args.output
    else:
        target_name = os.path.basename(args.input.rstrip("/\\"))
        base_name = os.path.splitext(target_name)[0]
        if not base_name or base_name == "*":
            base_name = "b173"
        csv_path = f"{base_name}_b173_pdsch_stats.csv"

    # Ensure parent dir exists
    out_dir = os.path.dirname(csv_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    # 4. Write CSV
    if records:
        fieldnames = list(records[0].to_dict().keys())
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in records:
                writer.writerow(r.to_dict())

        if not args.quiet:
            print(f"[✓] Saved {len(records):,} records to CSV: {csv_path}")
    else:
        if not args.quiet:
            print("[!] Warning: No 0xB173 records found to write to CSV.")

    # 5. Generate and Print/Save Summary
    summary_report = compute_summary(records)

    if args.summary:
        sum_dir = os.path.dirname(args.summary)
        if sum_dir:
            os.makedirs(sum_dir, exist_ok=True)
        with open(args.summary, "w", encoding="utf-8") as f:
            f.write(summary_report + "\n")
        if not args.quiet:
            print(f"[✓] Saved summary report to: {args.summary}")

    if not args.quiet:
        print("\n" + summary_report)


if __name__ == "__main__":
    main()
