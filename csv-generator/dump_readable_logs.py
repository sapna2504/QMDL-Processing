#!/usr/bin/env python3
"""
dump_readable_logs.py

Reads a combined-payloads.txt (or any DIAG log payload text file)
and writes two human-readable CSV files:

  <output_prefix>_b881.csv   - one row per B881 record, with cumulative fields
                                AND per-carrier deltas (new_tx_bytes, retx_bytes,
                                num_mcs, num_prb, num_new_tb, num_retx_tb,
                                avg_mcs, avg_prb, retx_rate_pct, interval_sec, throughput_mbps)

  <output_prefix>_b887.csv   - one row per B887 grant, with human-readable time,
                                frame, slot, pci, nr_arfcn, tb_size, mcs, num_rbs,
                                harq_id, k1, rv, num_layers, scs

Usage:
    python3 dump_readable_logs.py <combined_payload.txt> [output_prefix]

If output_prefix is omitted, it defaults to the payload filename without extension.

This script independently decodes and calculates all metrics:
  - Standalone multi-version B881 and B887 decoding (standard library only; no external dependencies).
  - B881 cumulative counters and deltas are tracked independently per component carrier (CA).
  - Throughput (Mbps) is calculated using true elapsed time intervals (dt).
  - Reset and anomaly guards handle capture gaps, clock jumps, and counter wraps.
  - Header-only CSVs are guaranteed if a log type has zero records in the input file.
"""

import sys
import os
import re
import csv
import datetime
import traceback

B881_HEADER = [
    "timestamp_epoch", "timestamp_utc",
    "cum_new_tx_bytes", "cum_retx_bytes", "cum_num_mcs", "cum_num_prb",
    "cum_num_new_tb", "cum_num_retx_tb",
    "delta_new_tx_bytes", "delta_retx_bytes", "delta_num_mcs", "delta_num_prb",
    "delta_num_new_tb", "delta_num_retx_tb",
    "avg_mcs_this_interval", "avg_prb_this_interval", "retx_rate_pct_this_interval",
    "interval_sec", "throughput_mbps",
]

B887_HEADER = [
    "timestamp_epoch", "timestamp_utc", "frame", "slot", "pci",
    "nr_arfcn", "tb_size_bytes", "mcs", "num_rbs", "harq_id", "k1",
    "rv", "num_layers", "scs",
]

SCS_MAP = {0: "15kHz", 1: "30kHz", 2: "60kHz", 3: "120kHz"}


def u16(b, o):
    return b[o] | (b[o + 1] << 8)


def u32(b, o):
    return int.from_bytes(b[o : o + 4], byteorder="little")


def u64(b, o):
    return int.from_bytes(b[o : o + 8], byteorder="little")


def parse_qxdm_time(ts_bytes):
    """
    Converts 8-byte QXDM hardware timestamp into UNIX epoch float.
    Upper 48 bits = 1.25 ms ticks since CDMA epoch (Jan 6, 1980 00:00:00 UTC).
    Lower 16 bits = fractional component (1/65536 of a tick).
    """
    ts_int = int.from_bytes(ts_bytes, byteorder="little")
    integer_ticks = ts_int >> 16
    fractional_ticks = (ts_int & 0xFFFF) / 65536.0
    time_seconds = (integer_ticks + fractional_ticks) * 1.25 / 1000.0
    cdma_epoch = datetime.datetime(1980, 1, 6, tzinfo=datetime.timezone.utc)
    return (cdma_epoch + datetime.timedelta(seconds=time_seconds)).timestamp()


def human_time(epoch_ts):
    """Formats UNIX epoch float into human-readable UTC timestamp string."""
    return datetime.datetime.fromtimestamp(epoch_ts, tz=datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )[:-3] + " UTC"


def read_payload_bytes(payload_file):
    """Extracts raw binary payload from whitespace-separated hex tokens in payload_file."""
    with open(payload_file, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    tokens = re.findall(r"[0-9A-Fa-f]{2}", text)
    if not tokens:
        return b""
    return bytes(int(t, 16) for t in tokens)


# -----------------------------------------------------------------------------
# B887 (NR5G MAC PDSCH Status) Parser
# -----------------------------------------------------------------------------
def parse_b887_records(raw):
    """
    Independently parses 0xB887 packets from raw bytes.
    Supports Major Version 2 (28-byte records) and Version 3 (32-byte records).
    Decodes full grant metadata including rv, num_layers, and scs.
    """
    records = []
    i = 0
    raw_len = len(raw)
    while i < raw_len - 3:
        if raw[i + 2] == 0x87 and raw[i + 3] == 0xB8:
            pkt_len = raw[i] | (raw[i + 1] << 8)
            if 32 <= pkt_len <= 4096 and i + pkt_len <= raw_len:
                pkt_data = raw[i : i + pkt_len]
                pkt_time = parse_qxdm_time(pkt_data[4:12])
                version_word = u32(pkt_data, 12)
                major_ver = version_word >> 16

                if major_ver == 2:
                    rec_len = 28
                    rec_start = 27
                elif major_ver == 3:
                    rec_len = 32
                    rec_start = 19
                else:
                    rec_len = 28
                    rec_start = 27

                if rec_start < len(pkt_data):
                    num_records = pkt_data[rec_start]
                    available = (len(pkt_data) - (rec_start + 1)) // rec_len
                    num_records = min(num_records, available)

                    for rec_idx in range(num_records):
                        base = rec_start + 1 + rec_idx * rec_len
                        rec = pkt_data[base : base + rec_len]
                        if len(rec) >= 10:
                            slot = rec[0]
                            mu = rec[1] & 0x0F
                            frame = u16(rec, 2) & 0x3FF
                            entry = rec[10:]
                            if len(entry) >= 14:
                                pci = u16(entry, 2) & 0x3FF
                                nr_arfcn = (u32(entry, 3) >> 2) & 0x3FFFFF
                                tb_size = (u32(entry, 6) >> 5) & 0x1FFFF
                                mcs = (u16(entry, 9) >> 2) & 0x1F
                                num_rbs = u16(entry, 10) & 0x1FF
                                rv = (entry[11] >> 1) & 0x3
                                harq_id = (entry[11] >> 3) & 0xF
                                k1 = (u16(entry, 12) >> 6) & 0xF
                                num_layers = ((entry[13] >> 5) & 0x7) + 1 if len(entry) > 13 else 1

                                records.append({
                                    "time": pkt_time,
                                    "slot": slot,
                                    "frame": frame,
                                    "scs": SCS_MAP.get(mu, f"mu{mu}"),
                                    "pci": pci,
                                    "nr_arfcn": nr_arfcn,
                                    "tb_size": tb_size,
                                    "mcs": mcs,
                                    "num_rbs": num_rbs,
                                    "rv": rv,
                                    "harq_id": harq_id,
                                    "k1": k1,
                                    "num_layers": num_layers,
                                })
                i += pkt_len
                continue
        i += 1
    return records


# -----------------------------------------------------------------------------
# B881 (NR5G MAC UL TB Stats) Parser
# -----------------------------------------------------------------------------
def parse_b881_records(raw):
    """
    Independently parses 0xB881 packets from raw bytes.
    Supports Major Version 2 (Minor 0 and 1) and Version 3.1.
    Extracts cumulative counters per component carrier (CA).
    """
    records = []
    i = 0
    payload_idx = 0
    raw_len = len(raw)
    while i < raw_len - 3:
        if raw[i + 2] == 0x81 and raw[i + 3] == 0xB8:
            pkt_len = raw[i] | (raw[i + 1] << 8)
            if 32 <= pkt_len <= 4096 and i + pkt_len <= raw_len:
                pkt_data = raw[i : i + pkt_len]
                pkt_time = parse_qxdm_time(pkt_data[4:12])
                minor_ver = u16(pkt_data, 12)
                major_ver = u16(pkt_data, 14)

                if major_ver == 3 and minor_ver == 1:
                    num_records = pkt_data[19] if pkt_data[19] > 0 else 1
                    rec_offset_start = 24
                    rec_len = 80
                elif major_ver == 2:
                    num_records = pkt_data[27] if len(pkt_data) >= 28 and pkt_data[27] > 0 else 1
                    rec_offset_start = 32
                    rec_len = 96 if minor_ver == 1 else 92
                else:
                    num_records = pkt_data[19] if pkt_data[19] > 0 else 1
                    rec_offset_start = 24
                    rec_len = 80

                O = rec_offset_start
                for rec_idx in range(num_records):
                    if O + rec_len > len(pkt_data):
                        break
                    carrier_id = rec_idx
                    new_tx = u64(pkt_data, O)
                    retx = u64(pkt_data, O + 8)
                    num_mcs = u64(pkt_data, O + 16)
                    num_prb = u64(pkt_data, O + 24)

                    if major_ver == 2 and minor_ver == 1:
                        num_new_tb = u32(pkt_data, O + 48)
                        num_retx_tb = u32(pkt_data, O + 52)
                    else:
                        num_new_tb = u32(pkt_data, O + 44)
                        num_retx_tb = u32(pkt_data, O + 48)

                    records.append({
                        "time": pkt_time,
                        "payload_idx": payload_idx,
                        "carrier_id": carrier_id,
                        "new_tx": new_tx,
                        "retx": retx,
                        "num_mcs": num_mcs,
                        "num_prb": num_prb,
                        "num_new_tb": num_new_tb,
                        "num_retx_tb": num_retx_tb,
                    })
                    O += rec_len

                payload_idx += 1
                i += pkt_len
                continue
        i += 1
    return records


# -----------------------------------------------------------------------------
# Dump CSV Functions
# -----------------------------------------------------------------------------
def dump_b887(raw_bytes, out_csv):
    """
    Decodes and writes B887 grants into out_csv sorted chronologically.
    Always writes a valid CSV (header-only if no records exist).
    """
    records = parse_b887_records(raw_bytes)
    records.sort(key=lambda r: (r["time"], r.get("frame", 0), r.get("slot", 0)))

    with open(out_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(B887_HEADER)
        for r in records:
            writer.writerow([
                f"{r['time']:.6f}",
                human_time(r["time"]),
                r["frame"],
                r["slot"],
                r["pci"],
                r["nr_arfcn"],
                r["tb_size"],
                r["mcs"],
                r["num_rbs"],
                r["harq_id"],
                r["k1"],
                r.get("rv", ""),
                r.get("num_layers", ""),
                r.get("scs", ""),
            ])

    if records:
        print(f"  [B887] Wrote {len(records)} rows -> {out_csv}")
    else:
        print(f"  [B887] No records found (header-only CSV written: {out_csv})")
    return len(records)


def dump_b881(raw_bytes, out_csv):
    """
    Decodes and writes B881 records into out_csv.
    Calculates cumulative fields, per-carrier deltas, average MCS, average PRB,
    retransmission rate, and true throughput (Mbps) independently per carrier.
    Always writes a valid CSV (header-only if no records exist).
    """
    raw_records = parse_b881_records(raw_bytes)
    raw_records.sort(key=lambda r: (r["time"], r["carrier_id"]))

    rows = []
    prev_by_carrier = {}

    for r in raw_records:
        cid = r["carrier_id"]
        if cid in prev_by_carrier:
            prev = prev_by_carrier[cid]
            dt = r["time"] - prev["time"]

            # Guard against capture gaps, concatenated logs, clock jumps, or counter wraps
            is_reset = (
                dt > 2.0
                or dt < 0
                or r.get("payload_idx", 0) < prev.get("payload_idx", 0)
                or r["new_tx"] < prev["new_tx"]
                or r["num_new_tb"] < prev["num_new_tb"]
            )

            if not is_reset:
                d_new_tx = max(0, r["new_tx"] - prev["new_tx"])
                d_retx = max(0, r["retx"] - prev["retx"])
                d_mcs = max(0, r["num_mcs"] - prev["num_mcs"])
                d_prb = max(0, r["num_prb"] - prev["num_prb"])
                d_new_tb = max(0, r["num_new_tb"] - prev["num_new_tb"])
                d_retx_tb = max(0, r["num_retx_tb"] - prev["num_retx_tb"])

                total_tb = d_new_tb + d_retx_tb
                avg_mcs = f"{(d_mcs / total_tb):.2f}" if total_tb > 0 else ""
                avg_prb = f"{(d_prb / total_tb):.2f}" if total_tb > 0 else ""
                retx_rate_pct = f"{(d_retx_tb / total_tb * 100.0):.2f}" if total_tb > 0 else ""
                throughput_mbps = (
                    f"{((d_new_tx * 8.0) / (dt * 1e6)):.4f}" if (dt > 0 and d_new_tx > 0) else "0.0000"
                )
                dt_str = f"{dt:.6f}"
            else:
                d_new_tx = d_retx = d_mcs = d_prb = d_new_tb = d_retx_tb = 0
                avg_mcs = avg_prb = retx_rate_pct = ""
                throughput_mbps = "0.0000"
                dt_str = ""
        else:
            # Baseline first record for this component carrier
            d_new_tx = d_retx = d_mcs = d_prb = d_new_tb = d_retx_tb = 0
            avg_mcs = avg_prb = retx_rate_pct = ""
            throughput_mbps = "0.0000"
            dt_str = ""

        rows.append([
            f"{r['time']:.6f}",
            human_time(r["time"]),
            r["new_tx"],
            r["retx"],
            r["num_mcs"],
            r["num_prb"],
            r["num_new_tb"],
            r["num_retx_tb"],
            d_new_tx,
            d_retx,
            d_mcs,
            d_prb,
            d_new_tb,
            d_retx_tb,
            avg_mcs,
            avg_prb,
            retx_rate_pct,
            dt_str,
            throughput_mbps,
        ])
        prev_by_carrier[cid] = r

    with open(out_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(B881_HEADER)
        writer.writerows(rows)

    if rows:
        print(f"  [B881] Wrote {len(rows)} rows -> {out_csv}")
    else:
        print(f"  [B881] No records found (header-only CSV written: {out_csv})")
    return len(rows)


# -----------------------------------------------------------------------------
# Main CLI Entry Point
# -----------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: python3 dump_readable_logs.py <combined_payload.txt> [output_prefix]")
        sys.exit(1 if len(sys.argv) < 2 else 0)

    payload_file = sys.argv[1]
    if not os.path.isfile(payload_file):
        print(f"ERROR: payload file not found: {payload_file}")
        sys.exit(1)

    out_prefix = sys.argv[2] if len(sys.argv) >= 3 else os.path.splitext(payload_file)[0]
    out_dir = os.path.dirname(out_prefix)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    print(f"Processing: {payload_file}")
    raw_bytes = read_payload_bytes(payload_file)
    if not raw_bytes:
        print(f"WARNING: No hex data extracted from {payload_file}")

    failed = False
    try:
        dump_b881(raw_bytes, f"{out_prefix}_b881.csv")
    except Exception:
        failed = True
        print("  [B881] ERROR while dumping B881 CSV:")
        traceback.print_exc()

    try:
        dump_b887(raw_bytes, f"{out_prefix}_b887.csv")
    except Exception:
        failed = True
        print("  [B887] ERROR while dumping B887 CSV:")
        traceback.print_exc()

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
