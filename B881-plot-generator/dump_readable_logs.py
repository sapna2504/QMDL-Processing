#!/usr/bin/env python3
"""
dump_readable_logs.py

Reads a combined-payloads.txt (produced by the Makefile's plot_all_qmdl target)
and writes two human-readable CSV files:

  <output_prefix>_b881.csv   - one row per B881 record, with cumulative fields
                                AND per-record deltas (new_tx_bytes, retx_bytes,
                                num_mcs, num_prb, num_new_tb, num_retx_tb,
                                avg_mcs, retx_rate_pct, throughput_mbps)

  <output_prefix>_b887.csv   - one row per B887 grant, with human-readable time,
                                pci, nr_arfcn, tb_size, mcs, num_rbs, harq_id, k1,
                                plus rv, num_layers, carrier_id, scs when available

Usage:
    python3 dump_readable_logs.py <combined_payload.txt> [output_prefix]

If output_prefix is omitted, it defaults to the payload filename without extension.

Decoding logic is imported from the existing scripts in this folder so it stays
in one place. For B887 two APIs are supported:
  - extract_b887_data(path) -> list of dicts   (older b887_box_plotter.py)
  - parse_stream(text)      -> list of PdschRecord objects (B887 multi-version parser)
The first B887 candidate file that provides either function is used.
"""

import sys
import os
import csv
import datetime
import importlib.util
import traceback

# B887 decoder candidates, tried in this order
B887_CANDIDATES = ["b887_box_plotter.py", "b887_parser.py"]

B887_HEADER = [
    "timestamp_epoch", "timestamp_utc", "frame", "slot", "pci",
    "nr_arfcn", "tb_size_bytes", "mcs", "num_rbs", "harq_id", "k1",
    "rv", "num_layers", "carrier_id", "scs",
]


def load_module(module_path, module_name):
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def human_time(epoch_ts):
    return datetime.datetime.fromtimestamp(epoch_ts, tz=datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )[:-3] + " UTC"


def find_b887_module(script_dir):
    """Return (module, path) for the first candidate exposing a usable B887 API."""
    tried = []
    for name in B887_CANDIDATES:
        path = os.path.join(script_dir, name)
        if not os.path.isfile(path):
            continue
        mod = load_module(path, os.path.splitext(name)[0])
        if hasattr(mod, "extract_b887_data") or hasattr(mod, "parse_stream"):
            return mod, path
        tried.append(name)
    msg = "No B887 decoder with extract_b887_data() or parse_stream() found"
    if tried:
        msg += f" (checked: {', '.join(tried)})"
    raise RuntimeError(msg + f" in {script_dir}")


def get_b887_records(b887_mod, payload_file):
    """Return B887 records as dicts, whichever API the module provides."""
    if hasattr(b887_mod, "extract_b887_data"):
        return b887_mod.extract_b887_data(payload_file)

    with open(payload_file, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    recs = b887_mod.parse_stream(text, verbose=False)
    return [
        {
            "time": r.timestamp.timestamp(),
            "frame": r.frame,
            "slot": r.slot,
            "pci": r.pci,
            "nr_arfcn": r.nr_arfcn,
            "tb_size": r.tb_size,
            "mcs": r.mcs,
            "num_rbs": r.num_rbs,
            "harq_id": r.harq_id,
            "k1": r.k1,
            "rv": r.rv,
            "num_layers": r.num_layers,
            "carrier_id": r.carrier_id,
            "scs": r.scs,
        }
        for r in recs
    ]


def dump_b887(b887_mod, payload_file, out_csv):
    records = get_b887_records(b887_mod, payload_file)
    records.sort(key=lambda r: r["time"])

    # Always write the file (header-only if empty) so a missing CSV means a real error
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
                r.get("carrier_id", ""),
                r.get("scs", ""),
            ])

    if records:
        print(f"  [B887] Wrote {len(records)} rows -> {out_csv}")
    else:
        print(f"  [B887] No records found in {payload_file} (header-only CSV written: {out_csv})")
    return len(records)


def dump_b881(b881_mod, payload_file, out_csv):
    raw_records = b881_mod.extract_b881_data(payload_file)
    if not raw_records:
        print(f"  [B881] No records found in {payload_file}")
        return 0

    raw_records.sort(key=lambda r: r["time"])

    rows = []
    prev = raw_records[0]
    for r in raw_records:
        d_new_tx = r["new_tx"] - prev["new_tx"]
        d_retx = r["retx"] - prev["retx"]
        d_mcs = r["num_mcs"] - prev["num_mcs"]
        d_prb = r["num_prb"] - prev["num_prb"]
        d_new_tb = r["num_new_tb"] - prev["num_new_tb"]
        d_retx_tb = r["num_retx_tb"] - prev["num_retx_tb"]

        # Same anomaly/reset guard as the plotter
        if min(d_new_tx, d_retx, d_mcs, d_prb, d_new_tb, d_retx_tb) < 0:
            d_new_tx = d_retx = d_mcs = d_prb = d_new_tb = d_retx_tb = 0

        total_tb = d_new_tb + d_retx_tb
        avg_mcs = (d_mcs / total_tb) if total_tb > 0 else ""
        avg_prb = (d_prb / total_tb) if total_tb > 0 else ""
        retx_rate_pct = (d_retx_tb / total_tb * 100.0) if total_tb > 0 else ""
        throughput_mbps = (d_new_tx * 8.0) / 1e6  # per-record interval, not normalized to 1s

        rows.append([
            f"{r['time']:.6f}",
            human_time(r["time"]),
            r["new_tx"], r["retx"], r["num_mcs"], r["num_prb"],
            r["num_new_tb"], r["num_retx_tb"],
            d_new_tx, d_retx, d_mcs, d_prb, d_new_tb, d_retx_tb,
            avg_mcs, avg_prb,  retx_rate_pct, throughput_mbps,
        ])
        prev = r

    with open(out_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp_epoch", "timestamp_utc",
            "cum_new_tx_bytes", "cum_retx_bytes", "cum_num_mcs", "cum_num_prb",
            "cum_num_new_tb", "cum_num_retx_tb",
            "delta_new_tx_bytes", "delta_retx_bytes", "delta_num_mcs", "delta_num_prb",
            "delta_num_new_tb", "delta_num_retx_tb",
            "avg_mcs_this_interval", "avg_prb_this_interval", "retx_rate_pct_this_interval", "throughput_mbps_interval",
        ])
        writer.writerows(rows)

    print(f"  [B881] Wrote {len(rows)} rows -> {out_csv}")
    return len(rows)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 dump_readable_logs.py <combined_payload.txt> [output_prefix]")
        sys.exit(1)

    payload_file = sys.argv[1]
    if not os.path.isfile(payload_file):
        print(f"ERROR: payload file not found: {payload_file}")
        sys.exit(1)

    out_prefix = sys.argv[2] if len(sys.argv) >= 3 else os.path.splitext(payload_file)[0]

    out_dir = os.path.dirname(out_prefix)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"Processing: {payload_file}")
    failed = False

    # B881 and B887 run independently: one failing never blocks the other
    try:
        b881_mod = load_module(os.path.join(script_dir, "b881_box_plotter.py"), "b881_box_plotter")
        dump_b881(b881_mod, payload_file, f"{out_prefix}_b881.csv")
    except Exception:
        failed = True
        print("  [B881] ERROR while dumping B881 CSV:")
        traceback.print_exc()

    try:
        b887_mod, b887_path = find_b887_module(script_dir)
        print(f"  [B887] Using decoder: {os.path.basename(b887_path)}")
        dump_b887(b887_mod, payload_file, f"{out_prefix}_b887.csv")
    except Exception:
        failed = True
        print("  [B887] ERROR while dumping B887 CSV:")
        traceback.print_exc()

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
