#!/usr/bin/env python3
import sys
import os
import glob
import datetime
import warnings
import matplotlib
# Suppress Matplotlib deprecation warning for 'labels' parameter in boxplot
warnings.filterwarnings("ignore", category=matplotlib.MatplotlibDeprecationWarning)
import numpy as np
import matplotlib.pyplot as plt

script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

try:
    from parser import parse_stream, UlTbStatsRecord
except ImportError:
    from .parser import parse_stream, UlTbStatsRecord

def u16(b, o): return b[o] | (b[o+1] << 8)
def u32(b, o): return int.from_bytes(b[o:o+4], byteorder='little')
def u64(b, o): return int.from_bytes(b[o:o+8], byteorder='little')

def parse_qxdm_time(ts_bytes):
    """
    Converts the 8-byte QXDM hardware timestamp into a standard UNIX epoch float.
    """
    ts_int = int.from_bytes(ts_bytes, byteorder='little')
    integer_ticks = ts_int >> 16
    fractional_ticks = (ts_int & 0xFFFF) / 65536.0
    time_seconds = (integer_ticks + fractional_ticks) * 1.25 / 1000.0
    
    cdma_epoch = datetime.datetime(1980, 1, 6, tzinfo=datetime.timezone.utc)
    return (cdma_epoch + datetime.timedelta(seconds=time_seconds)).timestamp()

def extract_b881_data(payload_file):
    """
    Parses B881 packets from the payloads file and returns structured records
    using multi-carrier and multi-version decoding.
    """
    if not os.path.isfile(payload_file) or os.path.getsize(payload_file) == 0:
        return []
    with open(payload_file, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()
    recs = parse_stream(text, verbose=False)
    records = []
    for r in recs:
        records.append({
            'time': r.timestamp.timestamp(),
            'new_tx': r.new_tx_bytes,
            'retx': r.retx_bytes,
            'num_mcs': r.num_mcs,
            'num_prb': r.num_prb,
            'num_new_tb': r.num_new_tx_tb,
            'num_retx_tb': r.num_retx_tb,
            'delta_tx_bytes': r.delta_tx_bytes,
            'delta_retx_bytes': r.delta_retx_bytes,
            'delta_slots': r.delta_slots,
            'delta_prb': r.delta_prb,
            'delta_mcs': r.delta_mcs,
            'prb_per_slot': r.prb_per_slot,
            'avg_mcs': r.avg_mcs,
            'carrier_id': r.carrier_id,
        })
    return records

def process_payload_file(payload_file, bin_size_sec=1.0, mode="slot"):
    """
    Processes a single payload file using multi-carrier and per-slot normalized
    telemetry. Computes:
      - Uplink Throughput (Mbps) via time-bin aggregation
      - Modulation & Coding Scheme (MCS)
      - Physical Resource Blocks (PRBs/slot)
    
    Modes:
      - 'slot' (default): True normalized per-slot allocations across scheduled transmission slots
      - 'bin': 1.0-second time-binned average allocations
    """
    if not os.path.isfile(payload_file) or os.path.getsize(payload_file) == 0:
        return None

    try:
        with open(payload_file, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()
    except Exception:
        return None

    records = parse_stream(text, verbose=False)
    if not records:
        return None

    # Filter to active scheduled transmission records (TBs/slots > 0 and transmitted bytes > 0)
    active_recs = [r for r in records if r.delta_slots > 0 and r.delta_tx_bytes > 0 and r.prb_per_slot is not None]
    if not active_recs:
        return None

    b881_times = np.array([r.timestamp.timestamp() for r in records])
    min_time = min(b881_times)
    max_time = max(b881_times)

    if max_time <= min_time:
        return None

    # Time-window binning for Throughput (and 'bin' mode)
    bins = np.arange(min_time, max_time + bin_size_sec, bin_size_sec)
    if len(bins) < 2:
        return None

    new_tx_bytes_binned, _ = np.histogram(b881_times, bins=bins, weights=[r.delta_tx_bytes for r in records])
    slots_binned, _ = np.histogram(b881_times, bins=bins, weights=[r.delta_slots for r in records])
    prb_sum_binned, _ = np.histogram(b881_times, bins=bins, weights=[r.delta_prb for r in records])
    mcs_sum_binned, _ = np.histogram(b881_times, bins=bins, weights=[r.delta_mcs for r in records])

    active_mask = (slots_binned > 0) & (new_tx_bytes_binned > 0)
    if not np.any(active_mask):
        return None

    throughput_active = (new_tx_bytes_binned[active_mask] * 8.0) / (1e6 * bin_size_sec)

    if mode == "slot":
        # Slot-weighted per-slot normalized allocations:
        # Each telemetry record covers r.delta_slots scheduled slots with r.prb_per_slot PRBs.
        slot_counts = [r.delta_slots for r in active_recs]
        prb_per_slot_vals = [r.prb_per_slot for r in active_recs]
        prb_active = np.repeat(prb_per_slot_vals, slot_counts)

        mcs_recs = [r for r in active_recs if r.avg_mcs is not None]
        if mcs_recs:
            mcs_active = np.repeat([r.avg_mcs for r in mcs_recs], [r.delta_slots for r in mcs_recs])
        else:
            mcs_active = mcs_sum_binned[active_mask] / slots_binned[active_mask]
    else:
        # Time-binned average allocations across 1-second active windows
        prb_active = prb_sum_binned[active_mask] / slots_binned[active_mask]
        mcs_active = mcs_sum_binned[active_mask] / slots_binned[active_mask]

    total_slots = sum(r.delta_slots for r in active_recs)

    return {
        'throughput': throughput_active,
        'mcs': mcs_active,
        'prb': prb_active,
        'total_slots': total_slots,
        'active_bins': len(throughput_active)
    }


def clean_filename(path):
    """
    Extracts a simplified clean name for plot labeling.
    Recognizes common logging patterns (Runs, Captures, Operators, Locations, Scenarios).
    """
    norm = os.path.normpath(path)
    parts = norm.split(os.sep)
    base = os.path.basename(path)
    import re
    
    # 1. Check for run_XXX pattern (e.g. run_000 -> R0)
    run_match = re.search(r'run_(\d+)', norm, re.IGNORECASE)
    if run_match:
        return f"R{int(run_match.group(1))}"
        
    # 2. Check for capture_XXX pattern (e.g. capture_000 -> C0)
    cap_match = re.search(r'capture_(\d+)', norm, re.IGNORECASE)
    cap_str = f"C{int(cap_match.group(1))}" if cap_match else ""
    
    # 3. Check for Operator / Network / Device in path
    operators = ['Airtel', 'Jio', 'Vodafone', 'Vi', 'Wifi', 'ACN_Lab', 'Vaishali', 'Ashish', 'Tarun', 'Lajja']
    found_op = None
    for p in parts:
        for op in operators:
            if op.lower() in p.lower():
                found_op = op
                break
        if found_op:
            break
            
    # 4. Check for location / activity
    activities = ['VideoStreaming', 'WebBrowsing', 'NoActivity', 'SpeedTest', 'ExperimentalSpeedtest', 'Amul_IITDelhi', 'Amul', 'Voda']
    found_act = None
    for p in parts:
        for act in activities:
            if act.lower() in p.lower():
                found_act = act.replace('VideoStreaming', 'Video').replace('WebBrowsing', 'Web').replace('NoActivity', 'Idle').replace('Amul_IITDelhi', 'Amul')
                break
        if found_act:
            break

    # Build clean label
    if found_op:
        label = found_op
        if found_act and found_act.lower() not in found_op.lower():
            label += f"-{found_act}"
        if cap_str:
            label += f"-{cap_str}"
        return label
    elif cap_str:
        return f"{parts[-2] if len(parts) > 1 else cap_str}"

    # 5. Check for moving / lab / ground patterns
    if "moving" in base.lower():
        m = re.search(r'(\d+)', base)
        return f"M{m.group(1)}" if m else "Moving"
    if "ground" in base.lower():
        m = re.search(r'(\d+)', base)
        return f"G{m.group(1)}" if m else "Ground"
    if "lab" in base.lower():
        m = re.search(r'(\d+)', base)
        return f"L{m.group(1)}" if m else "Lab"
    if "voda" in base.lower():
        m = re.search(r'(\d+)', base)
        return f"Voda{m.group(1)}" if m else "Voda"
        
    clean = os.path.splitext(base)[0].replace("payloads_", "").replace("_payloads", "").replace("payloads", "")
    return clean if clean else base


def style_boxplot(ax, data, labels, title, ylabel, color, rotation=0):
    """
    Applies custom styling to make the boxplots look beautiful.
    """
    try:
        bp = ax.boxplot(data, tick_labels=labels, patch_artist=True, 
                        showmeans=True, meanline=True,
                        medianprops={'color': 'black', 'linewidth': 1.5},
                        meanprops={'color': 'darkgreen', 'linestyle': '--', 'linewidth': 1.5},
                        flierprops={'marker': 'o', 'markerfacecolor': 'grey', 'markeredgecolor': 'none', 'markersize': 4, 'alpha': 0.5})
    except TypeError:
        bp = ax.boxplot(data, labels=labels, patch_artist=True, 
                        showmeans=True, meanline=True,
                        medianprops={'color': 'black', 'linewidth': 1.5},
                        meanprops={'color': 'darkgreen', 'linestyle': '--', 'linewidth': 1.5},
                        flierprops={'marker': 'o', 'markerfacecolor': 'grey', 'markeredgecolor': 'none', 'markersize': 4, 'alpha': 0.5})
    
    for patch in bp['boxes']:
        patch.set_facecolor(color)
        patch.set_alpha(0.6)
        patch.set_edgecolor('black')
        
    ax.set_title(title, fontsize=12, fontweight='bold', pad=10)
    ax.set_ylabel(ylabel, fontsize=10)
    ax.grid(True, linestyle=':', alpha=0.6)
    ax.set_xticklabels(labels, rotation=rotation, ha='center' if rotation == 0 else 'right')


def main():
    args = sys.argv[1:]
    
    mode = "slot"
    if "--mode" in args:
        m_idx = args.index("--mode")
        if m_idx + 1 < len(args):
            mode = args[m_idx + 1].lower()
            args = args[:m_idx] + args[m_idx + 2:]
    elif any(a.startswith("--mode=") for a in args):
        for i, a in enumerate(args):
            if a.startswith("--mode="):
                mode = a.split("=", 1)[1].lower()
                args = args[:i] + args[i+1:]
                break

    bin_size = 1.0
    if "--bin-size" in args:
        b_idx = args.index("--bin-size")
        if b_idx + 1 < len(args):
            bin_size = float(args[b_idx + 1])
            args = args[:b_idx] + args[b_idx + 2:]
    elif any(a.startswith("--bin-size=") for a in args):
        for i, a in enumerate(args):
            if a.startswith("--bin-size="):
                bin_size = float(a.split("=", 1)[1])
                args = args[:i] + args[i+1:]
                break

    # Check if the last argument is an output plot filename (usually ends with .png, .jpg, .pdf)
    plot_filename = "b881_box_plots.png"
    if args and (args[-1].endswith('.png') or args[-1].endswith('.jpg') or args[-1].endswith('.pdf')):
        plot_filename = args[-1]
        args = args[:-1]
        
    # If no files are specified, search in standard payload directories
    if not args:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        search_patterns = [
            os.path.join(script_dir, "payloads", "payloads_run_*.txt"),
            os.path.join(script_dir, "payloads", "payloads_lab-*.txt"),
            os.path.join(script_dir, "..", "loggers", "data", "**", "payloads_b881.txt"),
        ]
        files = []
        for p in search_patterns:
            matches = sorted(glob.glob(p, recursive=True))
            if matches:
                files.extend(matches)
        files = sorted(list(set([f for f in files if "parsed" not in f and "record" not in f and "qmdl" not in f])))
        if not files:
            print("Error: No run payloads found")
            print("Usage: python b881_box_plotter.py <payload1.txt> <payload2.txt> ... [output_plot.png]")
            sys.exit(1)
    else:
        # Resolve any globs
        files = []
        for a in args:
            matches = glob.glob(a, recursive=True)
            if matches:
                files.extend(matches)
            else:
                files.append(a)
        files = sorted(list(set(files)))

    print(f"Found {len(files)} payload file(s) to process (Mode: {mode}):")
    for f in files:
        print(f" - {f}")

    all_tput = []
    all_mcs = []
    all_prb = []
    labels = []
    run_metrics = []

    for f in files:
        base = os.path.basename(f)
        clean_name = clean_filename(f)
            
        print(f"Processing {clean_name} ({base})...")
        metrics = process_payload_file(f, bin_size_sec=bin_size, mode=mode)
        if metrics is not None:
            all_tput.append(metrics['throughput'])
            all_mcs.append(metrics['mcs'])
            all_prb.append(metrics['prb'])
            labels.append(clean_name)
            run_metrics.append(metrics)
        else:
            print(f"  Warning: No active transmission data found in {f}. Skipping.")

    if not labels:
        print("Error: No data could be processed from the files.")
        sys.exit(1)

    # Print summary statistics table
    print("\n" + "=" * 98)
    prb_col = "PRBs/Slot (Mean)" if mode == "slot" else "PRB/Slot (1s Mean)"
    print(f"{'Run / File':<22} | {'Slots (N)':>10} | {'Throughput (Mean±Std)':>24} | {'MCS (Mean)':>10} | {prb_col:>18}")
    print("=" * 98)
    for label, m in zip(labels, run_metrics):
        tp_mean = np.mean(m['throughput'])
        tp_std = np.std(m['throughput'])
        mcs_mean = np.mean(m['mcs'])
        prb_mean = np.mean(m['prb'])
        slots_count = m['total_slots']
        print(f"{label:<22} | {slots_count:>10,d} | {tp_mean:>9.2f} ± {tp_std:<7.2f} Mbps | {mcs_mean:>10.2f} | {prb_mean:>18.2f}")
    print("=" * 98 + "\n")

    max_label_len = max(len(l) for l in labels) if labels else 0
    rotation = 45 if len(labels) > 6 or max_label_len > 6 else 0

    # Make the figure with 3 subplots side by side in sequence: Throughput, MCS, PRB
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(18, 6))

    # 1. Uplink Throughput (blue/teal-ish color)
    style_boxplot(ax1, all_tput, labels, "Uplink Throughput", "Throughput (Mbps)", "#0288d1", rotation=rotation)

    # 2. Modulation & Coding Scheme (MCS) (indigo/purple-ish color)
    style_boxplot(ax2, all_mcs, labels, "Modulation & Coding Scheme", "Average MCS Index", "#6f42c1", rotation=rotation)
    
    # 3. Physical Resource Blocks (PRB) (coral/red-ish color)
    prb_ylabel = "Allocated PRBs (PRB / Slot)" if mode == "slot" else "Average PRBs / Slot (1s Bin)"
    prb_title = "Resource Block Allocation (Per-Slot)" if mode == "slot" else "Resource Block Allocation (1s Binned)"
    style_boxplot(ax3, all_prb, labels, prb_title, prb_ylabel, "#d9534f", rotation=rotation)

    plt.suptitle(f"Uplink Performance Metrics Distribution Across Runs [{mode.capitalize()} Mode]", fontsize=15, fontweight='bold', y=0.98)
    plt.tight_layout()
    
    # Make sure output directory exists if specified
    output_dir = os.path.dirname(plot_filename)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        
    plt.savefig(plot_filename, dpi=150)
    print(f"📈 Success! Box plots saved as '{plot_filename}'\n")

if __name__ == "__main__":
    main()
