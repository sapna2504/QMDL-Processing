#!/usr/bin/env python3
import os
import sys
import datetime
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter
from scapy.all import PcapReader, IP, IPv6

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
            'new_tx_bytes': r.delta_tx_bytes,
            'retx_bytes': r.delta_retx_bytes,
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

def guess_device_ip(pcap_file):
    """
    Scans the PCAP to find the most common IP address, assuming it belongs to the capturing device.
    """
    ips = []
    with PcapReader(pcap_file) as pcap_reader:
        for pkt in pcap_reader:
            if IP in pkt:
                ips.extend([pkt[IP].src, pkt[IP].dst])
            elif IPv6 in pkt:
                ips.extend([pkt[IPv6].src, pkt[IPv6].dst])
                
    if not ips:
        return None
    return Counter(ips).most_common(1)[0][0]

def extract_pcap_split(pcap_file, device_ip):
    """
    Extracts uplink packets matching the device's source IP.
    """
    ul_records = []
    with PcapReader(pcap_file) as pcap_reader:
        for pkt in pcap_reader:
            src = None
            if IP in pkt:
                src = pkt[IP].src
            elif IPv6 in pkt:
                src = pkt[IPv6].src
            else:
                continue 

            if src == device_ip:
                ul_records.append((float(pkt.time), len(pkt)))

    return np.array(ul_records)

def normalize(arr):
    """Safely normalizes data between 0 and 1."""
    if len(arr) == 0 or np.ptp(arr) == 0:
        return np.zeros_like(arr)
    return (arr - np.min(arr)) / np.ptp(arr)

def main():
    if len(sys.argv) < 3:
        print("Usage: python b881_plotter.py <payloads.txt> <capture.pcap> [output_plot.png]")
        sys.exit(1)

    payload_file = sys.argv[1]
    pcap_file = sys.argv[2]
    plot_filename = sys.argv[3] if len(sys.argv) > 3 else "b881_correlation_analysis.png"

    # Determine Device IP
    print("Analyzing PCAP to determine device IP...")
    device_ip = guess_device_ip(pcap_file)
    if not device_ip:
        print("Error: Could not find any valid IP traffic in the PCAP.")
        return
    print(f"Device IP: {device_ip}")

    # Extract B881 records
    print("Extracting B881 records...")
    b881_deltas = extract_b881_data(payload_file)
    if not b881_deltas:
        print("Error: No B881 records parsed.")
        return
    print(f"Parsed {len(b881_deltas)} B881 records.")

    # Sort records chronologically
    b881_deltas.sort(key=lambda x: x['time'])

    # Extract PCAP Uplink data
    print("Extracting PCAP uplink packets...")
    ul_data = extract_pcap_split(pcap_file, device_ip)
    if len(ul_data) == 0:
        print("Error: No PCAP uplink traffic found for device IP.")
        return
    print(f"Extracted {len(ul_data)} uplink packets.")

    # Determine overlapping time range
    all_times = [d['time'] for d in b881_deltas] + list(ul_data[:, 0])
    min_time = min(all_times)
    max_time = max(all_times)

    b881_times = np.array([d['time'] for d in b881_deltas])
    b881_vals = np.array([d['new_tx_bytes'] for d in b881_deltas])

    # Find optimal lag to align PCAP with B881 logs (check +/- 5 seconds with 0.1s resolution)
    print("Finding optimal time alignment lag...")
    lag_bin_size = 0.1
    lag_bins = np.arange(min_time, max_time + lag_bin_size, lag_bin_size)
    ul_lag_binned, _ = np.histogram(ul_data[:, 0], bins=lag_bins, weights=ul_data[:, 1])
    b881_lag_binned, _ = np.histogram(b881_times, bins=lag_bins, weights=b881_vals)

    best_corr = -1.0
    best_lag_seconds = 0.0
    max_lag_bins = int(5.0 / lag_bin_size)

    for lag in range(-max_lag_bins, max_lag_bins + 1):
        if lag < 0:
            c_ul = ul_lag_binned[-lag:]
            c_b881 = b881_lag_binned[:lag]
        elif lag > 0:
            c_ul = ul_lag_binned[:-lag]
            c_b881 = b881_lag_binned[lag:]
        else:
            c_ul = ul_lag_binned
            c_b881 = b881_lag_binned

        if np.std(c_ul) != 0 and np.std(c_b881) != 0:
            corr = np.corrcoef(c_ul, c_b881)[0, 1]
            if corr > best_corr:
                best_corr = corr
                best_lag_seconds = lag * lag_bin_size

    print(f"Optimal time alignment lag: PCAP packets occur {best_lag_seconds:.1f}s after baseband logs (max cross-corr: {best_corr:.4f})")
    
    # Align PCAP timestamps to baseband clock
    ul_data_aligned = ul_data.copy()
    ul_data_aligned[:, 0] += best_lag_seconds

    # Recalculate overlapping time range after alignment
    all_times = list(b881_times) + list(ul_data_aligned[:, 0])
    min_time = min(all_times)
    max_time = max(all_times)

    # Binning
    BIN_SIZE_SEC = 1.0
    print(f"Binning aligned data into {BIN_SIZE_SEC}s bins...")
    bins = np.arange(min_time, max_time + BIN_SIZE_SEC, BIN_SIZE_SEC)
    time_axis = bins[:-1] - min_time

    # Bin PCAP Upload traffic (Bytes/sec) using shifted timestamps
    ul_binned, _ = np.histogram(ul_data_aligned[:, 0], bins=bins, weights=ul_data_aligned[:, 1])

    # Bin B881 Metrics
    new_tx_binned, _ = np.histogram(b881_times, bins=bins, weights=[d['new_tx_bytes'] for d in b881_deltas])
    retx_binned, _ = np.histogram(b881_times, bins=bins, weights=[d['retx_bytes'] for d in b881_deltas])
    slots_binned, _ = np.histogram(b881_times, bins=bins, weights=[d['delta_slots'] for d in b881_deltas])
    prb_sum_binned, _ = np.histogram(b881_times, bins=bins, weights=[d['delta_prb'] for d in b881_deltas])
    mcs_sum_binned, _ = np.histogram(b881_times, bins=bins, weights=[d['delta_mcs'] for d in b881_deltas])
    
    # Calculate PRBs per slot for active bins (normalized allocation)
    valid_slots = slots_binned > 0
    prb_per_slot_binned = np.zeros_like(slots_binned, dtype=float)
    prb_per_slot_binned[valid_slots] = prb_sum_binned[valid_slots] / slots_binned[valid_slots]

    # Calculate Average MCS per bin: sum(mcs) / total_slots for active uplink throughput bins
    valid_tb_mask = (slots_binned > 0) & (new_tx_binned > 0)
    mcs_binned = np.full(len(mcs_sum_binned), np.nan, dtype=float)
    mcs_binned[valid_tb_mask] = mcs_sum_binned[valid_tb_mask] / slots_binned[valid_tb_mask]

    # Calculate Correlations
    corr_new_tx = 0.0
    corr_retx = 0.0
    corr_prb = 0.0

    if np.std(ul_binned) != 0:
        if np.std(new_tx_binned) != 0:
            corr_new_tx = np.corrcoef(ul_binned, new_tx_binned)[0, 1]
        if np.std(retx_binned) != 0:
            corr_retx = np.corrcoef(ul_binned, retx_binned)[0, 1]
        if np.std(prb_per_slot_binned) != 0:
            corr_prb = np.corrcoef(ul_binned, prb_per_slot_binned)[0, 1]

    # Print results to console
    print("\n" + "="*50)
    print("📊 B881 Uplink Metrics Correlation with PCAP Upload")
    print("="*50)
    print(f"New Tx Bytes (Goodput) Correlation:  {corr_new_tx: .4f}")
    print(f"ReTx Bytes (Badput) Correlation:    {corr_retx: .4f}")
    print(f"PRBs Allocated (PRB/Slot) Correlation: {corr_prb: .4f}")
    print("="*50 + "\n")

    # Normalize metrics for visual comparisons
    ul_norm = normalize(ul_binned)
    new_tx_norm = normalize(new_tx_binned)
    retx_norm = normalize(retx_binned)
    prb_norm = normalize(prb_per_slot_binned)

    # Plotting
    fig, axes = plt.subplots(3, 1, figsize=(14, 9), sharex=True)
    
    # 1. New Tx Bytes
    axes[0].plot(time_axis, ul_norm, label='PCAP Upload (Normalized)', color='tab:orange', alpha=0.8)
    axes[0].plot(time_axis, new_tx_norm, label='B881 New Tx Bytes (Normalized)', color='tab:blue', linestyle='--', alpha=0.8)
    axes[0].set_title(f"B881 New Tx Bytes (Goodput) vs PCAP Upload (Corr: {corr_new_tx:.3f})")
    axes[0].set_ylabel("Norm Magnitude")
    axes[0].legend()
    axes[0].grid(True, alpha=0.3)

    # 2. ReTx Bytes
    axes[1].plot(time_axis, ul_norm, label='PCAP Upload (Normalized)', color='tab:orange', alpha=0.8)
    axes[1].plot(time_axis, retx_norm, label='B881 ReTx Bytes (Normalized)', color='tab:red', linestyle='--', alpha=0.8)
    axes[1].set_title(f"B881 ReTx Bytes (Badput) vs PCAP Upload (Corr: {corr_retx:.3f})")
    axes[1].set_ylabel("Norm Magnitude")
    axes[1].legend()
    axes[1].grid(True, alpha=0.3)

    # 3. PRBs Allocated (PRB/Slot)
    axes[2].plot(time_axis, ul_norm, label='PCAP Upload (Normalized)', color='tab:orange', alpha=0.8)
    axes[2].plot(time_axis, prb_norm, label='B881 PRBs/Slot (Normalized)', color='tab:green', linestyle='--', alpha=0.8)
    axes[2].set_title(f"B881 PRB Allocation (PRB/Slot) vs PCAP Upload (Corr: {corr_prb:.3f})")
    axes[2].set_xlabel(f"Time (Seconds from start) [{BIN_SIZE_SEC}s bins]")
    axes[2].set_ylabel("Norm Magnitude")
    axes[2].legend()
    axes[2].grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(plot_filename)
    print(f"📈 Correlation plot saved as '{plot_filename}'")

if __name__ == "__main__":
    main()
