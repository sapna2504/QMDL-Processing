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

  <output_prefix>_b139.csv   - one row per B139 LTE PUSCH Tx record, with timing,
                                serving_cell_id, tb_size, num_rb, modulation, coding_rate,
                                tx_power_dbm, retx_index, rv, and UCI fields

  <output_prefix>_b173.csv   - one row per B173 LTE PDSCH Stat transport block, with
                                frame, subframe, num_layers, tb_size, mcs, modulation,
                                tb_rbs, harq_id, rv, ndi, crc_status, and rnti_type

Usage:
    python3 dump_readable_logs.py <combined_payload.txt> [output_prefix]

If output_prefix is omitted, it defaults to the payload filename without extension.

This script independently decodes and calculates all metrics:
  - Standalone multi-version B881, B887, B139, and B173 decoding (standard library only; no external dependencies).
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

B139_HEADER = [
    "timestamp_epoch", "timestamp_utc", "serving_cell_id",
    "dispatch_sfn", "dispatch_subfn", "current_sfn", "current_subfn",
    "retx_index", "is_retx", "rv", "tb_size_bytes", "tb_size_bits",
    "num_rb", "start_rb_slot0", "start_rb_slot1", "resource_alloc_type",
    "coding_rate", "mod_order", "modulation", "tx_power_dbm", "digital_gain_db",
    "ack_present", "cqi_present", "ri_present", "freq_hopping", "mirror_hopping",
    "ue_srs", "srs_occasion", "num_ack_bits", "rate_matched_ack_bits", "ack_payload",
    "num_ri_bits", "rate_matched_ri_bits", "ri_payload",
    "num_cqi_bits", "rate_matched_cqi_bits", "num_dl_carriers", "drop_pusch",
    "cyclic_shift_dmrs_slot0", "cyclic_shift_dmrs_slot1",
    "start_rb_cluster1", "num_rb_cluster1",
]

B173_HEADER = [
    "timestamp_epoch", "timestamp_utc", "frame", "subframe",
    "num_rbs_subframe", "num_layers", "num_tbs_present", "hsic_enabled",
    "tb_idx", "harq_id", "rv", "ndi", "crc_pass", "crc_status",
    "rnti_type_id", "rnti_type", "tb_size_bytes", "tb_size_bits",
    "mcs", "modulation", "tb_rbs", "did_recombining", "pmch_id", "area_id",
]

SCS_MAP = {0: "15kHz", 1: "30kHz", 2: "60kHz", 3: "120kHz"}

B139_MODULATION_MAP = {
    0: "BPSK",
    1: "QPSK",
    2: "16-QAM",
    3: "64-QAM",
    4: "256-QAM",
}

B173_RNTI_TYPE_MAP = {
    0: "C-RNTI",
    1: "RA-RNTI",
    2: "P-RNTI",
    3: "SI-RNTI",
    4: "SPS / Temp C-RNTI",
    5: "M-RNTI",
}

B173_MODULATION_MAP = {
    2: "QPSK",
    4: "16QAM",
    6: "64QAM",
    8: "256QAM",
    0: "QPSK",
    1: "16QAM",
    3: "256QAM",
}


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
# B139 (LTE PHY PUSCH Tx Report) Parser
# -----------------------------------------------------------------------------
def parse_b139_records(raw):
    """
    Independently parses 0xB139 (LTE PHY PUSCH Tx Report) packets from raw bytes.
    Supports versions v162/v145/v144 (100B), v124 (84B), v122 (68B), v102 (72B),
    v43 (64B), v26 (52B), v24/v23 (48B).
    """
    records = []
    i = 0
    raw_len = len(raw)
    while i < raw_len - 3:
        if raw[i + 2] == 0x39 and raw[i + 3] == 0xB1:
            pkt_len = raw[i] | (raw[i + 1] << 8)
            if 20 <= pkt_len <= 4096 and i + pkt_len <= raw_len:
                pkt_data = raw[i : i + pkt_len]
                pkt_time = parse_qxdm_time(pkt_data[4:12])
                payload = pkt_data[12:]
                if len(payload) >= 8:
                    version = payload[0]
                    sc_raw = u16(payload, 1)
                    serving_cell_id = sc_raw & 511
                    num_records = (sc_raw >> 9) & 31
                    disp_raw = u16(payload, 4)
                    dispatch_sfn = disp_raw // 10
                    dispatch_subfn = disp_raw % 10

                    if version >= 144:
                        rec_size = 100
                    elif version == 124:
                        rec_size = 84
                    elif version == 122:
                        rec_size = 68
                    elif version == 102:
                        rec_size = 72
                    elif version == 43:
                        rec_size = 64
                    elif version == 26:
                        rec_size = 52
                    else:
                        rec_size = 48

                    header_offset = 8
                    if 0 < num_records and header_offset + num_records * rec_size <= len(payload):
                        for r_idx in range(num_records):
                            rec_start = header_offset + (r_idx * rec_size)
                            rec = payload[rec_start : rec_start + rec_size]

                            sfn_sf = u16(rec, 0)
                            current_sfn = sfn_sf // 10
                            current_subfn = sfn_sf % 10

                            if version >= 144:
                                u2 = u16(rec, 2)
                                ack_present = (u2 >> 2) & 1
                                cqi_present = (u2 >> 3) & 1
                                ri_present = (u2 >> 4) & 1
                                freq_hopping = (u2 >> 5) & 3
                                retx_index = (u2 >> 7) & 31
                                rv = (u2 >> 12) & 3
                                mirror_hopping = (u2 >> 14) & 3

                                u4 = u32(rec, 4)
                                resource_alloc_type = u4 & 1
                                start_rb_slot0 = (u4 >> 1) & 127
                                start_rb_slot1 = (u4 >> 8) & 127
                                num_rb = (u4 >> 15) & 127

                                tb_size_bytes = u16(rec, 8)
                                coding_rate = round(u16(rec, 10) / 1024.0, 4)

                                u12 = u32(rec, 12)
                                rate_matched_ack_bits = u12 & 16383
                                ri_payload_int = (u12 >> 14) & 16383
                                ri_payload = f"0x{ri_payload_int:04x}"
                                num_ri_bits = (u12 >> 28) & 15

                                ack_payload = rec[16:32].hex()
                                rate_matched_ri_bits = (u32(rec, 32) >> 14) & 0x7FF

                                u36 = u32(rec, 36)
                                ue_srs = u36 & 1
                                srs_occasion = (u36 >> 1) & 1
                                mod_order = (u36 >> 2) & 7
                                digital_gain_db = (u36 >> 5) & 255
                                start_rb_cluster1 = (u36 >> 13) & 127
                                num_rb_cluster1 = (u36 >> 20) & 127

                                u40 = u32(rec, 40)
                                tx_power_dbm = u40 & 127
                                num_cqi_bits = (u40 >> 7) & 255
                                rate_matched_cqi_bits = (u40 >> 18) & 16383

                                u44 = u32(rec, 44)
                                num_dl_carriers = u44 & 3
                                drop_pusch = (u44 >> 16) & 1

                                u96 = u32(rec, 96)
                                cyclic_shift_dmrs_slot0 = u96 & 15
                                cyclic_shift_dmrs_slot1 = (u96 >> 4) & 15
                                num_ack_bits = 0
                            elif version in (102, 122, 124):
                                u2 = u16(rec, 2)
                                ack_present = (u2 >> 2) & 1
                                cqi_present = (u2 >> 3) & 1
                                ri_present = (u2 >> 4) & 1
                                freq_hopping = (u2 >> 5) & 3
                                retx_index = (u2 >> 7) & 31
                                rv = (u2 >> 12) & 3
                                mirror_hopping = (u2 >> 14) & 3

                                u4 = u32(rec, 4)
                                resource_alloc_type = (u4 & 1) if version != 122 else 0
                                start_rb_slot0 = (u4 >> 1) & 127 if version != 122 else (u4 & 127)
                                start_rb_slot1 = (u4 >> 8) & 127 if version != 122 else ((u4 >> 7) & 127)
                                num_rb = (u4 >> 15) & 127 if version != 122 else ((u4 >> 14) & 127)

                                tb_size_bytes = u16(rec, 8)
                                coding_rate = round(u16(rec, 10) / 1024.0, 4)

                                u12 = u32(rec, 12)
                                rate_matched_ack_bits = u12 & 16383
                                ri_payload_int = (u12 >> 14) & 15
                                ri_payload = f"0x{ri_payload_int:x}"
                                rate_matched_ri_bits = (u12 >> 18) & 2047
                                ue_srs = (u12 >> 29) & 1
                                srs_occasion = (u12 >> 30) & 1

                                u16_val = u32(rec, 16)
                                ack_payload = hex(u16_val & 0xFFFFF)
                                num_ri_bits = (u16_val >> 28) & 7

                                u20 = u32(rec, 20)
                                mod_order = u20 & 3
                                digital_gain_db = (u20 >> 2) & 255
                                start_rb_cluster1 = (u20 >> 10) & 255 if version in (102, 124) else 0
                                num_rb_cluster1 = (u20 >> 18) & 63 if version in (102, 124) else 0

                                u24 = u32(rec, 24)
                                tx_power_dbm = u24 & 127
                                num_cqi_bits = (u24 >> 7) & 255
                                rate_matched_cqi_bits = (u24 >> 15) & 65535

                                u28 = u32(rec, 28)
                                num_dl_carriers = u28 & 3
                                drop_pusch = (u28 >> 16) & 1

                                dmrs_offset = 64 if version == 102 else (60 if version == 122 else 76)
                                if len(rec) >= dmrs_offset + 4:
                                    udmrs = u32(rec, dmrs_offset)
                                    cyclic_shift_dmrs_slot0 = udmrs & 15
                                    cyclic_shift_dmrs_slot1 = (udmrs >> 4) & 15
                                else:
                                    cyclic_shift_dmrs_slot0 = 0
                                    cyclic_shift_dmrs_slot1 = 0
                                num_ack_bits = 0
                            elif version == 43:
                                coding_rate = round(u16(rec, 2) / 1024.0, 4)

                                u4 = u32(rec, 4)
                                ack_present = u4 & 1
                                cqi_present = (u4 >> 1) & 1
                                ri_present = (u4 >> 2) & 1
                                freq_hopping = (u4 >> 3) & 3
                                rv = (u4 >> 5) & 3
                                mirror_hopping = (u4 >> 7) & 3
                                cyclic_shift_dmrs_slot0 = (u4 >> 9) & 15
                                cyclic_shift_dmrs_slot1 = (u4 >> 13) & 15
                                ue_srs = (u4 >> 28) & 1

                                u8 = u32(rec, 8)
                                start_rb_slot0 = (u8 >> 11) & 127
                                start_rb_slot1 = (u8 >> 18) & 127
                                num_rb = (u8 >> 25) & 127

                                tb_size_bytes = u16(rec, 12)
                                ack_payload = hex(u32(rec, 14))

                                u22 = u32(rec, 22)
                                mod_order = u22 & 3
                                digital_gain_db = 0

                                srs_byte = rec[26]
                                srs_occasion = srs_byte & 1
                                retx_index = (srs_byte >> 1) & 31

                                u28 = u32(rec, 28)
                                tx_power_dbm = u28 & 1023
                                num_cqi_bits = (u28 >> 10) & 255
                                rate_matched_cqi_bits = (u28 >> 18) & 16383

                                num_dl_carriers = u32(rec, 32) & 3
                                resource_alloc_type = 0
                                rate_matched_ack_bits = 0
                                rate_matched_ri_bits = 0
                                num_ri_bits = 0
                                ri_payload = ""
                                num_ack_bits = 0
                                drop_pusch = 0
                                start_rb_cluster1 = 0
                                num_rb_cluster1 = 0
                            else:
                                coding_rate = round(u16(rec, 2) / 1024.0, 4)

                                u4 = u32(rec, 4)
                                ack_present = u4 & 1
                                cqi_present = (u4 >> 1) & 1
                                ri_present = (u4 >> 2) & 1
                                freq_hopping = (u4 >> 3) & 3
                                rv = (u4 >> 5) & 3
                                mirror_hopping = (u4 >> 7) & 3
                                cyclic_shift_dmrs_slot0 = (u4 >> 9) & 15
                                cyclic_shift_dmrs_slot1 = (u4 >> 13) & 15
                                ue_srs = (u4 >> 28) & 1

                                u8 = u32(rec, 8)
                                start_rb_slot0 = (u8 >> 11) & 127
                                start_rb_slot1 = (u8 >> 18) & 127
                                num_rb = (u8 >> 25) & 127

                                tb_size_bytes = u16(rec, 12)

                                u14 = u16(rec, 14)
                                num_ack_bits = u14 & 7
                                ack_payload = hex((u14 >> 3) & 15)

                                u16_val = u32(rec, 16)
                                rate_matched_ack_bits = u16_val & 2047
                                num_ri_bits = (u16_val >> 11) & 3
                                ri_payload = hex((u16_val >> 13) & 3)
                                rate_matched_ri_bits = (u16_val >> 15) & 2047
                                mod_order = (u16_val >> 26) & 3

                                digital_gain_db = rec[20]
                                u21 = rec[21]
                                srs_occasion = u21 & 1
                                retx_index = (u21 >> 1) & 31

                                u24 = u32(rec, 24)
                                tx_power_dbm = u24 & 1023
                                num_cqi_bits = (u24 >> 10) & 255
                                rate_matched_cqi_bits = (u24 >> 18) & 16383

                                resource_alloc_type = 0
                                num_dl_carriers = 1
                                drop_pusch = 0
                                start_rb_cluster1 = 0
                                num_rb_cluster1 = 0

                            mod_str = B139_MODULATION_MAP.get(mod_order, f"Mod_{mod_order}")
                            tb_size_bits = tb_size_bytes * 8
                            is_retx = 1 if retx_index > 0 else 0

                            records.append({
                                "time": pkt_time,
                                "serving_cell_id": serving_cell_id,
                                "dispatch_sfn": dispatch_sfn,
                                "dispatch_subfn": dispatch_subfn,
                                "current_sfn": current_sfn,
                                "current_subfn": current_subfn,
                                "retx_index": retx_index,
                                "is_retx": is_retx,
                                "rv": rv,
                                "tb_size_bytes": tb_size_bytes,
                                "tb_size_bits": tb_size_bits,
                                "num_rb": num_rb,
                                "start_rb_slot0": start_rb_slot0,
                                "start_rb_slot1": start_rb_slot1,
                                "resource_alloc_type": resource_alloc_type,
                                "coding_rate": coding_rate,
                                "mod_order": mod_order,
                                "modulation": mod_str,
                                "tx_power_dbm": tx_power_dbm,
                                "digital_gain_db": digital_gain_db,
                                "ack_present": ack_present,
                                "cqi_present": cqi_present,
                                "ri_present": ri_present,
                                "freq_hopping": freq_hopping,
                                "mirror_hopping": mirror_hopping,
                                "ue_srs": ue_srs,
                                "srs_occasion": srs_occasion,
                                "num_ack_bits": num_ack_bits,
                                "rate_matched_ack_bits": rate_matched_ack_bits,
                                "ack_payload": ack_payload,
                                "num_ri_bits": num_ri_bits,
                                "rate_matched_ri_bits": rate_matched_ri_bits,
                                "ri_payload": ri_payload,
                                "num_cqi_bits": num_cqi_bits,
                                "rate_matched_cqi_bits": rate_matched_cqi_bits,
                                "num_dl_carriers": num_dl_carriers,
                                "drop_pusch": drop_pusch,
                                "cyclic_shift_dmrs_slot0": cyclic_shift_dmrs_slot0,
                                "cyclic_shift_dmrs_slot1": cyclic_shift_dmrs_slot1,
                                "start_rb_cluster1": start_rb_cluster1,
                                "num_rb_cluster1": num_rb_cluster1,
                            })
                        i += pkt_len
                        continue
        i += 1
    return records


# -----------------------------------------------------------------------------
# B173 (LTE ML1 PDSCH Stat Indication) Parser
# -----------------------------------------------------------------------------
def parse_b173_records(raw):
    """
    Independently parses 0xB173 (LTE ML1 PDSCH Stat Indication) packets from raw bytes.
    Supports versions v48/v40/v37/v36 (40B), v34 (32B), v32/v24 (24B), v16/v5 (20B).
    """
    records = []
    i = 0
    raw_len = len(raw)
    while i < raw_len - 3:
        if raw[i + 2] == 0x73 and raw[i + 3] == 0xB1:
            pkt_len = raw[i] | (raw[i + 1] << 8)
            if 16 <= pkt_len <= 4096 and i + pkt_len <= raw_len:
                pkt_data = raw[i : i + pkt_len]
                pkt_time = parse_qxdm_time(pkt_data[4:12])
                payload = pkt_data[12:]
                if len(payload) >= 4:
                    version = payload[0]
                    num_records = payload[1]

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
                    else:
                        rec_size = 20
                        p1_size = 6
                        tb_size = 6

                    header_offset = 4
                    if 0 < num_records and header_offset + num_records * rec_size <= len(payload):
                        for r_idx in range(num_records):
                            rec_start = header_offset + (r_idx * rec_size)
                            rec = payload[rec_start : rec_start + rec_size]

                            subfn_raw = u16(rec, 0)
                            subframe = subfn_raw & 0xF
                            frame = (subfn_raw >> 4) & 0xFFF
                            num_rbs_subframe = rec[2]
                            num_layers = rec[3]
                            num_tbs_present = rec[4]
                            cell_raw = rec[5]
                            hsic_enabled = (cell_raw >> 3) & 0xF

                            if version >= 36:
                                pmch_id = rec[36]
                                area_id = rec[37]
                            else:
                                pmch_id = rec[-2]
                                area_id = rec[-1]

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
                                    rnti_word = u16(tb_bytes, 1)
                                    rnti_type_id = rnti_word & 0xF
                                    did_recombining = (rnti_word >> 10) & 0x1
                                    tb_size_bytes = u16(tb_bytes, 4)
                                    mcs = tb_bytes[6]
                                    tb_rbs = tb_bytes[7]
                                    mod_val = tb_bytes[8]
                                elif version in (34, 32, 24):
                                    rnti_byte = tb_bytes[1]
                                    rnti_type_id = rnti_byte & 0xF
                                    did_recombining = (rnti_byte >> 6) & 0x1
                                    tb_size_bytes = u16(tb_bytes, 2) if version == 32 else u16(tb_bytes, 4)
                                    mcs = tb_bytes[4] if version == 32 else tb_bytes[6]
                                    tb_rbs = tb_bytes[5] if version == 32 else tb_bytes[7]
                                    mod_val = tb_bytes[6] if version == 32 else tb_bytes[8]
                                else:
                                    rnti_type_id = tb_bytes[1] & 0xF
                                    did_recombining = 0
                                    tb_size_bytes = u16(tb_bytes, 2)
                                    mcs = tb_bytes[4]
                                    tb_rbs = tb_bytes[5]
                                    mod_val = 0

                                mod_str = B173_MODULATION_MAP.get(mod_val, f"Mod_{mod_val}")
                                rnti_str = B173_RNTI_TYPE_MAP.get(rnti_type_id, f"RNTI_{rnti_type_id}")
                                tb_size_bits = tb_size_bytes * 8

                                records.append({
                                    "time": pkt_time,
                                    "frame": frame,
                                    "subframe": subframe,
                                    "num_rbs_subframe": num_rbs_subframe,
                                    "num_layers": num_layers,
                                    "num_tbs_present": num_tbs_present,
                                    "hsic_enabled": hsic_enabled,
                                    "tb_idx": tb_i,
                                    "harq_id": harq_id,
                                    "rv": rv,
                                    "ndi": ndi,
                                    "crc_pass": crc_pass,
                                    "crc_status": crc_str,
                                    "rnti_type_id": rnti_type_id,
                                    "rnti_type": rnti_str,
                                    "tb_size_bytes": tb_size_bytes,
                                    "tb_size_bits": tb_size_bits,
                                    "mcs": mcs,
                                    "modulation": mod_str,
                                    "tb_rbs": tb_rbs,
                                    "did_recombining": did_recombining,
                                    "pmch_id": pmch_id,
                                    "area_id": area_id,
                                })
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


def dump_b139(raw_bytes, out_csv):
    """
    Decodes and writes B139 LTE PUSCH Tx records into out_csv sorted chronologically.
    Always writes a valid CSV (header-only if no records exist).
    """
    records = parse_b139_records(raw_bytes)
    records.sort(key=lambda r: (r["time"], r.get("current_sfn", 0), r.get("current_subfn", 0)))

    with open(out_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(B139_HEADER)
        for r in records:
            writer.writerow([
                f"{r['time']:.6f}",
                human_time(r["time"]),
                r["serving_cell_id"],
                r["dispatch_sfn"],
                r["dispatch_subfn"],
                r["current_sfn"],
                r["current_subfn"],
                r["retx_index"],
                r["is_retx"],
                r["rv"],
                r["tb_size_bytes"],
                r["tb_size_bits"],
                r["num_rb"],
                r["start_rb_slot0"],
                r["start_rb_slot1"],
                r["resource_alloc_type"],
                r["coding_rate"],
                r["mod_order"],
                r["modulation"],
                r["tx_power_dbm"],
                r["digital_gain_db"],
                r["ack_present"],
                r["cqi_present"],
                r["ri_present"],
                r["freq_hopping"],
                r["mirror_hopping"],
                r["ue_srs"],
                r["srs_occasion"],
                r["num_ack_bits"],
                r["rate_matched_ack_bits"],
                r["ack_payload"],
                r["num_ri_bits"],
                r["rate_matched_ri_bits"],
                r["ri_payload"],
                r["num_cqi_bits"],
                r["rate_matched_cqi_bits"],
                r["num_dl_carriers"],
                r["drop_pusch"],
                r["cyclic_shift_dmrs_slot0"],
                r["cyclic_shift_dmrs_slot1"],
                r["start_rb_cluster1"],
                r["num_rb_cluster1"],
            ])

    if records:
        print(f"  [B139] Wrote {len(records)} rows -> {out_csv}")
    else:
        print(f"  [B139] No records found (header-only CSV written: {out_csv})")
    return len(records)


def dump_b173(raw_bytes, out_csv):
    """
    Decodes and writes B173 LTE PDSCH Stat records into out_csv sorted chronologically.
    Always writes a valid CSV (header-only if no records exist).
    """
    records = parse_b173_records(raw_bytes)
    records.sort(key=lambda r: (r["time"], r.get("frame", 0), r.get("subframe", 0), r.get("tb_idx", 0)))

    with open(out_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(B173_HEADER)
        for r in records:
            writer.writerow([
                f"{r['time']:.6f}",
                human_time(r["time"]),
                r["frame"],
                r["subframe"],
                r["num_rbs_subframe"],
                r["num_layers"],
                r["num_tbs_present"],
                r["hsic_enabled"],
                r["tb_idx"],
                r["harq_id"],
                r["rv"],
                r["ndi"],
                r["crc_pass"],
                r["crc_status"],
                r["rnti_type_id"],
                r["rnti_type"],
                r["tb_size_bytes"],
                r["tb_size_bits"],
                r["mcs"],
                r["modulation"],
                r["tb_rbs"],
                r["did_recombining"],
                r["pmch_id"],
                r["area_id"],
            ])

    if records:
        print(f"  [B173] Wrote {len(records)} rows -> {out_csv}")
    else:
        print(f"  [B173] No records found (header-only CSV written: {out_csv})")
    return len(records)


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

    try:
        dump_b139(raw_bytes, f"{out_prefix}_b139.csv")
    except Exception:
        failed = True
        print("  [B139] ERROR while dumping B139 CSV:")
        traceback.print_exc()

    try:
        dump_b173(raw_bytes, f"{out_prefix}_b173.csv")
    except Exception:
        failed = True
        print("  [B173] ERROR while dumping B173 CSV:")
        traceback.print_exc()

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
