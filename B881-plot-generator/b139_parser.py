#!/usr/bin/env python3
"""
b139_parser.py
==============
Parser and Telemetry Extractor for Qualcomm DIAG Log Type 0xB139
(LTE PHY PUSCH Tx Report / Physical Uplink Shared Channel Transmission Report).

Decodes:
  - Hardware modem timestamps (UTC and local IST with microsecond precision)
  - Timing & Scheduling: Frame Number (SFN 0-1023) and Subframe Number (0-9)
  - Dispatch Timing: Dispatch SFN and Subframe
  - Serving Physical Cell ID (0-503)
  - Carrier Component info (PCC, SCC1..SCC4)
  - Physical Resource Blocks (Num RBs, Start RB Slot 0, Start RB Slot 1, Cluster 1)
  - Resource Allocation Type (Type 0 / Type 1)
  - Transport Block Sizes (Bytes & Bits) & Physical Layer UL Throughput
  - Effective Coding Rate (Coding Rate Data / 1024.0)
  - Modulation Order (BPSK, QPSK, 16-QAM, 64-QAM, 256-QAM)
  - HARQ Retransmissions: Retx Index (First Tx vs Re-Tx 1, 2, 3...) & Redundancy Version (RV 0-3)
  - Transmit Power (PUSCH Tx Power in dBm) & Modem Digital Gain (dB)
  - Uplink Control Information (UCI) multiplexed on PUSCH:
      * ACK/NACK presence, bit count, rate-matched bits, and payload
      * CQI/CSI presence, bit count, rate-matched bits, and payload
      * Rank Indicator (RI) presence, bit count, rate-matched bits, and payload
  - Hopping & Sounding: Frequency Hopping, Mirror Hopping, UE SRS, and SRS Occasion
  - Carrier Aggregation Downlink Info & PUSCH Puncturing (Drop PUSCH)
  - DMRS Cyclic Shift & Sequence Root indices

Input formats supported:
  - Raw binary QMDL files (.qmdl) directly (streaming extraction)
  - Directory containing QMDL files (recursive search)
  - Hex payload text files (SCAT/QXDM formatted payload lines) or stdin (-)

Outputs:
  - Clean per-transmission-record time-series CSV (ready for Pandas / ML / plotting)
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
LOG_CODE_0XB139 = 0xB139

CARRIER_INDEX_MAP = {
    0: "PCC",
    1: "SCC1",
    2: "SCC2",
    3: "SCC3",
    4: "SCC4",
}

MODULATION_MAP = {
    0: "BPSK",
    1: "QPSK",
    2: "16-QAM",
    3: "64-QAM",
    4: "256-QAM",
}


@dataclass
class PuschTxRecord:
    timestamp_utc: str
    timestamp_ist: str
    epoch_sec: float
    payload_idx: int
    record_idx: int
    version: int
    serving_cell_id: int
    dispatch_sfn: int
    dispatch_subfn: int
    current_sfn: int
    current_subfn: int
    carrier_idx: int
    carrier_name: str
    retx_index: int
    is_retx: int
    rv: int
    tb_size_bytes: int
    tb_size_bits: int
    num_rb: int
    start_rb_slot0: int
    start_rb_slot1: int
    resource_alloc_type: int
    coding_rate: float
    mod_order: int
    modulation: str
    tx_power_dbm: int
    digital_gain_db: int
    ack_present: int
    cqi_present: int
    ri_present: int
    freq_hopping: int
    mirror_hopping: int
    ue_srs: int
    srs_occasion: int
    num_ack_bits: int
    rate_matched_ack_bits: int
    ack_payload: str
    num_ri_bits: int
    rate_matched_ri_bits: int
    ri_payload: str
    num_cqi_bits: int
    rate_matched_cqi_bits: int
    num_dl_carriers: int
    drop_pusch: int
    cyclic_shift_dmrs_slot0: int
    cyclic_shift_dmrs_slot1: int
    start_rb_cluster1: int
    num_rb_cluster1: int

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


# ── 0xB139 Binary Payload Decoder ─────────────────────────────────────────────
def decode_b139_payload(
    payload: bytes,
    dt_utc: datetime.datetime,
    epoch_sec: float,
    payload_idx: int
) -> List[PuschTxRecord]:
    """
    Decodes the raw binary payload of a 0xB139 LTE PHY PUSCH Tx Report packet.
    Supports modern LTE / LTE-A Pro format (v162, v145, v144: 100 bytes/record)
    with full backward compatibility for v124 (84B), v122 (68B), v102 (72B),
    v43 (64B), v26 (52B), v24 (48B), and v23 (48B).
    """
    if len(payload) < 8:
        return []

    version = payload[0]

    # Parse 8-byte payload header
    sc_raw = struct.unpack('<H', payload[1:3])[0]
    serving_cell_id = sc_raw & 511          # 9 bits (0-503)
    num_records = (sc_raw >> 9) & 31        # 5 bits
    disp_raw = struct.unpack('<H', payload[4:6])[0]
    dispatch_sfn = disp_raw // 10           # Frame (0-1023)
    dispatch_subfn = disp_raw % 10          # Subframe (0-9)

    # Time representations (UTC & IST)
    ist_tz = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    dt_ist = dt_utc.astimezone(ist_tz)
    ts_utc_str = dt_utc.strftime("%Y-%m-%d %H:%M:%S.%f")
    ts_ist_str = dt_ist.strftime("%Y-%m-%d %H:%M:%S.%f")

    # Determine record layout based on version
    if version >= 144:  # v162, v145, v144
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
    else:  # v24, v23, legacy
        rec_size = 48

    records: List[PuschTxRecord] = []
    header_offset = 8

    for r_idx in range(num_records):
        rec_start = header_offset + (r_idx * rec_size)
        rec_end = rec_start + rec_size
        if rec_end > len(payload):
            break

        rec = payload[rec_start:rec_end]

        # 1. Parse Current SFN and Subframe (all versions)
        sfn_sf = struct.unpack('<H', rec[0:2])[0]
        current_sfn = sfn_sf // 10
        current_subfn = sfn_sf % 10

        # Version-specific parsing
        if version >= 144:  # v144, v145, v162
            u2 = struct.unpack('<H', rec[2:4])[0]
            carrier_idx = u2 & 3
            ack_present = (u2 >> 2) & 1
            cqi_present = (u2 >> 3) & 1
            ri_present = (u2 >> 4) & 1
            freq_hopping = (u2 >> 5) & 3
            retx_index = (u2 >> 7) & 31
            rv = (u2 >> 12) & 3
            mirror_hopping = (u2 >> 14) & 3

            u4 = struct.unpack('<I', rec[4:8])[0]
            resource_alloc_type = u4 & 1
            start_rb_slot0 = (u4 >> 1) & 127
            start_rb_slot1 = (u4 >> 8) & 127
            num_rb = (u4 >> 15) & 127
            dl_carrier_idx = (u4 >> 22) & 7

            tb_size_bytes = struct.unpack('<H', rec[8:10])[0]
            coding_rate_raw = struct.unpack('<H', rec[10:12])[0]
            coding_rate = round(coding_rate_raw / 1024.0, 4)

            u12 = struct.unpack('<I', rec[12:16])[0]
            rate_matched_ack_bits = u12 & 16383
            ri_payload_int = (u12 >> 14) & 16383
            ri_payload = f"0x{ri_payload_int:04x}"
            num_ri_bits = (u12 >> 28) & 15

            ack_payload = rec[16:32].hex()

            u32 = struct.unpack('<I', rec[32:36])[0]
            rate_matched_ri_bits = (u32 >> 14) & 0x7FF

            u36 = struct.unpack('<I', rec[36:40])[0]
            ue_srs = u36 & 1
            srs_occasion = (u36 >> 1) & 1
            mod_order = (u36 >> 2) & 7
            digital_gain_db = (u36 >> 5) & 255
            start_rb_cluster1 = (u36 >> 13) & 127
            num_rb_cluster1 = (u36 >> 20) & 127

            u40 = struct.unpack('<I', rec[40:44])[0]
            tx_power_dbm = u40 & 127
            num_cqi_bits = (u40 >> 7) & 255
            rate_matched_cqi_bits = (u40 >> 18) & 16383

            u44 = struct.unpack('<I', rec[44:48])[0]
            num_dl_carriers = u44 & 3
            drop_pusch = (u44 >> 16) & 1

            u96 = struct.unpack('<I', rec[96:100])[0]
            cyclic_shift_dmrs_slot0 = u96 & 15
            cyclic_shift_dmrs_slot1 = (u96 >> 4) & 15
            num_ack_bits = 0

        elif version in (102, 122, 124):
            u2 = struct.unpack('<H', rec[2:4])[0]
            carrier_idx = u2 & 3
            ack_present = (u2 >> 2) & 1
            cqi_present = (u2 >> 3) & 1
            ri_present = (u2 >> 4) & 1
            freq_hopping = (u2 >> 5) & 3
            retx_index = (u2 >> 7) & 31
            rv = (u2 >> 12) & 3
            mirror_hopping = (u2 >> 14) & 3

            u4 = struct.unpack('<I', rec[4:8])[0]
            resource_alloc_type = (u4 & 1) if version != 122 else 0
            start_rb_slot0 = (u4 >> 1) & 127 if version != 122 else (u4 & 127)
            start_rb_slot1 = (u4 >> 8) & 127 if version != 122 else ((u4 >> 7) & 127)
            num_rb = (u4 >> 15) & 127 if version != 122 else ((u4 >> 14) & 127)
            dl_carrier_idx = 0

            tb_size_bytes = struct.unpack('<H', rec[8:10])[0]
            coding_rate_raw = struct.unpack('<H', rec[10:12])[0]
            coding_rate = round(coding_rate_raw / 1024.0, 4)

            u12 = struct.unpack('<I', rec[12:16])[0]
            rate_matched_ack_bits = u12 & 16383
            ri_payload_int = (u12 >> 14) & 15
            ri_payload = f"0x{ri_payload_int:x}"
            rate_matched_ri_bits = (u12 >> 18) & 2047
            ue_srs = (u12 >> 29) & 1
            srs_occasion = (u12 >> 30) & 1

            u16 = struct.unpack('<I', rec[16:20])[0]
            ack_payload = hex(u16 & 0xFFFFF)
            num_ri_bits = (u16 >> 28) & 7

            u20 = struct.unpack('<I', rec[20:24])[0]
            mod_order = u20 & 3
            digital_gain_db = (u20 >> 2) & 255
            start_rb_cluster1 = (u20 >> 10) & 255 if version in (102, 124) else 0
            num_rb_cluster1 = (u20 >> 18) & 63 if version in (102, 124) else 0

            u24 = struct.unpack('<I', rec[24:28])[0]
            tx_power_dbm = u24 & 127
            num_cqi_bits = (u24 >> 7) & 255
            rate_matched_cqi_bits = (u24 >> 15) & 65535

            u28 = struct.unpack('<I', rec[28:32])[0]
            num_dl_carriers = u28 & 3
            drop_pusch = (u28 >> 16) & 1

            # DMRS shifts
            dmrs_offset = 64 if version == 102 else (60 if version == 122 else 76)
            if len(rec) >= dmrs_offset + 4:
                udmrs = struct.unpack('<I', rec[dmrs_offset:dmrs_offset+4])[0]
                cyclic_shift_dmrs_slot0 = udmrs & 15
                cyclic_shift_dmrs_slot1 = (udmrs >> 4) & 15
            else:
                cyclic_shift_dmrs_slot0 = 0
                cyclic_shift_dmrs_slot1 = 0
            num_ack_bits = 0

        elif version == 43:
            coding_rate_raw = struct.unpack('<H', rec[2:4])[0]
            coding_rate = round(coding_rate_raw / 1024.0, 4)

            u4 = struct.unpack('<I', rec[4:8])[0]
            ack_present = u4 & 1
            cqi_present = (u4 >> 1) & 1
            ri_present = (u4 >> 2) & 1
            freq_hopping = (u4 >> 3) & 3
            rv = (u4 >> 5) & 3
            mirror_hopping = (u4 >> 7) & 3
            cyclic_shift_dmrs_slot0 = (u4 >> 9) & 15
            cyclic_shift_dmrs_slot1 = (u4 >> 13) & 15
            ue_srs = (u4 >> 28) & 1

            u8 = struct.unpack('<I', rec[8:12])[0]
            start_rb_slot0 = (u8 >> 11) & 127
            start_rb_slot1 = (u8 >> 18) & 127
            num_rb = (u8 >> 25) & 127

            tb_size_bytes = struct.unpack('<H', rec[12:14])[0]
            ack_payload = hex(struct.unpack('<I', rec[14:18])[0])

            u22 = struct.unpack('<I', rec[22:26])[0]
            mod_order = u22 & 3
            digital_gain_db = 0

            srs_byte = rec[26]
            srs_occasion = srs_byte & 1
            retx_index = (srs_byte >> 1) & 31

            u28 = struct.unpack('<I', rec[28:32])[0]
            tx_power_dbm = u28 & 1023
            num_cqi_bits = (u28 >> 10) & 255
            rate_matched_cqi_bits = (u28 >> 18) & 16383

            num_dl_carriers = struct.unpack('<I', rec[32:36])[0] & 3
            carrier_idx = 0
            resource_alloc_type = 0
            rate_matched_ack_bits = 0
            rate_matched_ri_bits = 0
            num_ri_bits = 0
            ri_payload = ""
            num_ack_bits = 0
            drop_pusch = 0
            start_rb_cluster1 = 0
            num_rb_cluster1 = 0

        else:  # v23, v24, v26 legacy formats
            coding_rate_raw = struct.unpack('<H', rec[2:4])[0]
            coding_rate = round(coding_rate_raw / 1024.0, 4)

            u4 = struct.unpack('<I', rec[4:8])[0]
            ack_present = u4 & 1
            cqi_present = (u4 >> 1) & 1
            ri_present = (u4 >> 2) & 1
            freq_hopping = (u4 >> 3) & 3
            rv = (u4 >> 5) & 3
            mirror_hopping = (u4 >> 7) & 3
            cyclic_shift_dmrs_slot0 = (u4 >> 9) & 15
            cyclic_shift_dmrs_slot1 = (u4 >> 13) & 15
            ue_srs = (u4 >> 28) & 1

            u8 = struct.unpack('<I', rec[8:12])[0]
            start_rb_slot0 = (u8 >> 11) & 127
            start_rb_slot1 = (u8 >> 18) & 127
            num_rb = (u8 >> 25) & 127

            tb_size_bytes = struct.unpack('<H', rec[12:14])[0]

            u14 = struct.unpack('<H', rec[14:16])[0]
            num_ack_bits = u14 & 7
            ack_payload = hex((u14 >> 3) & 15)

            u16 = struct.unpack('<I', rec[16:20])[0]
            rate_matched_ack_bits = u16 & 2047
            num_ri_bits = (u16 >> 11) & 3
            ri_payload = hex((u16 >> 13) & 3)
            rate_matched_ri_bits = (u16 >> 15) & 2047
            mod_order = (u16 >> 26) & 3

            digital_gain_db = rec[20]

            u21 = rec[21]
            srs_occasion = u21 & 1
            retx_index = (u21 >> 1) & 31

            u24 = struct.unpack('<I', rec[24:28])[0]
            tx_power_dbm = u24 & 1023
            num_cqi_bits = (u24 >> 10) & 255
            rate_matched_cqi_bits = (u24 >> 18) & 16383

            carrier_idx = 0
            resource_alloc_type = 0
            num_dl_carriers = 1
            drop_pusch = 0
            start_rb_cluster1 = 0
            num_rb_cluster1 = 0

        carrier_name = CARRIER_INDEX_MAP.get(carrier_idx, f"SCC{carrier_idx}")
        mod_str = MODULATION_MAP.get(mod_order, f"Mod_{mod_order}")
        tb_size_bits = tb_size_bytes * 8
        is_retx = 1 if retx_index > 0 else 0

        record = PuschTxRecord(
            timestamp_utc=ts_utc_str,
            timestamp_ist=ts_ist_str,
            epoch_sec=epoch_sec,
            payload_idx=payload_idx,
            record_idx=r_idx,
            version=version,
            serving_cell_id=serving_cell_id,
            dispatch_sfn=dispatch_sfn,
            dispatch_subfn=dispatch_subfn,
            current_sfn=current_sfn,
            current_subfn=current_subfn,
            carrier_idx=carrier_idx,
            carrier_name=carrier_name,
            retx_index=retx_index,
            is_retx=is_retx,
            rv=rv,
            tb_size_bytes=tb_size_bytes,
            tb_size_bits=tb_size_bits,
            num_rb=num_rb,
            start_rb_slot0=start_rb_slot0,
            start_rb_slot1=start_rb_slot1,
            resource_alloc_type=resource_alloc_type,
            coding_rate=coding_rate,
            mod_order=mod_order,
            modulation=mod_str,
            tx_power_dbm=tx_power_dbm,
            digital_gain_db=digital_gain_db,
            ack_present=ack_present,
            cqi_present=cqi_present,
            ri_present=ri_present,
            freq_hopping=freq_hopping,
            mirror_hopping=mirror_hopping,
            ue_srs=ue_srs,
            srs_occasion=srs_occasion,
            num_ack_bits=num_ack_bits,
            rate_matched_ack_bits=rate_matched_ack_bits,
            ack_payload=ack_payload,
            num_ri_bits=num_ri_bits,
            rate_matched_ri_bits=rate_matched_ri_bits,
            ri_payload=ri_payload,
            num_cqi_bits=num_cqi_bits,
            rate_matched_cqi_bits=rate_matched_cqi_bits,
            num_dl_carriers=num_dl_carriers,
            drop_pusch=drop_pusch,
            cyclic_shift_dmrs_slot0=cyclic_shift_dmrs_slot0,
            cyclic_shift_dmrs_slot1=cyclic_shift_dmrs_slot1,
            start_rb_cluster1=start_rb_cluster1,
            num_rb_cluster1=num_rb_cluster1,
        )
        records.append(record)

    return records


# ── Streaming QMDL / Payload Readers ──────────────────────────────────────────
def iter_b139_from_qmdl(filepath: str) -> Generator[Tuple[bytes, datetime.datetime, float, int], None, None]:
    """Streams and yields (payload, dt_utc, epoch_sec, packet_idx) for 0xB139 from a QMDL file."""
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
                    if log_code == LOG_CODE_0XB139:
                        packet_idx += 1
                        ts_raw = struct.unpack('<Q', p[8:16])[0]
                        dt_utc, epoch_sec = parse_qualcomm_timestamp(ts_raw)
                        payload = p[16:]
                        yield payload, dt_utc, epoch_sec, packet_idx

            if not chunk:
                break


def iter_b139_from_text(f_in) -> Generator[Tuple[bytes, datetime.datetime, float, int], None, None]:
    """Reads hex payload lines (from text file or stdin) and yields payloads."""
    import re
    packet_idx = 0
    now_dt = datetime.datetime.now(datetime.timezone.utc)
    epoch_sec = now_dt.timestamp()

    for line in f_in:
        line_clean = line.strip()
        if not line_clean or line_clean.startswith('#'):
            continue

        # Check for continuous hex string
        line_no_spaces = line_clean.replace(" ", "").replace("\t", "").replace(":", "")
        if re.fullmatch(r'[0-9a-fA-F]+', line_no_spaces) and len(line_no_spaces) >= 16 and len(line_no_spaces) % 2 == 0:
            payload = bytes.fromhex(line_no_spaces)
            packet_idx += 1
            yield payload, now_dt, epoch_sec, packet_idx
        else:
            hex_bytes = re.findall(r'\b[0-9a-fA-F]{2}\b', line_clean)
            if len(hex_bytes) >= 8:
                payload = bytes(int(h, 16) for h in hex_bytes)
                packet_idx += 1
                yield payload, now_dt, epoch_sec, packet_idx


# ── Statistics & Summary Generator ────────────────────────────────────────────
def compute_summary(records: List[PuschTxRecord]) -> str:
    """Computes comprehensive telemetry metrics and formats a clean report."""
    if not records:
        return "No 0xB139 PUSCH records found in input."

    total_records = len(records)
    total_bytes = sum(r.tb_size_bytes for r in records)
    total_mb = total_bytes / (1024 * 1024)

    # Initial vs Retransmissions
    retx_records = sum(1 for r in records if r.is_retx == 1)
    new_tx_records = total_records - retx_records
    retx_rate = (retx_records / max(1, total_records)) * 100.0

    # Time span & throughput
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
    carrier_counts = Counter(r.carrier_name for r in records)
    carrier_bytes = defaultdict(int)
    carrier_retx = defaultdict(int)
    for r in records:
        carrier_bytes[r.carrier_name] += r.tb_size_bytes
        if r.is_retx:
            carrier_retx[r.carrier_name] += 1

    mod_counts = Counter(r.modulation for r in records)
    retx_counts = Counter(r.retx_index for r in records)
    rv_counts = Counter(r.rv for r in records)
    cell_counts = Counter(r.serving_cell_id for r in records)
    rb_counts = Counter(r.num_rb for r in records)

    # Control flags
    ack_count = sum(1 for r in records if r.ack_present)
    cqi_count = sum(1 for r in records if r.cqi_present)
    ri_count = sum(1 for r in records if r.ri_present)
    srs_count = sum(1 for r in records if r.srs_occasion or r.ue_srs)
    dropped_count = sum(1 for r in records if r.drop_pusch)

    # Power stats
    powers = [r.tx_power_dbm for r in records if r.tx_power_dbm > 0]
    min_power = min(powers) if powers else 0
    max_power = max(powers) if powers else 0
    avg_power = (sum(powers) / len(powers)) if powers else 0.0

    lines = []
    lines.append("=" * 88)
    lines.append(" 0xB139 LTE PHY PUSCH TX REPORT — TELEMETRY SUMMARY")
    lines.append("=" * 88)
    lines.append(f" Total Scheduled PUSCH Transmissions: {total_records:,}")
    lines.append(f" Initial Transmissions (First Tx)   : {new_tx_records:,} ({(new_tx_records/total_records)*100:.2f}%)")
    lines.append(f" HARQ Retransmissions               : {retx_records:,} ({retx_rate:.2f}%)")
    lines.append(f" Total PUSCH Uplink Data Volume     : {total_bytes:,} Bytes ({total_mb:.2f} MB)")
    if span_sec > 0:
        lines.append(f" Active Timeline Duration           : {start_str}  -->  {end_str} ({span_sec:.2f} s)")
        lines.append(f" Average PUSCH UL PHY Throughput    : {throughput_mbps:.2f} Mbps")
    lines.append(f" Serving Cell IDs (PCIs) Detected   : {', '.join(str(cid) for cid in sorted(cell_counts.keys()))}")
    lines.append("-" * 88)

    lines.append(" UPLINK CARRIER AGGREGATION BREAKDOWN:")
    lines.append(f" {'Carrier':<8} | {'Total PUSCH':<11} | {'Share (%)':<10} | {'UL Bytes':<14} | {'UL (MB)':<10} | {'Re-Tx (%)':<9}")
    lines.append("-" * 72)
    for c_name in sorted(carrier_counts.keys()):
        cnt = carrier_counts[c_name]
        share = (cnt / total_records) * 100.0
        c_b = carrier_bytes[c_name]
        c_mb = c_b / (1024 * 1024)
        c_retx_pct = (carrier_retx[c_name] / max(1, cnt)) * 100.0
        lines.append(f" {c_name:<8} | {cnt:<11,d} | {share:>8.2f}% | {c_b:<14,d} | {c_mb:>8.2f} MB | {c_retx_pct:>7.2f}%")
    lines.append("-" * 72)

    lines.append(" MODULATION DISTRIBUTION:")
    for mod in ["QPSK", "16-QAM", "64-QAM", "256-QAM", "BPSK"]:
        if mod in mod_counts:
            cnt = mod_counts[mod]
            pct = (cnt / total_records) * 100.0
            lines.append(f"   {mod:<8} : {cnt:>8,d} ({pct:>5.2f}%)")

    lines.append(" HARQ RETRANSMISSION INDEX DISTRIBUTION:")
    for r_idx in sorted(retx_counts.keys()):
        cnt = retx_counts[r_idx]
        pct = (cnt / total_records) * 100.0
        label = "Initial Tx" if r_idx == 0 else f"Re-Tx #{r_idx}"
        lines.append(f"   Index {r_idx:>2} ({label:<12}) : {cnt:>8,d} ({pct:>5.2f}%)")

    lines.append(" REDUNDANCY VERSION (RV) DISTRIBUTION:")
    for rv_val in sorted(rv_counts.keys()):
        cnt = rv_counts[rv_val]
        pct = (cnt / total_records) * 100.0
        rv_label = "New Data" if rv_val == 0 else f"Retransmission"
        lines.append(f"   RV {rv_val} ({rv_label:<14}) : {cnt:>8,d} ({pct:>5.2f}%)")

    lines.append(" TOP 10 SCHEDULED PHYSICAL RESOURCE BLOCK (PRB) ALLOCATIONS:")
    for num_rbs, cnt in rb_counts.most_common(10):
        pct = (cnt / total_records) * 100.0
        lines.append(f"   {num_rbs:>2} PRBs : {cnt:>8,d} ({pct:>5.2f}%)")

    lines.append(" PUSCH TRANSMIT POWER & RF METRICS:")
    if powers:
        lines.append(f"   Tx Power (Active Transmissions) : Min {min_power} dBm | Avg {avg_power:.1f} dBm | Max {max_power} dBm")
    else:
        lines.append(f"   Tx Power                        : 0 dBm (nominal/closed-loop)")

    lines.append(" UPLINK CONTROL INFORMATION (UCI) ON PUSCH & SIGNALS:")
    lines.append(f"   ACK/NACK Multiplexed on PUSCH   : {ack_count:>8,d} ({(ack_count/total_records)*100:>5.2f}%)")
    lines.append(f"   CQI/CSI Multiplexed on PUSCH    : {cqi_count:>8,d} ({(cqi_count/total_records)*100:>5.2f}%)")
    lines.append(f"   Rank Indicator (RI) Multiplexed : {ri_count:>8,d} ({(ri_count/total_records)*100:>5.2f}%)")
    lines.append(f"   SRS Transmissions / Occasions   : {srs_count:>8,d} ({(srs_count/total_records)*100:>5.2f}%)")
    lines.append(f"   Dropped / Punctured PUSCH       : {dropped_count:>8,d} ({(dropped_count/total_records)*100:>5.2f}%)")

    lines.append("=" * 88)
    return "\n".join(lines)


# ── Main Entry Point ──────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Comprehensive parser for Qualcomm DIAG log type 0xB139 (LTE PHY PUSCH Tx Report).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Parse a QMDL file and export CSV to default name (<file>_b139_pusch_tx.csv)
  python3 b139_parser.py loggers/vodafone_5g_toggle_off/diag_log_*.qmdl

  # Parse and specify custom CSV and text summary report paths
  python3 b139_parser.py loggers/vodafone_5g_toggle_off -o pusch_stats.csv --summary summary.txt

  # Parse from raw hex payload text file or pipeline via stdin
  python3 qmdl_to_codes.py input.txt --code 0xb139 | python3 b139_parser.py - -o parsed_b139.csv
"""
    )
    parser.add_argument("input", help="Path to .qmdl file, directory containing QMDL files, hex text file, or '-' for stdin")
    parser.add_argument("-o", "--output", help="Output CSV path (default: <input_basename>_b139_pusch_tx.csv)")
    parser.add_argument("-s", "--summary", help="Optional path to save ASCII summary report text file")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress console stdout printing")
    parser.add_argument("--include-rf", action="store_true", help="Include secondary RF modem files (mdm2)")

    args = parser.parse_args()

    records: List[PuschTxRecord] = []
    t0 = time.time()

    # 1. Handle STDIN / Text file mode
    if args.input == "-":
        if not args.quiet:
            print("[*] Reading 0xB139 payloads from STDIN...")
        for payload, dt_utc, epoch_sec, p_idx in iter_b139_from_text(sys.stdin):
            records.extend(decode_b139_payload(payload, dt_utc, epoch_sec, p_idx))

    elif os.path.isfile(args.input) and not args.input.endswith(".qmdl"):
        # Text payload file
        if not args.quiet:
            print(f"[*] Reading 0xB139 payloads from text file: {args.input}")
        with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
            for payload, dt_utc, epoch_sec, p_idx in iter_b139_from_text(f):
                records.extend(decode_b139_payload(payload, dt_utc, epoch_sec, p_idx))

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
            print(f"[*] Parsing 0xB139 records across {len(qmdl_files)} QMDL file(s)...")

        for fpath in qmdl_files:
            if not args.quiet:
                print(f"    - Processing: {fpath} ({os.path.getsize(fpath)/(1024*1024):.1f} MB)...")
            for payload, dt_utc, epoch_sec, p_idx in iter_b139_from_qmdl(fpath):
                records.extend(decode_b139_payload(payload, dt_utc, epoch_sec, p_idx))

    parse_time = time.time() - t0
    if not args.quiet:
        print(f"[*] Extracted {len(records):,} PUSCH transmission records in {parse_time:.2f} seconds.")

    # 3. Determine output CSV filename
    if args.output:
        csv_path = args.output
    else:
        target_name = os.path.basename(args.input.rstrip("/\\"))
        base_name = os.path.splitext(target_name)[0]
        if not base_name or base_name == "*":
            base_name = "b139"
        csv_path = f"{base_name}_b139_pusch_tx.csv"

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
            print("[!] Warning: No 0xB139 records found to write to CSV.")

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
