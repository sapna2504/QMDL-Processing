import re
import argparse

ap = argparse.ArgumentParser(description="Parse raw into raw_packets")
ap.add_argument("input", nargs="?", help="input text file")
ap.add_argument("output", nargs="?", help="output text file ")
args = ap.parse_args()

capture = False
payload = []

with open(args.input, "r") as f, open(args.output, "w") as out:
    for line in f:
        if ("Not parsing DIAG log item 0xb887" in line) or ("Not parsing DIAG log item 0xb881" in line):
            capture = True
            payload = []
            continue

        if capture and "-------- end --------" in line:
            out.write(" ".join(payload) + "\n")
            capture = False
            continue
        
        if capture:
            hex_part = line.split('\t')[0]
            bytes_found = re.findall(r'\b[0-9a-fA-F]{2}\b', hex_part)
            payload.extend(bytes_found)
