#!/usr/bin/env python3
# find_ca_in_oer.py
# Busca hashedId8 i punts EC comprimits dins fitxers .oer
# Requereix: pip install cryptography

import os
import binascii
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# CONFIG: posa aquí els hashedId8 que busques (en hex, 16 caràcters = 8 bytes)
TARGET_HASHES = [
    "ae2d8d9dc6165ddf",
    "0498fbf3b8b8c249"
]

# paràmetres
WINDOW = 256  # bytes al voltant de l'hash per buscar la key prop
MIN_COMPRESSED_POINT_LEN = 1 + 32  # prefix + 32 octets
FILES = [f for f in os.listdir('.') if f.lower().endswith('.oer')]

def find_all_occurrences(bdata, sub):
    offs = []
    start = 0
    while True:
        i = bdata.find(sub, start)
        if i == -1:
            break
        offs.append(i)
        start = i + 1
    return offs

def find_compressed_points(bdata):
    hits = []
    # scan for 0x02 or 0x03 followed by 32 bytes
    for i in range(len(bdata) - 33):
        if bdata[i] in (2,3):
            cand = bdata[i:i+33]
            # quick heuristic: avoid obviously non-random bytes (text). accept all.
            hits.append((i, cand))
    return hits

def try_decode_point(comp_bytes):
    try:
        # cryptography requires encoded point exactly: prefix + 32 octets
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), comp_bytes)
        nums = pub.public_numbers()
        return nums.x, nums.y
    except Exception:
        return None

def dump_window(filename, data, offset, win=256):
    a = max(0, offset - win)
    b = min(len(data), offset + win)
    small = data[a:b]
    outname = f"{filename}_dump_offset_{offset}.bin"
    with open(outname, "wb") as f:
        f.write(small)
    return outname, a, b

def main():
    if not FILES:
        print("No .oer files found in current directory.")
        return

    print(f"Files to scan: {FILES}\nTargets: {TARGET_HASHES}\nWindow (bytes): {WINDOW}\n")

    for fname in FILES:
        print(f"--- Scanning {fname} ---")
        with open(fname, "rb") as f:
            data = f.read()

        # find hashes
        for h in TARGET_HASHES:
            try:
                hbin = binascii.unhexlify(h)
            except Exception as e:
                print(f"Bad hex for target {h}: {e}")
                continue
            locs = find_all_occurrences(data, hbin)
            if locs:
                print(f"Found hashedId8 {h} at offsets: {locs}")
                for off in locs:
                    outname, a, b = dump_window(fname, data, off, win=WINDOW)
                    print(f"  -> dumped window [{a}:{b}] to {outname}")
            else:
                print(f"HashedId8 {h} NOT found in {fname}")

        # find compressed points
        comps = find_compressed_points(data)
        print(f"Found {len(comps)} compressed-point-like candidates in {fname}")
        # show only points near any target or top N
        nearby = []
        for (off, cand) in comps:
            # if any target within WINDOW
            near = False
            for h in TARGET_HASHES:
                hbin = binascii.unhexlify(h)
                if any(abs(off - loc) <= WINDOW for loc in find_all_occurrences(data, hbin)):
                    near = True
                    break
            if near:
                nearby.append((off, cand))
        # Print summary for nearby candidates (prefer these)
        if nearby:
            print(f"Candidates near target hashes (<= {WINDOW} bytes): {len(nearby)}")
            for off, cand in nearby:
                hexs = binascii.hexlify(cand).decode()
                print(f"  offset {off} : prefix {cand[0]:02x} : {hexs}")
                # try decode to (x,y)
                dec = try_decode_point(cand)
                if dec:
                    x,y = dec
                    print(f"    -> valid P-256 point. x={hex(x)} y={hex(y)}")
                else:
                    print("    -> not a valid EC point (or not P-256).")
        else:
            print("No compressed-point candidates found near target hashes (try increasing WINDOW).")

        # Also print first 10 compressed points as extras (if no nearby found)
        if not nearby:
            sample = comps[:30]
            for off, cand in sample:
                hexs = binascii.hexlify(cand).decode()
                dec = try_decode_point(cand)
                if dec:
                    x,y = dec
                    ok = f"valid (x={hex(x)})"
                else:
                    ok = "invalid"
                print(f"  offset {off} : prefix {cand[0]:02x} : {hexs}  => {ok}")

    print("\nDone. Check dumped .bin windows and candidate public keys above.")
if __name__ == "__main__":
    main()
