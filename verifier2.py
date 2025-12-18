# verify_packet73.py
# pip install cryptography

import binascii, hashlib, sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes

# ------------------ VALORS del paquet 73 (proporcionats per tu) ------------------
tbs_hex = (
    "40038082018120400180014d03000099000014005a82c3416059156484fd1d0b1166"
    "058e0a5b82780a901d0b0f2d058e124e03e800000000000007d200000201c3416059"
    "c761a0b02c87699422ac816b2508ab205d6d2aff82d70d7e44e65164c2a920058a880"
    "0f014100803000053137e882fe69c098ac6700b4b7e952084f6338015fbf7ad03dd3"
    "1380079dfcbb823c98ce003defefac1446c4e002277f76e0b8162700154bfe5103de3"
    "19c007d600b48124589c002bf00e1406f2c800014980eea037a627000e2c088100e83"
    "1380091e04a07ff1189c0366f01aabfc46c670015981131faea633800b6c09d8fbb93"
    "138005de043d7d8a18ce0027f01e4bebc4c670010f80e75f5776338007bc070cfac43"
    "19c0039e039a7d67989c001bf01d9beb8ac67000d780f6df5fe6338006fc085afb0eb"
    "19c0037e047c7d9758ce001bf02523ecbac67000df812a9f67b6338006fc09a6fb60b"
    "19c0037e04e47dc158ce001bf02943ee12c67000df814f9f78f6338006fc0acafbecb"
    "19c0035e05b87df1d8ce001bc05001250002753b90a7d4281d0b1166058e0a5b0c2c"
)

# signature components reported in Frame 73. (r printed as "compressed-y-1" by Wireshark)
r_comp_hex = "04e042759ce7fbbe26d03f5f3e795cbc6aa2b39f2996a3669df639d525a0626b"
s_comp_hex = "177a428ae753c72239ce93d12ae3aee3db96e974e14a33edbb45740c2cff1eac"

# certificate field (the certificate bytes copied with Copy->Bytes->HexStream from Item 0)
# Use the hex string you extracted; below is the one you provided earlier (packet 73).
cert_hex = (
    "80030080ae2d8d9dc6165ddf10830000000000293af3358400a80102800124810403"
    "01000080012581050401901a258080826c01f9769e4af84cf77999de3aba97f5da33"
    "2da674ed8894b25d473f08d74ece8080eda019dba37727f1ed2c0d8541cedf457022"
    "e55e4f9f6b7d6475b1c1b889a99f5f811a7478cbcfff5d28309aacc7630f7ab6abc1"
    "bbc4888a507dc23bfee16aed"
)

# public key X coordinate from the certificate's compressed point (verifyKeyIndicator)
pub_com_hex = "6c01f9769e4af84cf77999de3aba97f5da332da674ed8894b25d473f08d74ece"
# ------------------------------------------------------------------------------

def hex2bytes(h):
    return binascii.unhexlify(h.strip().replace(" ", "").replace("\n", ""))

def try_reconstruct_pubkey(pub_com):
    """Try reconstructing EC public key trying both compressed prefixes 02 and 03."""
    for prefix in (b'\x02', b'\x03'):
        try:
            pb = prefix + pub_com
            pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pb)
            nums = pk.public_numbers()
            print(f"Public key reconstructed with prefix 0x{prefix.hex()}: Q.x={hex(nums.x)} Q.y={hex(nums.y)}")
            return pk, prefix
        except Exception as e:
            # continue trying other prefix
            # print("prefix", prefix.hex(), "failed:", e)
            pass
    return None, None

def try_reconstruct_r(r_raw):
    """
    Try several strategies to obtain r as integer:
    - If r_raw length == 33 and startswith 0x04: strip leading 0x04 and take int
    - If len == 32: try treat as x coordinate of compressed point with prefix 02/03 to extract R.x
    - Fallback: treat raw as integer directly
    """
    candidates = []

    # direct integer
    try:
        candidates.append(("raw_int", int(binascii.hexlify(r_raw), 16)))
    except Exception:
        pass

    # if looks like 0x04 + 32 bytes (uncompressed-like single-byte prefix), strip it
    if len(r_raw) == 33 and r_raw[0] == 0x04:
        try:
            xr = r_raw[1:]
            candidates.append(("strip_04_then_int", int(binascii.hexlify(xr), 16)))
        except Exception:
            pass

    # try interpreting as compressed point x with prefix 02/03
    if len(r_raw) == 32:
        for pref in (b'\x02', b'\x03'):
            try:
                Rcand = pref + r_raw
                Rpub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), Rcand)
                r_x = Rpub.public_numbers().x
                candidates.append((f"point_pref_{pref.hex()}", r_x))
            except Exception:
                candidates.append((f"point_pref_{pref.hex()}_failed", None))

    # unique-ify preserving order
    uniq = []
    seen = set()
    for name, val in candidates:
        if val is None: continue
        if val in seen: continue
        uniq.append((name, val))
        seen.add(val)
    return uniq

def verify_all():
    tbs = hex2bytes(tbs_hex)
    r_raw = hex2bytes(r_comp_hex)
    s_int = int(s_comp_hex, 16)
    cert_der = hex2bytes(cert_hex)
    pub_com = hex2bytes(pub_com_hex)

    print("Lengths (bytes): tbs =", len(tbs), " cert_der =", len(cert_der), " pub_com =", len(pub_com))
    print("sha256(tbs) =", hashlib.sha256(tbs).hexdigest())
    print("sha256(cert_der) =", hashlib.sha256(cert_der).hexdigest())

    # rebuild public key:
    pubkey, used_prefix = try_reconstruct_pubkey(pub_com)
    if pubkey is None:
        print("Could not reconstruct public key from given pub_com (tried prefixes 02/03).")
        return False

    # Build hd and hs and message (per IEEE 1609.2)
    hd = hashlib.sha256(tbs).digest()
    hs = hashlib.sha256(cert_der).digest()
    message = hd + hs
    print("len(message) =", len(message), "sha256(message) =", hashlib.sha256(message).hexdigest())

    # Get candidate r integers
    r_cands = try_reconstruct_r(r_raw)
    print("\nCandidate r values:")
    for nm, rv in r_cands:
        print(" ", nm, hex(rv))

    from cryptography.hazmat.primitives import hashes
    verified = False
    for r_name, r_int in r_cands:
        der_sig = encode_dss_signature(r_int, s_int)
        try:
            # Try verify using standard ECDSA with SHA256 (cryptography will hash message)
            pubkey.verify(der_sig, message, ec.ECDSA(hashes.SHA256()))
            print("\n=> SIGNATURE VERIFIED using r_variant =", r_name, "and pub_prefix=0x" + used_prefix.hex())
            verified = True
            break
        except Exception as e:
            print("Try failed with r_variant =", r_name, " error:", str(e))
    if not verified:
        print("\nSignature could NOT be verified with any candidate r / pub prefix combination.")
    return verified

if __name__ == "__main__":
    ok = verify_all()
    if not ok:
        print("\n--- RESULT: NOT VERIFIED ---")
        print("If this fails, the most common causes are:")
        print("  - tbs_hex not exactly the raw bytes used to sign (copy with 'Copy->Bytes->Hex Stream' on tbsData).")
        print("  - cert_hex not the raw certificate bytes (copy Item 0 -> Copy->Bytes->Hex Stream).")
        print("  - r_comp_hex format: Wireshark sometimes prints '04'+x; script tries variants but verify data must be exact.")
        print("  - signature might actually be invalid.")
        print("\nIf you want, run again after re-copying tbs and cert exactly as 'Bytes -> Hex Stream' and paste here.")
