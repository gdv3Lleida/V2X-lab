# verifier_quick_check.py
# pip install cryptography

import binascii, hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes

# --------- Posa aquí els valors que has copiat ----------
tbs_hex     = "40038082016720400180013303000087000014007285c37226b78e0da6201d0d477d058e5e2d839604221d0d54be058e209703e800000000000007d200000201c37226b7c761b9135bee7a1391c1ae60e4e4706b9a452b23dbe70d7f29711a1162fd1fff4a8800f014100803079259108387700dcbf0fcc4e0013780a81f4e9627000ebc0528fa57b1380077e02887d2ed89c003af013f3e996c4e001df80a71f4c76270010bc0520fa643138008de02827d2d189c0047f013ebe994c670024780a55f4d762700137c052cfa6031380091e029a7d30589c0043f012f3e93cc4e001f7802c9f42d627000dbc00a2fa1f319c0069e00167d06d89c0031effee3e880c67001777ff85f418633800dfbff9efc1a319c0057dfed37f2658ce0016efee03fac0c67000c77e235fc91627000ffbf0c4fe80319c0073df85e7f3e989c003aefc3ebf9d0c4e001e37e185fcde63380111bf0defe7f319c00abdf8697f35989c0217efc3abf974c4e0026605001250002638ae55175ce1d0d477d058e5e2d0c54"
r_comp_hex  = "b223cdec3b081aa385bc056fd78b566653aa11b5f3b2675ab6ae1f2d392005ab"
s_comp_hex  = "a3b7e8d7794eba79ab8ecf681d361d10540de4ebd934237a9d25c8e93b0a9be9"
cert_hex    = "80030080ae2d8d9dc6165ddf108300000000002813a3358400a8010280012481040301000080012581050401901a25808083f2b6dcbb166fef5467baf0a9c98053043218f4522364a31c0b75ec704c7c1b1d8080b64f0cee38568533010f53de53ba8440b2664adc3266e4a4c90a36433bf939ff5395ac392237ebc9ffeb7c5cdbe4ead17e097f10df32f501a8233cd6519741c5"
pub_com_hex = "f2b6dcbb166fef5467baf0a9c98053043218f4522364a31c0b75ec704c7c1b1d"
# --------------------------------------------------------

# Convert hex to bytes
tbs = binascii.unhexlify(tbs_hex)
r_comp = binascii.unhexlify(r_comp_hex)
s_int = int(s_comp_hex, 16)
cert_der = binascii.unhexlify(cert_hex)
pub_com = binascii.unhexlify(pub_com_hex)

print("Lengths (bytes): tbs =", len(tbs), " cert_der =", len(cert_der))
print("sha256(tbs) =", hashlib.sha256(tbs).hexdigest())
print("sha256(cert_der) =", hashlib.sha256(cert_der).hexdigest())
print("r_comp hex:", r_comp_hex)
print("s hex:", s_comp_hex)
print("pub_com hex:", pub_com_hex)

# Reconstruct public key from compressed form
# Wireshark said compressed-y-1 -> use prefix 0x03 (y is odd)
pub_prefix = b'\x03'  # prova \x02 si Wireshark diu compressed-y-0
pub_bytes = pub_prefix + pub_com

try:
    pubkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)
    nums = pubkey.public_numbers()
    print("\nReconstructed public key coordinates:")
    print(" Q.x =", hex(nums.x))
    print(" Q.y =", hex(nums.y))
except Exception as e:
    print("\nError reconstructing public key:", e)
    # prova amb prefix 0x02 si \x03 falla
    try:
        pub_bytes2 = b'\x02' + pub_com
        pubkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes2)
        nums = pubkey.public_numbers()
        print("Reconstructed with prefix 0x02:")
        print(" Q.x =", hex(nums.x))
        print(" Q.y =", hex(nums.y))
    except Exception as e2:
        print("Also failed with prefix 0x02:", e2)
        raise SystemExit(1)

# Construct R from compressed r_comp (Wireshark reported compressed-y-0)
R_prefix = b'\x02'   # segons Wireshark: compressed-y-0 -> 0x02
R_bytes = R_prefix + r_comp
try:
    Rpub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), R_bytes)
    Rnums = Rpub.public_numbers()
    r_int = Rnums.x
    print("\nR point reconstructed. r (x) =", hex(r_int))
except Exception as e:
    print("\nError reconstructing R point:", e)
    # també provem a interpretar r_comp com integer directe:
    try:
        r_int = int(r_comp_hex, 16)
        print("Treated r_comp as integer:", hex(r_int))
    except Exception as e2:
        print("Cannot interpret r in any way:", e2)
        raise SystemExit(1)

# Build message = SHA256(tbs) || SHA256(cert_der)
hd = hashlib.sha256(tbs).digest()
hs = hashlib.sha256(cert_der).digest()
message = hd + hs
print("\nlen(message) =", len(message), "sha256(message) =", hashlib.sha256(message).hexdigest())

# Encode signature as DER and verify
der_sig = encode_dss_signature(r_int, s_int)

try:
    pubkey.verify(der_sig, message, ec.ECDSA(hashes.SHA256()))
    print("\nSignature VALID ✅")
except Exception as e:
    print("\nSignature verification FAILED ❌. Error:", e)
    print("Possible causes: wrong tbs bytes, wrong cert_hex canonicalization, wrong pub prefix, or r unpacking.")
