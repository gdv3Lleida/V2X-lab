from cryptography.hazmat.primitives.asymmetric import ec

FILE_PATH = "B78E9AF02C26C465.oer"

with open(FILE_PATH, "rb") as f:
    data = f.read()

print(f"File length: {len(data)} bytes")

found = False

# Scan byte-by-byte
for i in range(len(data) - 33):
    prefix = data[i]
    
    # Only valid compressed ECC prefixes
    if prefix not in (0x02, 0x03):
        continue

    x_bytes = data[i+1:i+33]

    try:
        # Try to reconstruct EC public key
        encoded = bytes([prefix]) + x_bytes
        pk = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), encoded
        )

        numbers = pk.public_numbers()
        print("\n Valid ECC P-256 public key found")
        print(f"Offset: {i}")
        print(f"Prefix: 0x{prefix:02x}")
        print(f"X = {numbers.x:#x}")
        print(f"Y = {numbers.y:#x}")
        found = True

    except Exception:
        # Not a real EC point
        pass

if not found:
    print("\nNo valid ECC P-256 public key found in file")
