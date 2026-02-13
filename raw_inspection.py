text_data = ""

with open("B78E9AF02C26C465.oer", "rb") as f:
    oer_data = f.read()

for byte in oer_data:
    if 32 <= byte <= 126:   # ASCII imprimible
        text_data += chr(byte)
    else:
        text_data += "."

print(text_data)
