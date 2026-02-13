import asn1tools
import binascii

# 1. Leer el archivo
file_path = 'B78E9AF02C26C465.oer'
with open(file_path, 'rb') as f:
    oer_data = f.read()

print(f"Tamaño del archivo: {len(oer_data)} bytes")
print("Primeros 100 bytes en hex:")
print(binascii.hexlify(oer_data[:100]).decode('ascii'))

# 2. Intentar crear un parser genérico (sin schema específico)
# asn1tools necesita un schema, pero podemos intentar uno básico
try:
    schema = """
    MyModule DEFINITIONS ::= BEGIN
        MyData ::= SEQUENCE {
            header BIT STRING,
            data OCTET STRING
        }
    END
    """
    compiled = asn1tools.compile_string(schema, codec='oer')
    
    # Intentar decodificar
    decoded = compiled.decode('MyData', oer_data)
    print("\nDecodificación exitosa con schema básico:")
    print(decoded)
    
except Exception as e:
    print(f"\nError con schema básico: {e}")
    
    # Mostrar más del contenido para análisis
    print("\nBuscando texto en el archivo...")
    text_data = ""
    for byte in oer_data:
        if 32 <= byte <= 126:  # Caracteres ASCII imprimibles
            text_data += chr(byte)
        elif len(text_data) > 3:  # Mostrar secuencias de texto
            if "http" in text_data or "://" in text_data or "CA" in text_data:
                print(f"Texto encontrado: {text_data}")
            text_data = ""