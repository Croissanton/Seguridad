from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
# Ver https://pycryptodome.readthedocs.io/en/latest/src/public_key/ecc.html
# Ver https://pycryptodome.readthedocs.io/en/latest/src/signature/dsa.html  
def crear_ECCKey():
    # Use 'NIST P‐256'
    key = ECC.generate(curve='P‐256')
    return key
def guardar_ECCKey_Privada(fichero, key, password):
    key_cifrada = key.export_key(passphrase=password, protection="PBKDF2WithHMAC-SHA512AndAES256-CBC")
    file_out = open(fichero, "wb")
    file_out.write(key_cifrada)
    file_out.close()

def cargar_ECCKey_Privada(fichero, password):
    key_cifrada = open(fichero, "rb").read()
    key = ECC.import_key(key_cifrada, passphrase=password)
    return key

def guardar_ECCKey_Publica(fichero, key):
    key_pub = key.public_key().export_key()
    file_out = open(fichero, "wb")
    file_out.write(key_pub)
    file_out.close()

def cargar_ECCKey_Publica(fichero):
    keyFile = open(fichero, "rb").read()
    key_pub = ECC.import_key(keyFile)

    return key_pub
# def cifrarECC_OAEP(cadena, key):
    # El cifrado con ECC (ECIES) aun no está implementado
    # Por lo tanto, no se puede implementar este método aun en la versión 3.9.7  
    # return cifrado
# def descifrarECC_OAEP(cifrado, key):
    # El cifrado con ECC (ECIES) aun no está implementado
    # Por lo tanto, no se puede implementar este método aun en la versión 3.9.7  
    # return cadena
def firmarECC_PSS(texto, key_private):
    # La firma se realiza sobre el hash del texto (h)
    h = SHA256.new(texto.encode("utf‐8"))
    signature = DSS.new(key_private, 'fips‐186‐3').sign(h)
    return signature

def comprobarECC_PSS(texto, firma, key_public):
    # Comprobamos que la firma coincide con el hash (h)
    h = SHA256.new(texto.encode("utf‐8"))
    verifier = DSS.new(key_public, 'fips‐186‐3')
    try:
        verifier.verify(h, firma)
        return True
    except (ValueError, TypeError):
        return False