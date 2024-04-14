from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

def crear_AESKey():
    """Devuelve un número aleatorio de 16 bytes - 128 bits"""
    return get_random_bytes(16)

<<<<<<< HEAD
"""
En esta librería, AES GCM funciona de la misma forma para el emisor y para el receptor (se utiliza iniciarAES_GCM). 
Esto es así porque las entidades únicamente se intercambian un mensaje.
Sin embargo, si tratásemos de hacer el paso 7 con esta forma de hacer las cosas, ¡tendríamos un error!
¿Por qué? Revisa la documentación de pycryptodome y mira que es realmente el parámetro aes_cifrado.nonce...
"""

def iniciarAES_GCM(key_16):
    """Inicia el engine de cifrado AES CTR"""
    nonce_16 = get_random_bytes(16)
    aes_cifrado = AES.new(key_16, AES.MODE_GCM, nonce = nonce_16, mac_len = 16)
    return aes_cifrado
=======
def iniciarAES_GCM_cifrado(key_16):
    """Inicia el engine de cifrado AES CTR"""
    nonce_16_ini = get_random_bytes(16)
    aes_cifrado = AES.new(key_16, AES.MODE_GCM, nonce = nonce_16_ini, mac_len = 16)
    return aes_cifrado, nonce_16_ini

def iniciarAES_GCM_descifrado(key_16, nonce_16_ini):
    """Inicia el engine de descifrado AES CTR"""
    aes_descifrado = AES.new(key_16, AES.MODE_GCM, nonce = nonce_16_ini, mac_len = 16)
    return aes_descifrado
>>>>>>> 05df069274a2e161a8eb5b611a1e2245ef4c58d1

def cifrarAES_GCM(aes_cifrado, datos):
    """Cifra el parametro datos (de tipo array de bytes), y devuelve el texto cifrado binario Y el mac Y el nonce """
    # En escenarios reales, el objeto AES se inicializa una vez, y luego vamos llamando a aes_cifrado
    datos_cifrado, mac_cifrado = aes_cifrado.encrypt_and_digest(datos)
<<<<<<< HEAD
    return datos_cifrado, mac_cifrado, aes_cifrado.nonce

def descifrarAES_GCM(key_16, nonce_16, datos, mac):
    """Descifra el parametro datos (de tipo binario), y devuelve los datos descrifrados de tipo array de bytes.
       También comprueba si el mac es correcto"""
    try:
        aes_descifrado = AES.new(key_16, AES.MODE_GCM, nonce = nonce_16)
=======
    return datos_cifrado, mac_cifrado

def descifrarAES_GCM(aes_descifrado, datos, mac):
    """Descifra el parametro datos (de tipo binario), y devuelve los datos descrifrados de tipo array de bytes.
       También comprueba si el mac es correcto"""
    try:
>>>>>>> 05df069274a2e161a8eb5b611a1e2245ef4c58d1
        datos_claro = aes_descifrado.decrypt_and_verify(datos, mac)
        return datos_claro
    except (ValueError, KeyError) as e:
        return False
        
<<<<<<< HEAD
"""
Para permitir que se envíen más mensajes en un mismo canal, para los pasos 5-7 utilizaremos esta API.
"""

=======
>>>>>>> 05df069274a2e161a8eb5b611a1e2245ef4c58d1
def iniciarAES_CTR_cifrado(key_16):
    """Inicia el engine de cifrado AES CTR"""
    nonce_16_ini = get_random_bytes(8) # nonce aleatorio de 64 bits
                                       # --64 nonce--|--64 contador--
    ctr_16 = 0                         # contador, empezando desde 0
    aes_cifrado = AES.new(key_16, AES.MODE_CTR, nonce = nonce_16_ini, initial_value = ctr_16)
    return aes_cifrado, nonce_16_ini

def iniciarAES_CTR_descifrado(key_16, nonce_16_ini):
    """Inicia el engine de cifrado AES CTR"""
    ctr_16 = 0                      # contador, empezando desde 0. Origen y destino DEBEN tener este mismo valor
                                    # Si lees esto, piensa: ¿Que problema puede haber en que este valor sea siempre 0 en esta libreria?
    aes_descifrado = AES.new(key_16, AES.MODE_CTR, nonce = nonce_16_ini, initial_value = ctr_16)
    return aes_descifrado

def cifrarAES_CTR(aes_cifrado, datos):
    """Cifra el parametro datos (de tipo array de bytes), y devuelve el texto cifrado binario Y el mac"""
    # En escenarios reales, el objeto AES se inicializa una vez, y luego vamos llamando a aes_cifrado
    datos_cifrado = aes_cifrado.encrypt(datos)
    return datos_cifrado

def descifrarAES_CTR(aes_descifrado, datos):
    """Descifra el parametro datos (de tipo binario), y devuelve los datos descrifrados de tipo array de bytes"""
    datos_claro = aes_descifrado.decrypt(datos)
    return datos_claro