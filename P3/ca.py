from RSA import *

# Creamos una clave RSA para Alice
keyA = crear_RSAKey()

# Guardamos la claves RSA de Alice (pública y privada)
guardar_RSAKey_Publica("publicaA.pub", keyA)
guardar_RSAKey_Privada("privadaA.pem", keyA, "password")

# Creamos una clave RSA para Bob
keyB = crear_RSAKey()

# Guardamos la claves RSA de Bob (pública y privada)
guardar_RSAKey_Publica("publicaB.pub", keyB)
guardar_RSAKey_Privada("privadaB.pem", keyB, "password")