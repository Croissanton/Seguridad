from RSA import *

# Cargamos la clave privada de Bob
keyB = cargar_RSAKey_Privada("privadaB.pem", "password")

# Cargamos la clave pública de Alice
keyA = cargar_RSAKey_Publica("publicaA.pub")

# Bob recibe un mensaje de Alice, cifrado con la clave pública de Bob
f = open("mensaje.txt", "rb")
cifrado = f.read(256)
firma = f.read()
f.close()
mensaje = descifrarRSA_OAEP(cifrado, keyB)
print("Mensaje descifrado: ", mensaje)
print("Firma correcta: ", comprobarRSA_PSS(mensaje, firma, keyA))