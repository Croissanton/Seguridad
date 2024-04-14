from RSA import *

# Cargamos la clave privada de Alice
keyA = cargar_RSAKey_Privada("privadaA.pem", "password")

# Cargamos la clave pública de Bob
keyB = cargar_RSAKey_Publica("publicaB.pub")

# Alice envía un mensaje a Bob, cifrado con la clave pública de Bob
mensaje = "Hola amigos de la seguridad"
cifrado = cifrarRSA_OAEP(mensaje, keyB)

#Firmamos el mensaje con la clave privada de Alice
firmado = firmarRSA_PSS(mensaje, keyA)

#Guardamos el mensaje cifrado y firmado en un fichero mensaje.txt
f = open("mensaje.txt", "wb")
f.write(cifrado)
f.write(firmado)
f.close()
