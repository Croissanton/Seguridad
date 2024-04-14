import funciones_rsa
import funciones_aes
from socket_class import SOCKET_SIMPLE_TCP
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import json

# Cargo la clave pública de Bob y la clave privada de Alice
Pub_B = funciones_rsa.cargar_RSAKey_Publica("rsa_bob.pub")
Pri_A = funciones_rsa.cargar_RSAKey_Privada("rsa_alice.pem", "alice")

# Genero las dos claves
K1 = funciones_aes.crear_AESKey()
K2 = funciones_aes.crear_AESKey()



# Cifro K1 y K2 con Pub_B
K1_cif = funciones_rsa.cifrarRSA_OAEP_BIN(K1, Pub_B)
K2_cif = funciones_rsa.cifrarRSA_OAEP_BIN(K2, Pub_B)

# Firmo la concatenación de K1 y K2 con Pri_A
K1K2_fir = funciones_rsa.firmarRSA_PSS(K1 + K2, Pri_A)

# Conectamos con el servidor y enviamos a Bob a través del socket
socketclient = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socketclient.conectar()

socketclient.enviar(K1_cif)
socketclient.enviar(K2_cif)
socketclient.enviar(K1K2_fir)


#####################
#####################

# Genero el json con el nombre de Alice y un nonce nA

nA = funciones_aes.crear_AESKey()

mensaje = []
mensaje.append("Alice")
mensaje.append(nA.hex())
json_mensaje = json.dumps(mensaje)


# Cifro el json con K1

aes_cifrado = funciones_aes.iniciarAES_CTR_cifrado(K1)
cifrado = funciones_aes.cifrarAES_CTR(aes_cifrado, json_mensaje.encode("utf-8"))


# Aplico HMAC

hmac = HMAC.new(K2, digestmod=SHA256)
hmac.update(cifrado)


# Envío el json cifrado junto con el nonce del AES CTR, y el mac del HMAC

socketclient.enviar(cifrado)
socketclient.enviar(nA)
socketclient.enviar(hmac.digest())


#####################
#####################

# Recibo el mensaje, junto con el nonce del AES CTR, y el mac del HMAC

mensaje_cifrado = socketclient.recibir()
nA_recibido = socketclient.recibir()
mac_recibido = socketclient.recibir()


# Descifro el mensaje

aes_descifrado = funciones_aes.iniciarAES_CTR_descifrado(K1, nA_recibido)
mensaje_descifrado = funciones_aes.descifrarAES_CTR(aes_descifrado, mensaje_cifrado)

# Verifico el mac

hmac = HMAC.new(K2, digestmod=SHA256)
hmac.update(mensaje_cifrado)
try:
    hmac.verify(mac_recibido)
    print("El mensaje es auténtico")
except ValueError:
    print("El mensaje no es auténtico")


# Visualizo la identidad del remitente y compruebo si los campos enviados son los mismo que los recibidos

mensaje_recibido = json.loads(mensaje_descifrado.decode("utf-8"))
if mensaje_recibido[0] == "Alice" and mensaje_recibido[1] == "Bob" and mensaje_recibido[2] == nA.hex():
    print("El mensaje es correcto")
else:
    print("El mensaje no es correcto")

print("El mensaje recibido es: ", mensaje_recibido)

#####################
#####################

# Intercambio de información NUMERO 1. Al utilizar K1, reutilizo el canal de comunicaciones aes_cifrado

mensaje = []
#mensaje.append("Alice")
mensaje.append("Hola Amigos")
json_mensaje = json.dumps(mensaje)

# aes_cifrado = funciones_aes.iniciarAES_CTR_cifrado(K1)
cifrado = funciones_aes.cifrarAES_CTR(aes_cifrado, json_mensaje.encode("utf-8"))

# Aplico HMAC

hmac = HMAC.new(K2, digestmod=SHA256)
hmac.update(cifrado)


# Envío el json cifrado junto con el nonce del AES CTR, y el mac del HMAC

socketclient.enviar(cifrado)
socketclient.enviar(nA.hex())
socketclient.enviar(hmac.digest())


# Intercambio de información NUMERO 2. Al utilizar K1, reutilizo el canal de comunicaciones aes_cifrado

mensaje = []
#mensaje.append("Alice")
mensaje.append("Hola Amigas")
json_mensaje = json.dumps(mensaje)

# aes_cifrado = funciones_aes.iniciarAES_CTR_cifrado(K1)
cifrado = funciones_aes.cifrarAES_CTR(aes_cifrado, json_mensaje.encode("utf-8"))


# Aplico HMAC

hmac = HMAC.new(K2, digestmod=SHA256)
hmac.update(cifrado)


# Envío el json cifrado junto con el nonce del AES CTR, y el mac del HMAC

socketclient.enviar(cifrado)
socketclient.enviar(nA.hex())
socketclient.enviar(hmac.digest())


# Cierro el socket
socketclient.cerrar()