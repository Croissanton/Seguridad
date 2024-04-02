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
jStr = json.dumps(mensaje)

# Cifro el json con K1

jStrCifrado = funciones_aes.cifrarAES_GCM(jStr, K1)

# Aplico HMAC

h = HMAC.new(K2, digestmod=SHA256)
h.update(jStrCifrado)


# Envío el json cifrado junto con el nonce del AES CTR, y el mac del HMAC

socketclient.enviar(jStrCifrado)
socketclient.enviar(nA)
socketclient.enviar(h)


#####################
#####################

# Recibo el mensaje, junto con el nonce del AES CTR, y el mac del HMAC

menRecibido = socketclient.recibir()
nARecibido = socketclient.recibir()
hRecibido = socketclient.recibir()


# Descifro el mensaje

menDescifrado = funciones_aes.descifrarAES_GCM(menRecibido, nARecibido)

# Verifico el mac

h.verify(hRecibido)


# Visualizo la identidad del remitente y compruebo si los campos enviados son los mismo que los recibidos

print(json.loads(menDescifrado))

try:
    h.hexverify(menDescifrado)
    print("El mensaje es auténtico")
except ValueError:
    print("El mensaje no es auténtico")

#####################
#####################

# Intercambio de información NUMERO 1. Al utilizar K1, reutilizo el canal de comunicaciones aes_cifrado

mensaje = []
mensaje.append("Hola Amigos")
mensaje.append(nA.hex())
jStr = json.dumps(mensaje)

jStrCifrado = funciones_aes.cifrarAES_CTR(jStr, K1)

# Aplico HMAC

h = HMAC.new(K2, digestmod=SHA256)
h.update(jStrCifrado)


# Envío el json cifrado junto con el nonce del AES CTR, y el mac del HMAC

socketclient.enviar(jStrCifrado)
socketclient.enviar(nA.hex())
socketclient.enviar(h.hexdigest())


# Intercambio de información NUMERO 2. Al utilizar K1, reutilizo el canal de comunicaciones aes_cifrado

mensaje = []
mensaje.append("Hola Amigas")
mensaje.append(nA.hex())
jStr = json.dumps(mensaje)

jStrCifrado = funciones_aes.cifrarAES_CTR(jStr, K1)

# Aplico HMAC

h = HMAC.new(K2, digestmod=SHA256)
h.update(jStrCifrado)


# Envío el json cifrado junto con el nonce del AES CTR, y el mac del HMAC

socketclient.enviar(jStrCifrado)
socketclient.enviar(nA.hex())
socketclient.enviar(h.hexdigest())


# Cierro el socket
socketclient.cerrar()