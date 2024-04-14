import funciones_rsa
import funciones_aes
from socket_class import SOCKET_SIMPLE_TCP
from Crypto.Hash import HMAC, SHA256
import json

# Cargo la clave pública de Alice y la clave privada de Bob
Pub_A = funciones_rsa.cargar_RSAKey_Publica("rsa_alice.pub")
Pri_B = funciones_rsa.cargar_RSAKey_Privada("rsa_bob.pem", "bob")

# Creamos el servidor para Bob y recibimos las claves y la firma
socketserver = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socketserver.escuchar()

K1_cif = socketserver.recibir()
K2_cif = socketserver.recibir()
K1K2_fir = socketserver.recibir()

# Descifro las claves K1 y K2 con Pri_B
K1 = funciones_rsa.descifrarRSA_OAEP_BIN(K1_cif, Pri_B)
K2 = funciones_rsa.descifrarRSA_OAEP_BIN(K2_cif, Pri_B)

# Compruebo la validez de la firma con Pub_A
if funciones_rsa.comprobarRSA_PSS(K1+K2,K1K2_fir,Pub_A):
    print("Firma de K1||K2 válida")
else:
    print("Firma de K1||K2 NO válida")

#####################
#####################

# Recibo el mensaje, junto con el nonce del AES CTR, y el mac del HMAC
<<<<<<< HEAD

mensaje_cifrado = socketserver.recibir()
nA_recibido = socketserver.recibir()
mac_recibido = socketserver.recibir()

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

# Visualizo la identidad del remitente

mensaje_json = json.loads(mensaje_descifrado.decode("utf-8"))
print("El remitente es " + mensaje_json[0])
print("El nonce nA es " + mensaje_json[1])
=======
    
    mensaje_cif = socketserver.recibir()
    nA = socketserver.recibir()
    nA = bytearray.fromhex(nA)
    mac = socketserver.recibir()

# Descifro el mensaje
    
    mensaje = funciones_aes.descifrarAES_CTR(mensaje_cif, K1, nA)

# Verifico el mac
    
    h = HMAC.new(K2, digestmod=SHA256)
    h.update(mensaje)
    try:
        h.hexverify(mac)
        print("MAC correcto")
    except ValueError:
        print("MAC incorrecto")

# Visualizo la identidad del remitente
        
        print(json.loads(mensaje)[0])
>>>>>>> 05df069274a2e161a8eb5b611a1e2245ef4c58d1

#####################
#####################

# Genero el json con el nombre de Bob, el de Alice y el nonce nA
<<<<<<< HEAD

mensaje = []
mensaje.append("Bob")
mensaje.append("Alice")
mensaje.append(nA_recibido.hex())
json_mensaje = json.dumps(mensaje)

# Cifro el json con K1

aes_cifrado = funciones_aes.iniciarAES_CTR_cifrado(K1)
mensaje_cifrado = funciones_aes.cifrarAES_CTR(aes_cifrado, json_mensaje.encode("utf-8"))

# Aplico HMAC

hmac = HMAC.new(K2, digestmod=SHA256)
hmac.update(mensaje_cifrado)

# Envío el json cifrado junto con el nonce del AES CTR, y el mac del HMAC

socketserver.enviar(mensaje_cifrado)
socketserver.enviar(nA_recibido)
socketserver.enviar(hmac.digest())
=======
        
    jStr = json.dumps(["Bob","Alice",nA.hex()])

# Cifro el json con K1
    
    mensaje_cif = funciones_aes.cifrarAES_CTR(jStr, K1, nA)

# Aplico HMAC
    
    h = HMAC.new(K2, digestmod=SHA256)
    h.update(jStr)

# Envío el json cifrado junto con el nonce del AES CTR, y el mac del HMAC
    
    socketserver.enviar(mensaje_cif)
    socketserver.enviar(nA)
    socketserver.enviar(h.hexdigest())
>>>>>>> 05df069274a2e161a8eb5b611a1e2245ef4c58d1

#####################
#####################

# Recibo el primer mensaje de Alice
<<<<<<< HEAD

mensaje_cifrado = socketserver.recibir()
nA_recibido = socketserver.recibir()
mac_recibido = socketserver.recibir()

# Descifro el mensaje

# aes_descifrado = funciones_aes.iniciarAES_CTR_descifrado(K1, nA_recibido)
mensaje_descifrado = funciones_aes.descifrarAES_CTR(aes_descifrado, mensaje_cifrado)


# Verifico el mac

hmac = HMAC.new(K2, digestmod=SHA256)
hmac.update(mensaje_cifrado)
try:
    hmac.verify(mac_recibido)
    print("El mensaje es auténtico")
except ValueError:
    print("El mensaje no es auténtico")

# Muestro el mensaje

mensaje_json = json.loads(mensaje_descifrado.decode("utf-8"))
print("El mensaje es" + mensaje_json[0])
# print("El destinatario es " + mensaje_json[1])
# print("El nonce nA es " + mensaje_json[2])


# Recibo el segundo mensaje de Alice

mensaje_cifrado = socketserver.recibir()
nA_recibido = socketserver.recibir()
mac_recibido = socketserver.recibir()

# Descifro el mensaje

# aes_descifrado = funciones_aes.iniciarAES_CTR_descifrado(K1, nA_recibido)
mensaje_descifrado = funciones_aes.descifrarAES_CTR(aes_descifrado, mensaje_cifrado)


# Verifico el mac

hmac = HMAC.new(K2, digestmod=SHA256)
hmac.update(mensaje_cifrado)
try:
    hmac.verify(mac_recibido)
    print("El mensaje es auténtico")
except ValueError:
    print("El mensaje no es auténtico")

# Muestro el mensaje

mensaje_json = json.loads(mensaje_descifrado.decode("utf-8"))
print("El remitente es " + mensaje_json[0])
# print("El destinatario es " + mensaje_json[1])
# print("El nonce nA es " + mensaje_json[2])
=======
    
    mensaje_cif = socketserver.recibir()
    nA = socketserver.recibir()
    nA = bytearray.fromhex(nA)
    mac = socketserver.recibir()

# Descifro el mensaje
        
    mensaje = funciones_aes.descifrarAES_CTR(mensaje_cif, K1, nA)


# Verifico el mac
        
    h = HMAC.new(K2, digestmod=SHA256)
    h.update(mensaje)
    try:
        h.hexverify(mac)
        print("MAC correcto")
    except ValueError:
        print("MAC incorrecto")

# Muestro el mensaje
            
    print(json.loads(mensaje)[0])


# Recibo el segundo mensaje de Alice
    
    mensaje_cif = socketserver.recibir()
    nA = socketserver.recibir()
    nA = bytearray.fromhex(nA)
    mac = socketserver.recibir()

# Descifro el mensaje

    mensaje = funciones_aes.descifrarAES_CTR(mensaje_cif, K1, nA)


# Verifico el mac
    
    h = HMAC.new(K2, digestmod=SHA256)
    h.update(mensaje)
    try:
        h.hexverify(mac)
        print("MAC correcto")
    except ValueError:
        print("MAC incorrecto")

# Muestro el mensaje
            
    print(json.loads(mensaje)[0])
>>>>>>> 05df069274a2e161a8eb5b611a1e2245ef4c58d1


# Cierro el socket
socketserver.cerrar()
