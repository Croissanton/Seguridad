#Cristian Ruiz Martín

from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Util import Counter
# Datos necesarios
key = get_random_bytes(16) # Clave aleatoria de 128 bits
IV = get_random_bytes(16)  # IV aleatorio de 128 bits para CBC
BLOCK_SIZE_AES = 16 # Bloque de 128 bits
data = "Hola amigos de la seguridad".encode("utf‐8") # Datos a cifrar
print(data)
# CIFRADO #######################################################################
# Creamos un mecanismo de cifrado AES en modo CBC con un vector de inicialización IV
cipherCBC = AES.new(key, AES.MODE_CBC, IV)
cipherECB = AES.new(key, AES.MODE_ECB)
cipherCTR = AES.new(nonce=get_random_bytes(BLOCK_SIZE_AES//2), key=key, mode=AES.MODE_CTR)
cipherOFB = AES.new(key, AES.MODE_OFB, IV)
cipherCFB = AES.new(key, AES.MODE_CFB, IV)
cipherGCM = AES.new(nonce=get_random_bytes(BLOCK_SIZE_AES), mac_len=16, key=key, mode=AES.MODE_GCM)


# Ciframos, haciendo que la variable “data” sea múltiplo del tamaño de bloque
ciphertextCBC = cipherCBC.encrypt(pad(data,BLOCK_SIZE_AES))
ciphertextECB = cipherECB.encrypt(pad(data,BLOCK_SIZE_AES))
ciphertextCTR = cipherCTR.encrypt(pad(data,BLOCK_SIZE_AES))
ciphertextOFB = cipherOFB.encrypt(pad(data,BLOCK_SIZE_AES))
ciphertextCFB = cipherCFB.encrypt(pad(data,BLOCK_SIZE_AES))
ciphertextGCM = cipherGCM.encrypt(pad(data,BLOCK_SIZE_AES))

print(ciphertextCBC)
print(ciphertextECB)
print(ciphertextCTR)
print(ciphertextOFB)
print(ciphertextCFB)
print(ciphertextGCM)
# DESCIFRADO #######################################################################
# Creamos un mecanismo de (des)cifrado AES en modo CBC con un vector de inicialización IV para CBC
# Ambos, cifrado y descifrado, se crean de la misma forma
decipher_AES_CBC = AES.new(key, AES.MODE_CBC, IV)
decipher_AES_ECB = AES.new(key, AES.MODE_ECB)
decipher_AES_CTR = AES.new(key, AES.MODE_CTR, nonce=cipherCTR.nonce)
decipher_AES_OFB = AES.new(key, AES.MODE_OFB, IV)
decipher_AES_CFB = AES.new(key, AES.MODE_CFB, IV)
decipher_AES_GCM = AES.new(key, AES.MODE_GCM, nonce=cipherGCM.nonce, mac_len=16)
# Desciframos, eliminamos el padding, y recuperamos la cadena
new_dataCBC = unpad(decipher_AES_CBC.decrypt(ciphertextCBC), BLOCK_SIZE_AES).decode("utf‐8","ignore")
new_dataECB = unpad(decipher_AES_ECB.decrypt(ciphertextECB), BLOCK_SIZE_AES).decode("utf‐8","ignore")
new_dataCTR = unpad(decipher_AES_CTR.decrypt(ciphertextCTR), BLOCK_SIZE_AES).decode("utf‐8","ignore")
new_dataOFB = unpad(decipher_AES_OFB.decrypt(ciphertextOFB), BLOCK_SIZE_AES).decode("utf‐8","ignore")
new_dataCFB = unpad(decipher_AES_CFB.decrypt(ciphertextCFB), BLOCK_SIZE_AES).decode("utf‐8","ignore")
new_dataGCM = unpad(decipher_AES_GCM.decrypt(ciphertextGCM), BLOCK_SIZE_AES).decode("utf‐8","ignore")
# Imprimimos los datos descifrados
print(new_dataCBC)
print(new_dataECB)
print(new_dataCTR)
print(new_dataOFB)
print(new_dataCFB)
print(new_dataGCM)

#EJERCICIO 1
#b'Hola amigos de la seguridad'
#b'=\x88\xd9z\x13\xa9)kq\xd0M6I\xee\x9a(\x95y\xb0\x18\x02[\\R\xa9\x89\xf7C1X\xffJ'

#b'Hola amigas de la seguridad'
#b')8\xa9\x02\xa9\x123\xf3d\xf2\xb9\x8e-\x07\xc5\xb6\x12\xd1\xde#{8C$m\xcb\xae\xa2\x0e\x1db\x05'

# El resultado es diferente porque aparte de ser el texto introducido distinto,
# la clave y el vector de inicialización también son diferentes ya que se generan aleatoriamente,
# por lo que el resultado es diferente.