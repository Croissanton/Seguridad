
from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
from Crypto.Random import get_random_bytes

# Paso 0: Inicializacion
########################

# (A realizar por el alumno/a...)

<<<<<<< HEAD
aes_key = funciones_aes.crear_AESKey()
aes_cifrado = funciones_aes.iniciarAES_GCM(aes_key)
nA = funciones_aes.crear_AESKey()

=======
>>>>>>> 05df069274a2e161a8eb5b611a1e2245ef4c58d1
# Paso 3) A->T: KAT(Alice, Na) en AES-GCM
#########################################

# (A realizar por el alumno/a...)

<<<<<<< HEAD


=======
>>>>>>> 05df069274a2e161a8eb5b611a1e2245ef4c58d1
# Paso 4) T->A: KAT(K1, K2, Na) en AES-GCM
##########################################

# (A realizar por el alumno/a...)

# Paso 5) A->B: KAB(Nombre) en AES-CTR con HMAC
###############################################

# (A realizar por el alumno/a...)

# Paso 6) B->A: KAB(Apellido) en AES-CTR con HMAC
#################################################

# (A realizar por el alumno/a...)

# Paso 7) A->B: KAB(END) en AES-CTR con HMAC
############################################

# (A realizar por el alumno/a...)
