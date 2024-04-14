from RSA import *

class RSA_OBJECT:
    def __init__(self):
        """Inicializa un objeto RSA, sin ninguna clave"""
        self.public_key = None
        self.private_key = None
    # Nota: Para comprobar si un objeto (no) ha sido inicializado, hay
    #   que hacer "if self.public_key is None:"
    def create_KeyPair(self):
        """Crea un par de claves publico/privada, y las almacena dentro de la instancia"""
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()

    def save_PrivateKey(self, file, password):
        """Guarda la clave privada self.private_key en un fichero file, usando una contraseña password"""
        guardar_RSAKey_Privada(file, self.private_key, password)

    def load_PrivateKey(self, file, password):
        """Carga la clave privada self.private_key de un fichero file, usando una contraseña password"""
        cargar_RSAKey_Privada(file, password)

    def save_PublicKey(self, file):
        """Guarda la clave publica self.public_key en un fichero file"""
        guardar_RSAKey_Publica(file, self.public_key)

    def load_PublicKey(self, file):
        """Carga la clave publica self.public_key de un fichero file"""
        cargar_RSAKey_Publica(file)

    def cifrar(self, datos):
        """Cifra el parámetro datos (de tipo binario) con la clave self.public_key, y devuelve el resultado. En caso de error, se devuelve None"""
        try:
            return cifrarRSA_OAEP(datos, self.public_key)
        except (ValueError, TypeError):
            return None

    def descifrar(self, cifrado):
        """Descrifra el parámetro cifrado (de tipo binario) con la clave self.private_key, y Devuelve el resultado (de tipo binario). En caso de error, se devuelve None"""
        try:
            return descifrarRSA_OAEP(cifrado, self.private_key)
        except (ValueError, TypeError):
            return None

    def firmar(self, datos):
        """Firma el parámetro datos (de tipo binario) con la clave self.private_key, y devuelve el resultado. En caso de error, se devuelve None."""
        try:
            return firmarRSA_PSS(datos, self.private_key)
        except (ValueError, TypeError):
            return None

    def comprobar(self, text, signature):
        """Comprueba el parámetro text (de tipo binario) con respecto a una firma signature (de tipo binario), usando para ello la clave self.public_key. Devuelve True si la comprobacion es correcta, o False en caso contrario o en caso de error."""
        #Esta funcion devuelve True si la comprobacion es correcta, o False en caso contrario o en caso de error, por lo que no es necesario hacer un try/except.
        return comprobarRSA_PSS(text, signature, self.public_key)