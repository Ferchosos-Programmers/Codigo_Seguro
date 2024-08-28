from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def generate_aes_key():
    return os.urandom(32)  # Genera una clave AES de 256 bits

def aes_encrypt(key, data):
    iv = os.urandom(16)  # Genera un vector de inicialización aleatorio
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Rellenar los datos para que sean múltiplos del tamaño del bloque
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    # Cifrar los datos
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data  # Prepend IV to encrypted data for decryption

def aes_decrypt(key, encrypted_data):
    iv = encrypted_data[:16]  # Extrae IV de los primeros 16 bytes
    encrypted_data = encrypted_data[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Descifrar los datos
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Deshacer el padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data
