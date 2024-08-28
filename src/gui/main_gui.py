import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from tkinter import ttk
import sys
import os
import secrets

# Agregar la carpeta "src" al sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from encryption.aes_cipher import aes_encrypt, aes_decrypt
from encryption.rsa_cipher import generate_rsa_keys, rsa_encrypt, rsa_decrypt

# Generar claves RSA al inicio
private_key, public_key = generate_rsa_keys()

def load_file():
    filepath = filedialog.askopenfilename()
    if filepath:
        with open(filepath, 'rb') as file:
            data = file.read()
            return data, filepath
    return None, None

def generate_aes_key():
    """Genera una clave AES de 32 bytes y la coloca en el campo de entrada."""
    aes_key = secrets.token_bytes(32)
    aes_key_entry.delete(0, tk.END)  # Limpiar el campo de entrada
    aes_key_entry.insert(0, aes_key.hex())  # Insertar la clave en formato hexadecimal

def encrypt_file():
    data, filepath = load_file()
    if data:
        aes_key_hex = aes_key_entry.get()
        try:
            aes_key = bytes.fromhex(aes_key_hex)
        except ValueError:
            messagebox.showerror("Error", "La clave AES no es válida.")
            return
        
        # Verificar la longitud de la clave AES
        if len(aes_key) not in [16, 24, 32]:
            messagebox.showerror("Error", "La clave AES debe tener 16, 24 o 32 bytes.")
            return
        
        # Cifra los datos con AES
        encrypted_data = aes_encrypt(aes_key, data)
        
        # Cifra la clave AES con RSA
        encrypted_aes_key = rsa_encrypt(public_key, aes_key)
        
        # Obtén la extensión del archivo original
        file_extension = os.path.splitext(filepath)[1]
        file_extension_encoded = file_extension.encode('utf-8')
        extension_length = len(file_extension_encoded).to_bytes(1, 'big')

        # Guarda el archivo cifrado con la clave cifrada y la extensión original
        with open(filepath + '.enc', 'wb') as file:
            file.write(encrypted_aes_key + extension_length + file_extension_encoded + encrypted_data)
        messagebox.showinfo("Éxito", f"Archivo cifrado guardado en: {filepath}.enc")

def decrypt_file():
    data, filepath = load_file()
    if data:
        encrypted_aes_key = data[:256]
        extension_length = data[256]
        file_extension = data[257:257 + extension_length].decode('utf-8')
        encrypted_data = data[257 + extension_length:]
        
        # Mostrar un cuadro de diálogo para que el usuario ingrese la clave AES
        aes_key_hex = simpledialog.askstring("Clave de Descifrado", "Ingrese la clave AES en formato hexadecimal:", show='*')
        
        if not aes_key_hex:
            messagebox.showerror("Error", "No se ingresó ninguna clave AES.")
            return
        
        try:
            aes_key = bytes.fromhex(aes_key_hex)
        except ValueError:
            messagebox.showerror("Error", "La clave AES no es válida.")
            return
        
        # Verificar la longitud de la clave AES
        if len(aes_key) not in [16, 24, 32]:
            messagebox.showerror("Error", "La clave AES debe tener 16, 24 o 32 bytes.")
            return
        
        # Descifra los datos con AES
        try:
            decrypted_data = aes_decrypt(aes_key, encrypted_data)
            decrypted_filepath = filepath.replace('.enc', '') + file_extension
            with open(decrypted_filepath, 'wb') as file:
                file.write(decrypted_data)
            messagebox.showinfo("Éxito", f"Archivo descifrado guardado en: {decrypted_filepath}")
            # Intentar abrir el archivo automáticamente
            os.startfile(decrypted_filepath)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo descifrar el archivo: {str(e)}")

def toggle_show_key():
    if show_key_var.get():
        aes_key_entry.config(show="")
    else:
        aes_key_entry.config(show="*")

# Configuración de la ventana principal
root = tk.Tk()
root.title("Cifrado de Archivos RSA y AES")
root.geometry("450x500")
root.configure(bg="#69b8c8")  # Fondo oscuro moderno

# Estilos de ttk
style = ttk.Style()
style.configure("TButton",
    font=("Segoe UI", 14, "bold"),
    foreground="#080808",
    background="#0476fa",
    padding=10,
    relief="flat"
)
style.map("TButton",
    background=[('active', '#69b8c8')]
)

style.configure("TLabel",
    font=("Segoe UI", 14),
    foreground="#080808",
    background="#69b8c8"
)
style.configure("TEntry",
    padding=5,
    fieldbackground="#3A3A3A",
    foreground="#080808",
    borderwidth=1,
    relief="flat"
)

# Encabezado
header = ttk.Label(root, text="Cifrado de Archivos", font=("Segoe UI", 24, "bold"))
header.pack(pady=20)

# Etiqueta para el campo de la clave AES
aes_key_label = ttk.Label(root, text="Clave AES (16, 24 o 32 bytes):")
aes_key_label.pack(pady=10)

# Campo de entrada para la clave AES
aes_key_entry = ttk.Entry(root, font=("Segoe UI", 14), show="*")
aes_key_entry.pack(pady=10, padx=20, fill=tk.X)

# Casilla de verificación para mostrar/ocultar clave
show_key_var = tk.BooleanVar()
show_key_checkbox = ttk.Checkbutton(root, text="Mostrar clave", variable=show_key_var, command=toggle_show_key, style="TCheckbutton")
show_key_checkbox.pack(pady=5)

# Botón para generar una nueva clave AES
generate_key_button = ttk.Button(root, text="Generar Clave AES", command=generate_aes_key)
generate_key_button.pack(pady=15, padx=20, fill=tk.X)

# Botón para cargar y cifrar archivo
encrypt_button = ttk.Button(root, text="Cifrar Archivo", command=encrypt_file)
encrypt_button.pack(pady=15, padx=20, fill=tk.X)

# Botón para cargar y descifrar archivo
decrypt_button = ttk.Button(root, text="Descifrar Archivo", command=decrypt_file)
decrypt_button.pack(pady=15, padx=20, fill=tk.X)

# Generar automáticamente una clave AES al iniciar la aplicación
generate_aes_key()

# Ejecución de la ventana
root.mainloop()
