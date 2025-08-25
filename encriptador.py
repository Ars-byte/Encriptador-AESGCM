from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def generar_clave(nombre_archivo_clave):
    """
    Genera una clave de 256 bits y la guarda en un archivo .key.
    """
    clave = get_random_bytes(32)
    with open(nombre_archivo_clave, 'wb') as f:
        f.write(clave)
    print(f"Clave generada y guardada en '{nombre_archivo_clave}'")

def encriptar_archivo(nombre_archivo, nombre_archivo_clave):
    """
    Encripta un archivo usando AES-GCM y elimina el original.
    """
    try:
        with open(nombre_archivo_clave, 'rb') as f:
            clave = f.read()
    except FileNotFoundError:
        print(f"Error: El archivo de clave '{nombre_archivo_clave}' no fue encontrado.")
        return

    try:
        with open(nombre_archivo, 'rb') as f:
            datos = f.read()
    except FileNotFoundError:
        print(f"Error: El archivo a encriptar '{nombre_archivo}' no fue encontrado.")
        return

    cipher = AES.new(clave, AES.MODE_GCM)
    nonce = cipher.nonce
    texto_cifrado, tag = cipher.encrypt_and_digest(datos)

    archivo_encriptado = nombre_archivo + '.enc'
    with open(archivo_encriptado, 'wb') as f:
        f.write(nonce)
        f.write(tag)
        f.write(texto_cifrado)

    print(f"Archivo '{nombre_archivo}' encriptado exitosamente como '{archivo_encriptado}'.")
    
    try:
        os.remove(nombre_archivo)
        print(f"Archivo original '{nombre_archivo}' eliminado de forma segura.")
    except OSError as e:
        print(f"Error al eliminar el archivo original: {e}")


def desencriptar_archivo(archivo_encriptado, nombre_archivo_clave):
    """
    Desencripta un archivo usando AES-GCM y elimina el archivo encriptado.
    """
    try:
        with open(nombre_archivo_clave, 'rb') as f:
            clave = f.read()
    except FileNotFoundError:
        print(f"Error: El archivo de clave '{nombre_archivo_clave}' no fue encontrado.")
        return

    try:
        with open(archivo_encriptado, 'rb') as f:
            nonce = f.read(16)
            tag = f.read(16)
            texto_cifrado = f.read()
    except FileNotFoundError:
        print(f"Error: El archivo encriptado '{archivo_encriptado}' no fue encontrado.")
        return

    cipher = AES.new(clave, AES.MODE_GCM, nonce=nonce)

    try:
        datos_desencriptados = cipher.decrypt_and_verify(texto_cifrado, tag)
    except ValueError:
        print("Error de desencriptación: La clave es incorrecta o el archivo está corrupto.")
        return

    archivo_desencriptado = os.path.splitext(archivo_encriptado)[0]
    with open(archivo_desencriptado, 'wb') as f:
        f.write(datos_desencriptados)

    print(f"Archivo '{archivo_encriptado}' desencriptado exitosamente como '{archivo_desencriptado}'.")

    try:
        os.remove(archivo_encriptado)
        print(f"Archivo encriptado '{archivo_encriptado}' eliminado.")
    except OSError as e:
        print(f"Error al eliminar el archivo encriptado: {e}")


def main():
    while True:
        print("\n--- Menú de Encriptación ---")
        print("1. Generar una nueva clave")
        print("2. Encriptar un archivo (elimina el original)")
        print("3. Desencriptar un archivo (elimina el encriptado)")
        print("4. Salir")
        opcion = input("Elige una opción: ")

        if opcion == '1':
            nombre_archivo_clave = input("Ingresa el nombre para el archivo de clave (ej. mi_clave.key): ")
            generar_clave(nombre_archivo_clave)
        elif opcion == '2':
            nombre_archivo = input("Ingresa el nombre del archivo a encriptar: ")
            nombre_archivo_clave = input("Ingresa el nombre del archivo de clave a usar: ")
            encriptar_archivo(nombre_archivo, nombre_archivo_clave)
        elif opcion == '3':
            archivo_encriptado = input("Ingresa el nombre del archivo a desencriptar (con extensión .enc): ")
            nombre_archivo_clave = input("Ingresa el nombre del archivo de clave: ")
            desencriptar_archivo(archivo_encriptado, nombre_archivo_clave)
        elif opcion == '4':
            break
        else:
            print("Opción no válida. Por favor, intenta de nuevo.")

if __name__ == '__main__':
    main()
