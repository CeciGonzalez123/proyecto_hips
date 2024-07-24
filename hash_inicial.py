import hashlib
import json
import os

def generar_y_guardar_hashes(archivos, ruta_hashes):
    hashes_guardados = {}

    # Generar hashes
    for archivo in archivos:
        try:
            with open(archivo, 'r') as f:
                contenido = f.read()
            hash_valor = hashlib.md5(contenido.encode()).hexdigest()
            hashes_guardados[archivo] = hash_valor
        except Exception as e:
            print(f"Error al leer el archivo {archivo}: {e}")

    # Guardar hashes
    with open(ruta_hashes, 'w') as f:
        json.dump(hashes_guardados, f)

    print(f"Hashes guardados en {ruta_hashes}")

if __name__ == "__main__":
    archivos = ['/etc/passwd', '/etc/shadow', '/etc/group']
    ruta_hashes = '/home/cecilia/carpeta_montaje/hashes_guardados.json'
    generar_y_guardar_hashes(archivos, ruta_hashes)

