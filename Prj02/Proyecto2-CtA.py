# ====================================================================
#  Proyecto2-CtA.py
#  FORTIN DE DATOS - Conjunto A (Criptografia y Gestion)
#  Programacion II - Proyecto #2 - Prof. Regis Rivera
#  Objetivo: proteger informacion sensible EN REPOSO usando Python.
#  Version con INTERFAZ GRAFICA (Tkinter), llave maestra (DEK/KEK)
#  y boveda de contrasenas cifrada.
# ====================================================================

# --------------------------------------------------------------------
#  IMPORTACION DE MODULOS
# --------------------------------------------------------------------
import os          # Manejo de rutas y archivos del sistema operativo.
import json        # Leer y escribir datos en formato JSON.
import base64      # Codificar/decodificar en base64 (llaves Fernet).
import hashlib     # Hashing: PBKDF2 para contrasenas y llaves.
import hmac        # Firma HMAC-SHA256 para verificar integridad.
import secrets     # Generacion criptograficamente segura: salt y contrasenas.
import string      # Conjuntos de caracteres (letras, digitos).
from datetime import datetime  # Fecha y hora para las entradas de la boveda.

from cryptography.fernet import Fernet, InvalidToken  # Cifrado autenticado (Fernet/AES).
from dotenv import load_dotenv, set_key               # Manejo del archivo .env.

import tkinter as tk                                   # Libreria grafica (interfaz).
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog  # Componentes graficos.


# --------------------------------------------------------------------
#  CONSTANTES DE CONFIGURACION
# --------------------------------------------------------------------
CARPETA = os.path.dirname(os.path.abspath(__file__))     # Carpeta base del proyecto.
RUTA_ENV = os.path.join(CARPETA, ".env")                 # Archivo .env (guarda el pepper).
RUTA_USUARIOS = os.path.join(CARPETA, "usuarios.json")   # Archivo de usuarios (login).
RUTA_FIRMAS = os.path.join(CARPETA, "firmas.json")       # Archivo de firmas HMAC (integridad).
RUTA_BOVEDA = os.path.join(CARPETA, "boveda.json")       # Archivo de la boveda (DEK envuelta + entradas).

NOMBRE_PEPPER = "APP_PEPPER"     # Nombre de la variable de entorno del pepper.
ITERACIONES = 200_000            # Iteraciones de PBKDF2 para el login.
ITER_KEK = 200_000               # Iteraciones de PBKDF2 para derivar la KEK (llave maestra).
ITER_ARCHIVO = 100_000           # Iteraciones de PBKDF2 para cifrar archivos (como el Proyecto 1).
TAM_SALT = 16                    # Tamano del salt en bytes (128 bits).
SALT_FIRMA = b"SALT_INTEGRIDAD_HMAC"  # Salt fijo para derivar la llave de firma.
LONGITUD_MINIMA = 8              # Longitud minima de contrasena.

MINUSCULAS = string.ascii_lowercase   # "abc...xyz"
MAYUSCULAS = string.ascii_uppercase   # "ABC...XYZ"
DIGITOS = string.digits               # "0123456789"
SIMBOLOS = "!@#$%^&*()-_=+[]{}"       # Simbolos permitidos.

# Paleta de colores (esquema navy / teal) para la interfaz.
NAVY = "#1B2A4A"        # Azul marino para el encabezado.
TEAL = "#0E7C7B"        # Verde azulado para acentos y botones.
TEAL_OSCURO = "#0A5E5D"  # Teal mas oscuro (hover/realce).
FONDO = "#F4F6F8"       # Gris muy claro de fondo.
BLANCO = "#FFFFFF"      # Blanco.
VERDE_OK = "#1E7E34"    # Verde para mensajes de exito.
ROJO_ERR = "#C0392B"    # Rojo para mensajes de error/alerta.

# Estado de la sesion: usuario con sesion y su DEK (llave real) desbloqueada.
sesion = {"usuario": None, "dek": None}   # Al inicio: sin sesion y sin llave desbloqueada.


# ====================================================================
#  SECCION 1 - ENTORNO / PEPPER EN VARIABLE DE ENTORNO  (AMBOS GRUPOS)
#  El "pepper" es un secreto global guardado en .env (fuera del codigo)
#  que se suma a la contrasena maestra al derivar la KEK. Cumple el
#  requisito de "almacenar llaves en variables de entorno".
# ====================================================================
def asegurar_env():
    """Crea el archivo .env vacio si todavia no existe."""
    if not os.path.exists(RUTA_ENV):     # Si el archivo .env NO existe...
        open(RUTA_ENV, "a").close()      # ...lo crea vacio y lo cierra.


def obtener_pepper():
    """Devuelve el pepper guardado en .env; si no existe, lo genera."""
    asegurar_env()                          # Asegura que .env exista.
    load_dotenv(RUTA_ENV, override=True)    # Carga las variables del .env.
    pepper = os.getenv(NOMBRE_PEPPER)       # Lee el pepper.
    if not pepper:                          # Si aun no hay pepper...
        pepper = secrets.token_hex(32)      # ...genera uno aleatorio (64 caracteres hex).
        set_key(RUTA_ENV, NOMBRE_PEPPER, pepper)  # Lo guarda en .env.
    return pepper                           # Devuelve el pepper como texto.


# ====================================================================
#  SECCION 2 - LOGIN CON CONTRASENA HASHEADA CON SALT  (PRIMER GRUPO)
# ====================================================================
def cargar_usuarios():
    """Lee usuarios.json y devuelve un diccionario."""
    if not os.path.exists(RUTA_USUARIOS):   # Si no existe el archivo...
        return {}                           # ...devuelve diccionario vacio.
    with open(RUTA_USUARIOS, "r", encoding="utf-8") as archivo:  # Abre en lectura.
        try:                                # Intenta leer como JSON.
            return json.load(archivo)       # Devuelve el diccionario.
        except json.JSONDecodeError:        # Si esta vacio o danado...
            return {}                       # ...devuelve diccionario vacio.


def guardar_usuarios(usuarios):
    """Guarda el diccionario de usuarios en usuarios.json."""
    with open(RUTA_USUARIOS, "w", encoding="utf-8") as archivo:  # Abre en escritura.
        json.dump(usuarios, archivo, indent=4, ensure_ascii=False)  # Escribe el JSON.


def derivar_hash(contrasena, salt):
    """Deriva el hash de la contrasena con PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(             # Funcion lenta a proposito (anti fuerza bruta).
        "sha256",                           # Algoritmo base SHA-256.
        contrasena.encode("utf-8"),         # Contrasena en bytes.
        salt,                               # Salt unico del usuario.
        ITERACIONES,                        # Iteraciones configuradas.
    )                                       # Devuelve el hash en bytes.


def registrar_usuario(usuario, contrasena):
    """Registra un usuario guardando salt + hash (nunca texto plano)."""
    usuario = usuario.strip().lower()       # Normaliza el nombre (sin espacios, minusculas).
    usuarios = cargar_usuarios()            # Carga los usuarios existentes.
    if usuario in usuarios:                 # Si ya existe...
        return False                        # ...no lo registra.

    salt = secrets.token_bytes(TAM_SALT)    # Salt aleatorio y unico (16 bytes).
    hash_derivado = derivar_hash(contrasena, salt)  # Hash de la contrasena con ese salt.

    usuarios[usuario] = {                   # Crea el registro del usuario:
        "salt": salt.hex(),                 #   salt en hexadecimal.
        "hash": hash_derivado.hex(),        #   hash en hexadecimal.
        "iteraciones": ITERACIONES,         #   iteraciones usadas.
    }
    guardar_usuarios(usuarios)              # Guarda en disco.
    return True                             # Registro exitoso.


def verificar_login(usuario, contrasena):
    """Verifica credenciales recalculando el hash con el salt guardado."""
    usuario = usuario.strip().lower()       # Normaliza el nombre.
    usuarios = cargar_usuarios()            # Carga los usuarios.
    if usuario not in usuarios:             # Si el usuario no existe...
        derivar_hash(contrasena, secrets.token_bytes(TAM_SALT))  # Hash falso (gasta tiempo igual).
        return False                        # Login fallido.

    datos = usuarios[usuario]               # Registro del usuario.
    salt = bytes.fromhex(datos["salt"])     # Salt de vuelta a bytes.
    hash_guardado = datos["hash"]           # Hash original almacenado.
    hash_calculado = derivar_hash(contrasena, salt).hex()  # Recalcula el hash.

    return secrets.compare_digest(hash_calculado, hash_guardado)  # Compara en tiempo constante.


def usuario_existe(usuario):
    """Indica si un usuario ya esta registrado."""
    return usuario.strip().lower() in cargar_usuarios()  # True si esta en el diccionario.


# ====================================================================
#  SECCION 3 - LLAVE MAESTRA (DEK/KEK) Y BOVEDA DE CONTRASENAS
#  (PRIMER GRUPO + AMBOS)
#
#  Modelo de "cifrado de sobre" (envelope encryption):
#   - DEK (Data Encryption Key): llave AES aleatoria que cifra la boveda.
#   - KEK (Key Encryption Key): llave derivada de la CONTRASENA MAESTRA
#     (que el usuario escribe) + salt + pepper; solo envuelve a la DEK.
#   - En disco se guarda la DEK ENVUELTA (cifrada con la KEK), nunca en
#     texto plano. La DEK real solo existe en memoria durante la sesion.
# ====================================================================
def cargar_boveda():
    """Lee boveda.json y devuelve un diccionario (por usuario)."""
    if not os.path.exists(RUTA_BOVEDA):     # Si no existe el archivo...
        return {}                           # ...devuelve diccionario vacio.
    with open(RUTA_BOVEDA, "r", encoding="utf-8") as archivo:  # Abre en lectura.
        try:                                # Intenta leer como JSON.
            return json.load(archivo)       # Devuelve el diccionario.
        except json.JSONDecodeError:        # Si esta danado...
            return {}                       # ...diccionario vacio.


def guardar_boveda(data):
    """Guarda el diccionario de la boveda en boveda.json."""
    with open(RUTA_BOVEDA, "w", encoding="utf-8") as archivo:  # Abre en escritura.
        json.dump(data, archivo, indent=4, ensure_ascii=False)  # Escribe el JSON.


def derivar_kek(master_password, salt):
    """Deriva la KEK (llave que envuelve la DEK) de la contrasena maestra + pepper."""
    combinado = (master_password + obtener_pepper()).encode("utf-8")  # Contrasena maestra + pepper.
    bruto = hashlib.pbkdf2_hmac(            # Deriva 32 bytes con PBKDF2-HMAC-SHA256.
        "sha256",                           # Algoritmo SHA-256.
        combinado,                          # Contrasena maestra + pepper, en bytes.
        salt,                               # Salt propio de la KEK.
        ITER_KEK,                           # 200 000 iteraciones.
        dklen=32,                           # 32 bytes (lo que exige Fernet).
    )
    return base64.urlsafe_b64encode(bruto)  # Codifica base64 url-safe -> llave Fernet (KEK).


def tiene_llave_maestra(usuario):
    """Indica si el usuario ya creo su llave maestra (existe DEK envuelta)."""
    boveda = cargar_boveda()                # Carga la boveda.
    return usuario in boveda and "dek_envuelta" in boveda[usuario]  # True si ya tiene DEK.


def crear_llave_maestra(usuario, master_password):
    """Crea la llave maestra del usuario: genera la DEK y la envuelve con la KEK."""
    usuario = usuario.strip().lower()       # Normaliza el nombre.
    boveda = cargar_boveda()                # Carga la boveda.
    if usuario in boveda and "dek_envuelta" in boveda[usuario]:  # Si ya tiene llave maestra...
        raise ValueError("Este usuario ya tiene una llave maestra.")  # ...no permite otra.

    salt = secrets.token_bytes(TAM_SALT)    # Salt aleatorio para derivar la KEK.
    kek = derivar_kek(master_password, salt)  # Deriva la KEK de la contrasena maestra.
    dek = Fernet.generate_key()             # Genera la DEK aleatoria (la llave AES real).
    dek_envuelta = Fernet(kek).encrypt(dek)  # Envuelve (cifra) la DEK con la KEK.
    entradas_vacias = Fernet(dek).encrypt(json.dumps([]).encode())  # Boveda vacia cifrada con la DEK.

    boveda.setdefault(usuario, {})          # Crea la entrada del usuario si no existe.
    boveda[usuario]["salt_kek"] = salt.hex()  # Guarda el salt de la KEK (en hex).
    boveda[usuario]["dek_envuelta"] = dek_envuelta.decode()  # Guarda la DEK envuelta (texto).
    boveda[usuario]["entradas"] = entradas_vacias.decode()   # Guarda la boveda vacia cifrada.
    guardar_boveda(boveda)                  # Escribe todo en disco.
    return dek                              # Devuelve la DEK para cargarla en memoria.


def desbloquear_dek(usuario, master_password):
    """Desbloquea (desenvuelve) la DEK usando la contrasena maestra."""
    usuario = usuario.strip().lower()       # Normaliza el nombre.
    boveda = cargar_boveda()                # Carga la boveda.
    if usuario not in boveda or "dek_envuelta" not in boveda[usuario]:  # Si no tiene llave...
        raise ValueError("Este usuario no tiene llave maestra.")  # ...error.

    salt = bytes.fromhex(boveda[usuario]["salt_kek"])  # Recupera el salt de la KEK.
    kek = derivar_kek(master_password, salt)  # Re-deriva la KEK con la contrasena escrita.
    try:                                    # Intenta desenvolver la DEK.
        dek = Fernet(kek).decrypt(boveda[usuario]["dek_envuelta"].encode())  # Descifra la DEK.
    except InvalidToken:                    # Si la contrasena maestra es incorrecta...
        raise ValueError("Llave maestra incorrecta.")  # ...el propio Fernet lo detecta.
    return dek                              # Devuelve la DEK (solo vivira en memoria).


# --- Boveda de contrasenas (cifrada con la DEK) ---------------------
def leer_entradas(usuario, dek):
    """Descifra y devuelve la lista de entradas de la boveda del usuario."""
    boveda = cargar_boveda()                # Carga la boveda.
    token = boveda.get(usuario, {}).get("entradas")  # Toma el bloque cifrado de entradas.
    if not token:                           # Si no hay entradas...
        return []                           # ...devuelve lista vacia.
    datos = Fernet(dek).decrypt(token.encode())  # Descifra el bloque con la DEK.
    return json.loads(datos.decode())       # Convierte el JSON en lista de diccionarios.


def agregar_entrada(usuario, dek, proposito, contrasena):
    """Agrega una contrasena (con su proposito) a la boveda, cifrada con la DEK."""
    entradas = leer_entradas(usuario, dek)  # Lee las entradas actuales (descifradas).
    entradas.append({                       # Agrega la nueva entrada:
        "proposito": proposito,             #   para que sirve la contrasena.
        "contrasena": contrasena,           #   la contrasena generada.
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M"),  # fecha y hora de creacion.
    })
    boveda = cargar_boveda()                # Carga la boveda para actualizarla.
    boveda.setdefault(usuario, {})          # Asegura la entrada del usuario.
    boveda[usuario]["entradas"] = Fernet(dek).encrypt(  # Vuelve a cifrar toda la lista...
        json.dumps(entradas).encode()).decode()          # ...con la DEK y la guarda como texto.
    guardar_boveda(boveda)                  # Escribe en disco.


def eliminar_entrada(usuario, dek, indice):
    """Elimina una entrada de la boveda por su posicion en la lista."""
    entradas = leer_entradas(usuario, dek)  # Lee las entradas descifradas.
    if 0 <= indice < len(entradas):         # Si el indice es valido...
        entradas.pop(indice)                # ...quita esa entrada.
    boveda = cargar_boveda()                # Carga la boveda.
    boveda.setdefault(usuario, {})          # Asegura la entrada del usuario.
    boveda[usuario]["entradas"] = Fernet(dek).encrypt(  # Re-cifra la lista actualizada...
        json.dumps(entradas).encode()).decode()          # ...con la DEK.
    guardar_boveda(boveda)                  # Guarda en disco.


# ====================================================================
#  SECCION 4 - CIFRADO/DESCIFRADO E INTEGRIDAD DE ARCHIVOS  (SEGUNDO GRUPO)
#  Nota: los archivos se cifran con una CONTRASENA POR ARCHIVO (para poder
#  compartirlos), pero solo se puede usar esta seccion con la llave maestra
#  desbloqueada (control de acceso).
# ====================================================================
def cargar_firmas():
    """Lee firmas.json (firmas HMAC) y devuelve un diccionario."""
    if not os.path.exists(RUTA_FIRMAS):      # Si no existe...
        return {}                            # ...diccionario vacio.
    with open(RUTA_FIRMAS, "r", encoding="utf-8") as archivo:  # Abre en lectura.
        try:                                 # Intenta leer como JSON.
            return json.load(archivo)        # Devuelve el diccionario de firmas.
        except json.JSONDecodeError:         # Si esta danado...
            return {}                        # ...diccionario vacio.


def guardar_firmas(firmas):
    """Guarda el diccionario de firmas en firmas.json."""
    with open(RUTA_FIRMAS, "w", encoding="utf-8") as archivo:  # Abre en escritura.
        json.dump(firmas, archivo, indent=4, ensure_ascii=False)  # Escribe el JSON.


def derivar_llave_firma(password):
    """Deriva la llave de firma a partir de la contrasena (PBKDF2 + salt fijo)."""
    return hashlib.pbkdf2_hmac(              # Deriva 32 bytes con PBKDF2-HMAC-SHA256.
        "sha256",                           # Algoritmo SHA-256.
        password.encode("utf-8"),           # Contrasena en bytes.
        SALT_FIRMA,                         # Salt fijo exclusivo para integridad.
        ITER_ARCHIVO,                       # 100 000 iteraciones.
        dklen=32,                           # Llave de 32 bytes.
    )


def firmar_archivo(ruta, password):
    """Genera la firma HMAC-SHA256 del archivo y la guarda (sello de integridad)."""
    with open(ruta, "rb") as archivo:        # Abre el archivo en binario.
        contenido = archivo.read()           # Lee todo el contenido.
    llave = derivar_llave_firma(password)    # Deriva la llave de firma con la contrasena.
    firma = hmac.new(llave, contenido, hashlib.sha256).hexdigest()  # Calcula el HMAC en hex.
    firmas = cargar_firmas()                 # Carga las firmas guardadas.
    firmas[os.path.basename(ruta)] = firma   # Asocia el nombre del archivo a su firma.
    guardar_firmas(firmas)                   # Guarda el diccionario de firmas.
    return firma                             # Devuelve la firma generada.


def verificar_firma(ruta, password):
    """Recalcula la firma HMAC y la compara con la guardada (detecta alteraciones)."""
    nombre = os.path.basename(ruta)          # Nombre del archivo (sin ruta).
    firmas = cargar_firmas()                 # Carga las firmas guardadas.
    if nombre not in firmas:                 # Si el archivo no tiene firma registrada...
        return False                         # ...no se puede verificar.
    with open(ruta, "rb") as archivo:        # Abre el archivo en binario.
        contenido = archivo.read()           # Lee el contenido actual.
    llave = derivar_llave_firma(password)    # Re-deriva la llave de firma.
    firma_actual = hmac.new(llave, contenido, hashlib.sha256).hexdigest()  # Recalcula el HMAC.
    return hmac.compare_digest(firma_actual, firmas[nombre])  # True si esta intacto.


def derivar_llave_archivo(password, salt):
    """Convierte una contrasena normal en una llave Fernet (PBKDF2 + base64)."""
    bruto = hashlib.pbkdf2_hmac(             # Deriva 32 bytes con PBKDF2-HMAC-SHA256.
        "sha256",                           # Algoritmo SHA-256.
        password.encode("utf-8"),           # Contrasena en bytes.
        salt,                               # Salt (16 bytes) de este archivo.
        ITER_ARCHIVO,                       # 100 000 iteraciones (como el Proyecto 1).
        dklen=32,                           # 32 bytes, longitud que exige Fernet.
    )
    return base64.urlsafe_b64encode(bruto)  # Codifica en base64 url-safe -> llave Fernet.


def archivo_ya_cifrado(datos):
    """Detecta si el contenido ya esta cifrado (formato: salt + token Fernet)."""
    return len(datos) >= 22 and datos[16:22] == b"gAAAAA"  # El token Fernet empieza en 'gAAAAA'.


def cifrar_archivo(ruta, password):
    """Cifra un archivo EN EL MISMO lugar (no crea copias nuevas)."""
    if not os.path.exists(ruta):             # Si el archivo no existe...
        raise FileNotFoundError(f"No existe el archivo: {ruta}")  # ...error.

    with open(ruta, "rb") as archivo:        # Abre el archivo en binario lectura.
        datos = archivo.read()               # Lee todo el contenido.

    if archivo_ya_cifrado(datos):            # Si ya estaba cifrado...
        raise ValueError("El archivo ya esta cifrado.")  # ...evita doble cifrado.

    salt = secrets.token_bytes(16)           # Salt aleatorio de 16 bytes para este archivo.
    llave = derivar_llave_archivo(password, salt)  # Deriva la llave Fernet con la contrasena.
    token = Fernet(llave).encrypt(datos)     # Cifra (Fernet agrega HMAC = autenticado).

    with open(ruta, "wb") as archivo:        # Abre el MISMO archivo en binario escritura.
        archivo.write(salt + token)          # Escribe salt + cifrado (reemplaza el original).

    return ruta                              # Devuelve la misma ruta.


def descifrar_archivo(ruta, password):
    """Descifra un archivo EN EL MISMO lugar (no crea copias nuevas)."""
    if not os.path.exists(ruta):             # Si el archivo no existe...
        raise FileNotFoundError(f"No existe el archivo: {ruta}")  # ...error.

    with open(ruta, "rb") as archivo:        # Abre el archivo en binario lectura.
        contenido = archivo.read()           # Lee todo el contenido.

    if not archivo_ya_cifrado(contenido):    # Si no esta cifrado por este programa...
        raise ValueError("El archivo no esta cifrado (o ya esta descifrado).")  # Aborta: el archivo no estaba cifrado.

    salt = contenido[:16]                    # Los primeros 16 bytes son el salt.
    token = contenido[16:]                   # El resto es el token cifrado.
    llave = derivar_llave_archivo(password, salt)  # Re-deriva la llave con la contrasena + salt.

    try:                                     # Intenta descifrar.
        datos = Fernet(llave).decrypt(token)  # Fernet verifica el HMAC y descifra.
    except InvalidToken:                     # Si la clave es mala o el archivo fue alterado...
        raise ValueError("Clave incorrecta o archivo manipulado.")  # Aborta: clave incorrecta o archivo alterado.

    with open(ruta, "wb") as archivo:        # Abre el MISMO archivo en binario escritura.
        archivo.write(datos)                 # Restaura el contenido original.

    return ruta                              # Devuelve la misma ruta.


# ====================================================================
#  SECCION 5 - GENERADOR DE CONTRASENAS SEGURAS  (AMBOS GRUPOS)
# ====================================================================
def generar_contrasena(longitud=16):
    """Genera una contrasena segura con al menos un caracter de cada tipo."""
    if longitud < LONGITUD_MINIMA:           # Si piden menos del minimo...
        longitud = LONGITUD_MINIMA           # ...se ajusta al minimo.

    todos = MINUSCULAS + MAYUSCULAS + DIGITOS + SIMBOLOS  # Todos los caracteres posibles.

    contrasena = [                           # Garantiza uno de cada tipo:
        secrets.choice(MINUSCULAS),          #   una minuscula.
        secrets.choice(MAYUSCULAS),          #   una mayuscula.
        secrets.choice(DIGITOS),             #   un digito.
        secrets.choice(SIMBOLOS),            #   un simbolo.
    ]
    contrasena += [secrets.choice(todos) for _ in range(longitud - 4)]  # Rellena el resto.

    secrets.SystemRandom().shuffle(contrasena)  # Mezcla para que no sea predecible.
    return "".join(contrasena)               # Devuelve la contrasena como texto.


def evaluar_fortaleza(contrasena):
    """Evalua si la contrasena es Debil, Media o Fuerte."""
    puntos = 0                               # Criterios cumplidos.
    if len(contrasena) >= 12:                # 12 o mas caracteres...
        puntos += 1                          # ...suma punto.
    if any(c in MINUSCULAS for c in contrasena):  # Tiene minuscula...
        puntos += 1                          # ...suma punto.
    if any(c in MAYUSCULAS for c in contrasena):  # Tiene mayuscula...
        puntos += 1                          # ...suma punto.
    if any(c in DIGITOS for c in contrasena):     # Tiene digito...
        puntos += 1                          # ...suma punto.
    if any(c in SIMBOLOS for c in contrasena):    # Tiene simbolo...
        puntos += 1                          # ...suma punto.

    if puntos <= 2:                          # 2 o menos...
        return "Debil"                       # ...debil.
    if puntos in (3, 4):                     # 3 o 4...
        return "Media"                       # ...media.
    return "Fuerte"                          # 5: fuerte.


# ====================================================================
#  SECCION 6 - ATAQUE VS DEFENSA  (AMBOS GRUPOS)
#  (Estas funciones DEVUELVEN texto para mostrarlo en la interfaz.)
# ====================================================================
def demo_1_hash_sin_salt():
    """ATAQUE: hash sin salt (MD5). DEFENSA: PBKDF2 con salt unico."""
    lineas = []                              # Lista de lineas de texto del reporte.
    lineas.append("=== DEMO 1: Hash sin salt vs PBKDF2 con salt ===")  # Titulo de la demo.
    contrasena = "Panama123"                 # Contrasena de ejemplo.

    # MALA PRACTICA: MD5 sin salt -> misma entrada = mismo hash.
    h_a = hashlib.md5(contrasena.encode()).hexdigest()  # Hash MD5 del usuario A.
    h_b = hashlib.md5(contrasena.encode()).hexdigest()  # Hash MD5 del usuario B.
    lineas.append("[ATAQUE]  MD5 sin salt:")             # Encabezado del ataque.
    lineas.append(f"          Usuario A: {h_a}")         # Muestra el hash de A.
    lineas.append(f"          Usuario B: {h_b}")         # Muestra el hash de B (igual a A).
    lineas.append("          -> Mismo hash. Vulnerable a tablas rainbow.")  # Explica el riesgo.

    # DEFENSA: PBKDF2 con salt distinto -> hashes distintos.
    sa = secrets.token_bytes(16)             # Salt de A.
    sb = secrets.token_bytes(16)             # Salt de B.
    hs_a = derivar_hash(contrasena, sa).hex()  # Hash seguro de A.
    hs_b = derivar_hash(contrasena, sb).hex()  # Hash seguro de B.
    lineas.append("[DEFENSA] PBKDF2-HMAC-SHA256 con salt unico:")  # Encabezado de la defensa.
    lineas.append(f"          Usuario A: {hs_a[:40]}...")  # Muestra parte del hash de A.
    lineas.append(f"          Usuario B: {hs_b[:40]}...")  # Muestra parte del hash de B.
    lineas.append("          -> Hashes distintos con la misma contrasena.")  # Explica la mejora.
    return "\n".join(lineas)                 # Une todo y lo devuelve como texto.


def demo_2_archivo_alterado():
    """ATAQUE: modificar un archivo cifrado. DEFENSA: integridad lo detecta."""
    lineas = []                              # Lineas del reporte.
    lineas.append("=== DEMO 2: Manipulacion de archivo vs integridad ===")  # Titulo de la demo.
    ruta = os.path.join(CARPETA, "_demo_secreto.txt")  # Archivo temporal de la demo.
    clave_demo = "ClaveDemo123!"             # Contrasena de ejemplo para cifrar el archivo.

    with open(ruta, "w", encoding="utf-8") as f:  # Crea el archivo de prueba.
        f.write("Informacion confidencial de IstmoSec, S.A.")  # Contenido de ejemplo.

    cifrar_archivo(ruta, clave_demo)         # Cifra EN EL MISMO archivo (sin crear copias).
    lineas.append(f"[OK]      Archivo cifrado en el mismo lugar: {os.path.basename(ruta)}")  # Confirma.

    # ATAQUE: alterar un byte del archivo cifrado.
    with open(ruta, "rb") as f:              # Abre el cifrado en binario.
        datos = bytearray(f.read())          # Lee como bytes modificables.
    datos[-1] = datos[-1] ^ 0x01             # Invierte un bit del ultimo byte (parte cifrada).
    with open(ruta, "wb") as f:              # Abre en escritura.
        f.write(datos)                       # Reescribe el contenido alterado.
    lineas.append("[ATAQUE]  Se modifico 1 byte del archivo cifrado.")  # Informa el ataque.

    # DEFENSA: al descifrar, la autenticacion (HMAC de Fernet) detecta el cambio.
    try:                                     # Intenta descifrar el archivo alterado.
        descifrar_archivo(ruta, clave_demo)  # Deberia fallar por la alteracion.
        lineas.append("[DEFENSA] (no deberia llegar aqui)")  # Caso que no ocurre.
    except Exception as e:                    # La excepcion confirma la deteccion.
        lineas.append(f"[DEFENSA] Al descifrar: {e}")  # Muestra el mensaje de error.
        lineas.append("          -> El cambio se detecta y se rechaza (HMAC de Fernet).")  # Explica.

    try:                                     # Limpia el archivo temporal.
        os.remove(ruta)                      # Elimina el archivo.
    except OSError:                          # Si falla...
        pass                                 # ...lo ignora.
    return "\n".join(lineas)                 # Devuelve el reporte como texto.


def demo_3_llave_envuelta():
    """ATAQUE: guardar la llave en texto plano. DEFENSA: envolverla (envelope) + pepper en .env."""
    lineas = []                              # Lineas del reporte.
    lineas.append("=== DEMO 3: Llave en texto plano vs llave envuelta ===")  # Titulo de la demo.

    dek_falsa = Fernet.generate_key()        # Genera una DEK de ejemplo (llave AES real).
    lineas.append("[ATAQUE]  DEK guardada en texto plano en disco:")  # Encabezado del ataque.
    lineas.append(f"          {dek_falsa.decode()[:40]}...")  # Muestra la llave legible.
    lineas.append("          -> Cualquiera que lea el archivo obtiene la llave real.")  # Riesgo.

    # DEFENSA: envolver la DEK con una KEK derivada de la contrasena maestra + pepper.
    salt = secrets.token_bytes(16)           # Salt para derivar la KEK de la demo.
    kek = derivar_kek("ContrasenaMaestraDemo", salt)  # Deriva la KEK (usa el pepper de .env).
    dek_envuelta = Fernet(kek).encrypt(dek_falsa)  # Envuelve (cifra) la DEK con la KEK.
    lineas.append("[DEFENSA] DEK envuelta (cifrada con la KEK de la contrasena maestra):")  # Defensa.
    lineas.append(f"          {dek_envuelta.decode()[:40]}...")  # Muestra el blob ilegible.
    lineas.append("          -> Sin la contrasena maestra, este blob es inutil.")  # Por que es seguro.
    lineas.append("          -> Ademas el 'pepper' vive en .env, fuera del codigo.")  # Refuerzo.
    return "\n".join(lineas)                 # Devuelve el reporte como texto.


def ejecutar_demos():
    """Ejecuta las 3 demostraciones y devuelve todo el texto junto."""
    partes = [                               # Llama a cada demo y guarda su texto.
        demo_1_hash_sin_salt(),              # Demo 1.
        demo_2_archivo_alterado(),           # Demo 2.
        demo_3_llave_envuelta(),             # Demo 3.
    ]
    return "\n\n".join(partes)               # Une las tres separadas por lineas en blanco.


# ====================================================================
#  SECCION 7 - INTERFAZ GRAFICA (Tkinter)
# ====================================================================
class FortinApp:
    """Clase principal de la aplicacion grafica (ventana del Fortin de Datos)."""

    def __init__(self, root):
        """Constructor: arma toda la ventana y sus pestanas."""
        self.root = root                          # Guarda la ventana principal.
        self.archivo_cifrar = None                # Ruta del archivo a cifrar/descifrar.
        self.archivo_verificar = None             # Ruta del archivo a firmar/verificar.
        self.entradas = []                        # Copia en memoria de las entradas de la boveda.
        self.mostrar_claves = False               # Bandera: mostrar u ocultar las contrasenas.

        self.root.title("Fortin de Datos - Proyecto #2")  # Titulo de la ventana.
        self.root.geometry("780x600")             # Tamano inicial de la ventana.
        self.root.configure(bg=FONDO)             # Color de fondo de la ventana.
        self.root.minsize(740, 560)               # Tamano minimo permitido.

        self._configurar_estilos()                # Aplica colores y estilos a los widgets.
        self._construir_encabezado()              # Crea la barra superior (titulo).
        self._construir_pestanas()                # Crea el cuaderno de pestanas.
        self._actualizar_estado_sesion()          # Muestra el estado inicial de la sesion.

    # ----------------------------------------------------------------
    #  Estilos visuales
    # ----------------------------------------------------------------
    def _configurar_estilos(self):
        """Define los estilos (colores, fuentes) de los componentes ttk."""
        estilo = ttk.Style()                      # Objeto de estilos de ttk.
        estilo.theme_use("clam")                  # Tema base que permite personalizar colores.

        estilo.configure("TNotebook", background=FONDO, borderwidth=0)  # Fondo del cuaderno.
        estilo.configure("TNotebook.Tab", padding=(14, 8),             # Espaciado de cada pestana.
                         font=("Segoe UI", 10, "bold"))                # Fuente de las pestanas.
        estilo.map("TNotebook.Tab",                                    # Color segun seleccion:
                   background=[("selected", TEAL), ("!selected", "#D8DEE4")],  # activa/inactiva.
                   foreground=[("selected", BLANCO), ("!selected", NAVY)])     # texto.

        estilo.configure("TFrame", background=BLANCO)                  # Fondo de los marcos.
        estilo.configure("TLabel", background=BLANCO, foreground=NAVY, # Etiquetas:
                         font=("Segoe UI", 10))                        # fuente normal.
        estilo.configure("Titulo.TLabel", font=("Segoe UI", 12, "bold"),  # Estilo para titulos.
                         foreground=NAVY, background=BLANCO)
        estilo.configure("TButton", font=("Segoe UI", 10, "bold"),    # Botones:
                         padding=6)                                    # espaciado interno.
        estilo.configure("Accent.TButton", background=TEAL,           # Boton de acento (teal).
                         foreground=BLANCO)
        estilo.map("Accent.TButton",                                  # Color al pasar el mouse:
                   background=[("active", TEAL_OSCURO)])
        estilo.configure("TEntry", padding=5)                         # Espaciado de los campos.
        estilo.configure("TLabelframe", background=BLANCO, foreground=NAVY)  # Marcos con titulo.
        estilo.configure("TLabelframe.Label", background=BLANCO, foreground=TEAL,  # Titulo del marco.
                         font=("Segoe UI", 10, "bold"))
        estilo.configure("TSpinbox", padding=4)                       # Espaciado del selector.
        estilo.configure("Treeview", font=("Segoe UI", 9), rowheight=24)  # Filas de la tabla.
        estilo.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))  # Encabezados de la tabla.

    # ----------------------------------------------------------------
    #  Encabezado
    # ----------------------------------------------------------------
    def _construir_encabezado(self):
        """Crea la barra navy superior con el titulo y el estado de sesion."""
        barra = tk.Frame(self.root, bg=NAVY, height=70)   # Marco navy del encabezado.
        barra.pack(fill="x")                              # Lo extiende a lo ancho.
        barra.pack_propagate(False)                       # Mantiene la altura fija.

        tk.Label(barra, text="FORTIN DE DATOS",           # Titulo principal.
                 bg=NAVY, fg=BLANCO,
                 font=("Segoe UI", 18, "bold")).pack(side="left", padx=20, pady=10)

        tk.Label(barra, text="Proteccion de informacion en reposo",  # Subtitulo.
                 bg=NAVY, fg="#A8DADC",
                 font=("Segoe UI", 9)).pack(side="left", pady=10)

        self.lbl_sesion = tk.Label(barra, text="Sesion: invitado",   # Estado de la sesion.
                                   bg=NAVY, fg=BLANCO,
                                   font=("Segoe UI", 10, "bold"))
        self.lbl_sesion.pack(side="right", padx=20)       # A la derecha de la barra.

    # ----------------------------------------------------------------
    #  Pestanas
    # ----------------------------------------------------------------
    def _construir_pestanas(self):
        """Crea el cuaderno de pestanas y las llena con cada modulo."""
        cuaderno = ttk.Notebook(self.root)                # Contenedor de pestanas.
        cuaderno.pack(fill="both", expand=True, padx=12, pady=12)  # Lo expande en la ventana.

        # Crea un marco por cada pestana.
        tab_auth = ttk.Frame(cuaderno, padding=16)        # Pestana de autenticacion.
        tab_gen = ttk.Frame(cuaderno, padding=16)         # Pestana del generador + boveda.
        tab_cif = ttk.Frame(cuaderno, padding=16)         # Pestana de cifrado.
        tab_int = ttk.Frame(cuaderno, padding=16)         # Pestana de integridad.
        tab_llave = ttk.Frame(cuaderno, padding=16)       # Pestana de llave maestra.
        tab_demo = ttk.Frame(cuaderno, padding=16)        # Pestana de ataque/defensa.

        # Agrega cada marco al cuaderno con su titulo.
        cuaderno.add(tab_auth, text="Autenticacion")   # Pestana 1.
        cuaderno.add(tab_gen, text="Generador")        # Pestana 2.
        cuaderno.add(tab_cif, text="Cifrado")          # Pestana 3.
        cuaderno.add(tab_int, text="Integridad")       # Pestana 4.
        cuaderno.add(tab_llave, text="Llave maestra")  # Pestana 5.
        cuaderno.add(tab_demo, text="Ataque/Defensa")  # Pestana 6.

        # Llama al metodo que arma el contenido de cada pestana.
        self._tab_autenticacion(tab_auth)  # Contenido de Autenticacion.
        self._tab_generador(tab_gen)       # Contenido del Generador + boveda.
        self._tab_cifrado(tab_cif)         # Contenido de Cifrado.
        self._tab_integridad(tab_int)      # Contenido de Integridad.
        self._tab_llave(tab_llave)         # Contenido de Llave maestra.
        self._tab_demos(tab_demo)          # Contenido de Ataque/Defensa.

    # --- Pestana 1: Autenticacion --------------------------------
    def _tab_autenticacion(self, tab):
        """Arma el formulario de registro e inicio de sesion."""
        ttk.Label(tab, text="Registro e inicio de sesion",   # Titulo de la pestana.
                  style="Titulo.TLabel").pack(anchor="w", pady=(0, 6))
        ttk.Label(tab, text="Al registrarte crearas tu llave maestra. Sin ella no puedes usar las funciones.",
                  foreground=TEAL).pack(anchor="w", pady=(0, 10))  # Aviso del flujo.

        # --- Marco de registro ---
        marco_reg = ttk.Labelframe(tab, text="Registrar usuario", padding=12)  # Caja "Registrar".
        marco_reg.pack(fill="x", pady=6)                    # A lo ancho.

        ttk.Label(marco_reg, text="Usuario:").grid(row=0, column=0, sticky="w", pady=4)  # Etiqueta.
        self.reg_usuario = ttk.Entry(marco_reg, width=28)   # Campo de usuario.
        self.reg_usuario.grid(row=0, column=1, padx=8, pady=4)  # Posicion del campo.

        ttk.Label(marco_reg, text="Contrasena:").grid(row=1, column=0, sticky="w", pady=4)  # Etiqueta.
        self.reg_clave = ttk.Entry(marco_reg, width=28, show="*")  # Campo de clave (oculta con *).
        self.reg_clave.grid(row=1, column=1, padx=8, pady=4)  # Posicion.

        ttk.Button(marco_reg, text="Registrar", style="Accent.TButton",  # Boton registrar.
                   command=self.accion_registrar).grid(row=2, column=1, sticky="e", pady=6)

        # --- Marco de inicio de sesion ---
        marco_log = ttk.Labelframe(tab, text="Iniciar sesion", padding=12)  # Caja "Iniciar sesion".
        marco_log.pack(fill="x", pady=6)                    # A lo ancho.

        ttk.Label(marco_log, text="Usuario:").grid(row=0, column=0, sticky="w", pady=4)  # Etiqueta.
        self.log_usuario = ttk.Entry(marco_log, width=28)   # Campo de usuario.
        self.log_usuario.grid(row=0, column=1, padx=8, pady=4)  # Posicion.

        ttk.Label(marco_log, text="Contrasena:").grid(row=1, column=0, sticky="w", pady=4)  # Etiqueta.
        self.log_clave = ttk.Entry(marco_log, width=28, show="*")  # Campo de clave (oculta).
        self.log_clave.grid(row=1, column=1, padx=8, pady=4)  # Posicion.

        botones = ttk.Frame(marco_log)                      # Marco para alinear dos botones.
        botones.grid(row=2, column=1, sticky="e", pady=6)   # Posicion.
        ttk.Button(botones, text="Iniciar sesion", style="Accent.TButton",  # Boton login.
                   command=self.accion_login).pack(side="left", padx=4)
        ttk.Button(botones, text="Cerrar sesion",           # Boton cerrar sesion.
                   command=self.accion_logout).pack(side="left", padx=4)

    # --- Pestana 2: Generador + Boveda ---------------------------
    def _tab_generador(self, tab):
        """Arma el generador de contrasenas y la boveda cifrada."""
        ttk.Label(tab, text="Generador y boveda de contrasenas",  # Titulo.
                  style="Titulo.TLabel").pack(anchor="w", pady=(0, 10))

        fila = ttk.Frame(tab)                               # Fila: proposito + longitud + generar.
        fila.pack(fill="x", pady=4)                         # A lo ancho.
        ttk.Label(fila, text="Proposito:").pack(side="left")  # Etiqueta del proposito.
        self.gen_proposito = ttk.Entry(fila, width=22)      # Campo del proposito (ej. "Correo UTP").
        self.gen_proposito.pack(side="left", padx=6)        # Posicion.
        ttk.Label(fila, text="Long.:").pack(side="left")    # Etiqueta de longitud.
        self.gen_longitud = ttk.Spinbox(fila, from_=8, to=64, width=5)  # Selector de longitud.
        self.gen_longitud.set(16)                           # Valor por defecto: 16.
        self.gen_longitud.pack(side="left", padx=6)         # Posicion.
        ttk.Button(fila, text="Generar", style="Accent.TButton",  # Boton generar.
                   command=self.accion_generar).pack(side="left", padx=6)

        fila2 = ttk.Frame(tab)                              # Fila: resultado + copiar + guardar.
        fila2.pack(fill="x", pady=6)                        # A lo ancho.
        self.gen_resultado = ttk.Entry(fila2, font=("Consolas", 11))  # Campo del resultado.
        self.gen_resultado.pack(side="left", fill="x", expand=True)  # Ocupa el espacio.
        ttk.Button(fila2, text="Copiar",                    # Boton copiar al portapapeles.
                   command=self.accion_copiar).pack(side="left", padx=4)
        ttk.Button(fila2, text="Guardar en boveda", style="Accent.TButton",  # Boton guardar.
                   command=self.accion_guardar_entrada).pack(side="left", padx=4)

        self.gen_fortaleza = ttk.Label(tab, text="Fortaleza: -")  # Etiqueta de fortaleza.
        self.gen_fortaleza.pack(anchor="w")                 # A la izquierda.

        # --- Tabla de la boveda ---
        ttk.Label(tab, text="Boveda (cifrada con tu llave maestra):",  # Titulo de la tabla.
                  style="Titulo.TLabel").pack(anchor="w", pady=(10, 4))

        cols = ("proposito", "clave", "fecha")              # Columnas de la tabla.
        self.tree = ttk.Treeview(tab, columns=cols, show="headings", height=7)  # Tabla de entradas.
        self.tree.heading("proposito", text="Proposito")    # Encabezado de la columna proposito.
        self.tree.heading("clave", text="Contrasena")       # Encabezado de la columna contrasena.
        self.tree.heading("fecha", text="Fecha")            # Encabezado de la columna fecha.
        self.tree.column("proposito", width=200)            # Ancho de la columna proposito.
        self.tree.column("clave", width=220)                # Ancho de la columna contrasena.
        self.tree.column("fecha", width=130)                # Ancho de la columna fecha.
        self.tree.pack(fill="both", expand=True, pady=4)    # Ocupa el espacio disponible.
        self.tree.bind("<Double-1>", self.accion_copiar_entrada)  # Doble clic: copia la contrasena.

        fila3 = ttk.Frame(tab)                              # Fila de botones de la boveda.
        fila3.pack(anchor="w", pady=4)                      # Posicion.
        ttk.Button(fila3, text="Mostrar/Ocultar",           # Boton mostrar/ocultar contrasenas.
                   command=self.accion_toggle_mostrar).pack(side="left", padx=4)
        ttk.Button(fila3, text="Eliminar seleccionada",     # Boton eliminar entrada.
                   command=self.accion_eliminar_entrada).pack(side="left", padx=4)

    # --- Pestana 3: Cifrado --------------------------------------
    def _tab_cifrado(self, tab):
        """Arma el cifrado/descifrado de archivos EN EL MISMO lugar."""
        ttk.Label(tab, text="Cifrar / Descifrar archivos",  # Titulo.
                  style="Titulo.TLabel").pack(anchor="w", pady=(0, 8))

        ttk.Label(tab, text="El archivo se cifra y descifra EN EL MISMO lugar (no se crean copias).",
                  foreground=TEAL).pack(anchor="w")          # Aviso del comportamiento in-place.
        ttk.Label(tab, text="Requiere iniciar sesion y desbloquear la llave maestra.",  # Aviso del gate.
                  foreground=TEAL).pack(anchor="w", pady=(0, 8))

        ttk.Button(tab, text="Seleccionar archivo...",      # Boton para elegir archivo.
                   command=self.seleccionar_archivo_cifrar).pack(anchor="w", pady=4)
        self.cif_ruta = ttk.Label(tab, text="Ningun archivo seleccionado.")  # Muestra la ruta.
        self.cif_ruta.pack(anchor="w", pady=4)              # Posicion.

        fila_clave = ttk.Frame(tab)                         # Fila para la contrasena del archivo.
        fila_clave.pack(anchor="w", pady=6)                 # Posicion.
        ttk.Label(fila_clave, text="Contrasena del archivo:").pack(side="left")  # Etiqueta.
        self.cif_clave = ttk.Entry(fila_clave, width=28, show="*")  # Campo de clave (oculta).
        self.cif_clave.pack(side="left", padx=8)            # Posicion.

        fila = ttk.Frame(tab)                               # Fila de botones cifrar/descifrar.
        fila.pack(anchor="w", pady=10)                      # Posicion.
        ttk.Button(fila, text="Cifrar", style="Accent.TButton",  # Boton cifrar.
                   command=self.accion_cifrar).pack(side="left", padx=4)
        ttk.Button(fila, text="Descifrar",                  # Boton descifrar.
                   command=self.accion_descifrar).pack(side="left", padx=4)

        self.cif_resultado = ttk.Label(tab, text="", font=("Segoe UI", 10, "bold"))  # Mensaje resultado.
        self.cif_resultado.pack(anchor="w", pady=8)         # Posicion.

    # --- Pestana 4: Integridad -----------------------------------
    def _tab_integridad(self, tab):
        """Arma la firma y verificacion de integridad (HMAC-SHA256)."""
        ttk.Label(tab, text="Firmar / Verificar integridad",  # Titulo.
                  style="Titulo.TLabel").pack(anchor="w", pady=(0, 8))

        ttk.Label(tab, text="Genera un sello HMAC-SHA256 del archivo y detecta si fue alterado.",
                  foreground=TEAL).pack(anchor="w")          # Explicacion.
        ttk.Label(tab, text="Requiere iniciar sesion y desbloquear la llave maestra.",  # Aviso del gate.
                  foreground=TEAL).pack(anchor="w", pady=(0, 8))

        ttk.Button(tab, text="Seleccionar archivo...",      # Boton para elegir archivo.
                   command=self.seleccionar_archivo_verificar).pack(anchor="w", pady=4)
        self.int_ruta = ttk.Label(tab, text="Ningun archivo seleccionado.")  # Muestra la ruta.
        self.int_ruta.pack(anchor="w", pady=4)              # Posicion.

        fila_clave = ttk.Frame(tab)                         # Fila para la contrasena de firma.
        fila_clave.pack(anchor="w", pady=6)                 # Posicion.
        ttk.Label(fila_clave, text="Contrasena de firma:").pack(side="left")  # Etiqueta.
        self.int_clave = ttk.Entry(fila_clave, width=28, show="*")  # Campo de clave (oculta).
        self.int_clave.pack(side="left", padx=8)            # Posicion.

        fila = ttk.Frame(tab)                               # Fila con dos botones.
        fila.pack(anchor="w", pady=10)                      # Posicion.
        ttk.Button(fila, text="Firmar archivo",             # Boton: genera el sello HMAC.
                   command=self.accion_firmar).pack(side="left", padx=4)
        ttk.Button(fila, text="Verificar integridad", style="Accent.TButton",  # Boton verificar.
                   command=self.accion_verificar).pack(side="left", padx=4)

        self.int_resultado = ttk.Label(tab, text="", font=("Segoe UI", 11, "bold"))  # Resultado.
        self.int_resultado.pack(anchor="w", pady=8)         # Posicion.

    # --- Pestana 5: Llave maestra --------------------------------
    def _tab_llave(self, tab):
        """Arma la gestion de la llave maestra (crear / desbloquear / bloquear)."""
        ttk.Label(tab, text="Llave maestra",                # Titulo.
                  style="Titulo.TLabel").pack(anchor="w", pady=(0, 8))

        ttk.Label(tab, text="La llave maestra desbloquea la DEK que cifra tu boveda y habilita las funciones.",
                  foreground=TEAL).pack(anchor="w", pady=(0, 8))  # Explicacion.

        self.llave_estado = ttk.Label(tab, text="")         # Etiqueta del estado de la llave.
        self.llave_estado.pack(anchor="w", pady=6)          # Posicion.

        fila = ttk.Frame(tab)                               # Fila de botones.
        fila.pack(anchor="w", pady=6)                       # Posicion.
        ttk.Button(fila, text="Crear llave maestra", style="Accent.TButton",  # Boton crear.
                   command=self.accion_crear_llave).pack(side="left", padx=4)
        ttk.Button(fila, text="Desbloquear",                # Boton desbloquear.
                   command=self.accion_desbloquear).pack(side="left", padx=4)
        ttk.Button(fila, text="Bloquear",                   # Boton bloquear (borra la DEK de memoria).
                   command=self.accion_bloquear).pack(side="left", padx=4)

        ttk.Label(tab, text="Aviso: si olvidas tu llave maestra, no se puede recuperar la boveda.",
                  foreground=ROJO_ERR).pack(anchor="w", pady=(10, 0))  # Aviso importante.
        self._actualizar_estado_llave()                     # Muestra el estado actual.

    # --- Pestana 6: Ataque/Defensa -------------------------------
    def _tab_demos(self, tab):
        """Arma la pestana que ejecuta y muestra las demostraciones."""
        ttk.Label(tab, text="Demostracion: Ataque vs Defensa",  # Titulo.
                  style="Titulo.TLabel").pack(anchor="w", pady=(0, 8))

        ttk.Button(tab, text="Ejecutar demostraciones", style="Accent.TButton",  # Boton ejecutar.
                   command=self.accion_demos).pack(anchor="w", pady=6)

        self.demo_salida = scrolledtext.ScrolledText(tab, height=15, width=84,  # Area de texto.
                                                     font=("Consolas", 9),
                                                     bg="#0F1B2D", fg="#D8DEE4")  # Estilo "consola".
        self.demo_salida.pack(fill="both", expand=True, pady=8)  # Ocupa el espacio disponible.

    # ----------------------------------------------------------------
    #  GATE: control de acceso por pop-up
    # ----------------------------------------------------------------
    def _requiere_dek(self):
        """Devuelve True solo si hay sesion Y llave maestra desbloqueada; si no, avisa con pop-up."""
        if sesion["usuario"] is None:             # Si no hay sesion iniciada...
            messagebox.showwarning("Acceso restringido",  # ...muestra un pop-up...
                                   "Debes iniciar sesion o registrarte para usar esta funcion.")
            return False                          # ...y bloquea la accion.
        if sesion["dek"] is None:                 # Si hay sesion pero la llave esta bloqueada...
            messagebox.showwarning("Llave maestra requerida",  # ...muestra un pop-up...
                                   "Debes desbloquear tu llave maestra para usar esta funcion.")
            return False                          # ...y bloquea la accion.
        return True                               # Todo en orden: permite la accion.

    # ----------------------------------------------------------------
    #  Flujos de la llave maestra (dialogos)
    # ----------------------------------------------------------------
    def _flujo_crear_llave_maestra(self, usuario):
        """Pide dos veces la nueva llave maestra, la crea y carga la DEK en memoria."""
        if tiene_llave_maestra(usuario):          # Si el usuario ya tiene llave maestra...
            messagebox.showinfo("Llave maestra", "Este usuario ya tiene una llave maestra.")  # Avisa que ya existe una llave maestra.
            return False                          # ...no crea otra (regla de una sola llave).
        p1 = simpledialog.askstring("Crear llave maestra",  # Pide la nueva llave maestra.
                                    "Crea tu LLAVE MAESTRA (minimo 8 caracteres).\n"
                                    "OJO: no se puede recuperar si la olvidas.",
                                    show="*", parent=self.root)
        if not p1:                                # Si cancelo o dejo vacio...
            return False                          # ...no hace nada.
        if len(p1) < 8:                           # Si es demasiado corta...
            messagebox.showwarning("Atencion", "La llave maestra debe tener al menos 8 caracteres.")  # Rechaza: llave maestra muy corta.
            return False                          # ...la rechaza.
        p2 = simpledialog.askstring("Confirmar llave maestra",  # Pide confirmar la llave.
                                    "Escribe de nuevo tu llave maestra:",
                                    show="*", parent=self.root)
        if p1 != p2:                              # Si las dos no coinciden...
            messagebox.showerror("Error", "Las llaves maestras no coinciden.")  # Rechaza: las llaves maestras no coinciden.
            return False                          # ...la rechaza.
        if verificar_login(usuario, p1):          # Si la llave maestra coincide con la contrasena de login...
            messagebox.showerror("Error",         # ...se rechaza (deben ser credenciales distintas).
                "La llave maestra no puede ser igual a tu contrasena de cuenta.\n"
                "Elige una llave maestra diferente.")
            return False                          # No se crea la llave maestra.
        dek = crear_llave_maestra(usuario, p1)    # Crea la DEK y la envuelve con la KEK.
        sesion["dek"] = dek                       # Carga la DEK en memoria (queda desbloqueada).
        return True                               # Exito.

    def _flujo_desbloquear(self, usuario):
        """Pide la llave maestra y, si es correcta, carga la DEK en memoria."""
        pw = simpledialog.askstring("Llave maestra",  # Pide la llave maestra.
                                    "Escribe tu llave maestra para desbloquear:",
                                    show="*", parent=self.root)
        if not pw:                                # Si cancelo o dejo vacio...
            return False                          # ...no hace nada.
        try:                                      # Intenta desbloquear.
            dek = desbloquear_dek(usuario, pw)    # Desenvuelve la DEK con la llave maestra.
        except ValueError as e:                   # Si la llave es incorrecta...
            messagebox.showerror("Error", str(e))  # ...muestra el error.
            return False                          # ...y falla.
        sesion["dek"] = dek                       # Carga la DEK en memoria.
        return True                               # Exito.

    def _post_autenticacion(self):
        """Actualiza la interfaz tras iniciar sesion o cambiar el estado de la llave."""
        self._actualizar_estado_sesion()          # Refresca el estado de la sesion en el encabezado.
        self._actualizar_estado_llave()           # Refresca el estado de la llave maestra.
        self._refrescar_boveda()                  # Refresca la tabla de la boveda.

    # ----------------------------------------------------------------
    #  ACCIONES - Autenticacion
    # ----------------------------------------------------------------
    def accion_registrar(self):
        """Registra un usuario y lo obliga a crear su llave maestra."""
        usuario = self.reg_usuario.get().strip()  # Lee el usuario del campo.
        clave = self.reg_clave.get()              # Lee la contrasena del campo.
        if not usuario:                           # Si el usuario esta vacio...
            messagebox.showwarning("Atencion", "El usuario no puede estar vacio.")  # Avisa.
            return                                # Sale.
        if len(clave) < 8:                        # Si la clave es corta...
            messagebox.showwarning("Atencion", "La contrasena debe tener al menos 8 caracteres.")  # Rechaza: contrasena de login muy corta.
            return                                # Sale.
        if not registrar_usuario(usuario, clave):  # Intenta registrar; si ya existia...
            messagebox.showerror("Error", "Ese usuario ya existe.")  # ...avisa.
            return                                # Sale.

        messagebox.showinfo("Usuario creado",     # Confirma el registro...
                            f"Usuario '{usuario}' registrado. Ahora crea tu llave maestra.")
        sesion["usuario"] = usuario.strip().lower()  # Deja al usuario con sesion iniciada.
        if self._flujo_crear_llave_maestra(sesion["usuario"]):  # Fuerza crear la llave maestra.
            messagebox.showinfo("Listo", "Llave maestra creada. Ya puedes usar todas las funciones.")
        self._post_autenticacion()                # Actualiza la interfaz.
        self.reg_usuario.delete(0, "end")         # Limpia el campo usuario.
        self.reg_clave.delete(0, "end")           # Limpia el campo clave.

    def accion_login(self):
        """Inicia sesion y pide (o crea) la llave maestra."""
        usuario = self.log_usuario.get().strip()  # Lee el usuario.
        clave = self.log_clave.get()              # Lee la clave.
        if not verificar_login(usuario, clave):   # Si las credenciales son incorrectas...
            messagebox.showerror("Error", "Credenciales incorrectas.")  # ...avisa.
            return                                # Sale.

        sesion["usuario"] = usuario.strip().lower()  # Guarda al usuario en la sesion.
        if tiene_llave_maestra(sesion["usuario"]):  # Si ya tiene llave maestra...
            if not self._flujo_desbloquear(sesion["usuario"]):  # ...pide desbloquearla.
                messagebox.showwarning("Llave maestra",  # Si no la desbloquea...
                    "Sesion iniciada, pero debes desbloquear tu llave maestra para usar las funciones.")
        else:                                     # Si aun no tiene llave maestra...
            messagebox.showinfo("Llave maestra", "Aun no tienes llave maestra. Debes crearla ahora.")  # Avisa que debe crear su llave maestra.
            self._flujo_crear_llave_maestra(sesion["usuario"])  # ...la crea.

        self._post_autenticacion()                # Actualiza la interfaz.
        self.log_clave.delete(0, "end")           # Limpia la clave.

    def accion_logout(self):
        """Cierra la sesion y borra la DEK de la memoria."""
        sesion["usuario"] = None                  # Borra el usuario de la sesion.
        sesion["dek"] = None                      # Borra la DEK (bloquea la boveda).
        self.entradas = []                        # Vacia la copia de entradas en memoria.
        self._post_autenticacion()                # Actualiza la interfaz.
        messagebox.showinfo("Sesion", "Sesion cerrada.")  # Confirma.

    # ----------------------------------------------------------------
    #  ACCIONES - Generador y boveda
    # ----------------------------------------------------------------
    def accion_generar(self):
        """Genera una contrasena segura y la muestra (requiere llave maestra)."""
        if not self._requiere_dek():              # Gate: exige sesion + llave desbloqueada.
            return                                # Sale si no cumple.
        try:                                      # Intenta leer la longitud.
            longitud = int(self.gen_longitud.get())  # Convierte el valor a numero.
        except ValueError:                        # Si no es un numero valido...
            longitud = 16                         # ...usa 16 por defecto.
        clave = generar_contrasena(longitud)      # Genera la contrasena.
        self.gen_resultado.delete(0, "end")       # Limpia el campo del resultado.
        self.gen_resultado.insert(0, clave)       # Muestra la contrasena generada.
        self.gen_fortaleza.config(text=f"Fortaleza: {evaluar_fortaleza(clave)}")  # Muestra fortaleza.

    def accion_copiar(self):
        """Copia la contrasena generada al portapapeles."""
        clave = self.gen_resultado.get()          # Lee la contrasena mostrada.
        if clave:                                 # Si hay algo que copiar...
            self.root.clipboard_clear()           # Limpia el portapapeles.
            self.root.clipboard_append(clave)     # Copia la contrasena.
            messagebox.showinfo("Copiado", "Contrasena copiada al portapapeles.")  # Confirma.

    def accion_guardar_entrada(self):
        """Guarda la contrasena generada en la boveda, cifrada con la DEK (requiere llave)."""
        if not self._requiere_dek():              # Gate: exige sesion + llave desbloqueada.
            return                                # Sale si no cumple.
        proposito = self.gen_proposito.get().strip()  # Lee el proposito.
        clave = self.gen_resultado.get()          # Lee la contrasena generada.
        if not proposito:                         # Si no hay proposito...
            messagebox.showwarning("Atencion", "Escribe para que sera la contrasena (proposito).")  # Exige escribir un proposito.
            return                                # Sale.
        if not clave:                             # Si no hay contrasena generada...
            messagebox.showwarning("Atencion", "Genera una contrasena primero.")  # Avisa.
            return                                # Sale.
        agregar_entrada(sesion["usuario"], sesion["dek"], proposito, clave)  # Guarda cifrada.
        self.gen_proposito.delete(0, "end")       # Limpia el campo proposito.
        self.gen_resultado.delete(0, "end")       # Limpia el campo de la contrasena generada (no queda visible).
        self.gen_fortaleza.config(text="Fortaleza: -")  # Reinicia la etiqueta de fortaleza.
        self._refrescar_boveda()                  # Actualiza la tabla.
        messagebox.showinfo("Boveda", "Contrasena guardada en tu boveda (cifrada con la DEK).")  # Confirma el guardado en la boveda.

    def accion_toggle_mostrar(self):
        """Muestra u oculta las contrasenas de la boveda (requiere llave)."""
        if not self._requiere_dek():              # Gate: exige sesion + llave desbloqueada.
            return                                # Sale si no cumple.
        self.mostrar_claves = not self.mostrar_claves  # Invierte la bandera mostrar/ocultar.
        self._refrescar_boveda()                  # Refresca la tabla con el nuevo estado.

    def accion_eliminar_entrada(self):
        """Elimina la entrada seleccionada de la boveda (requiere llave)."""
        if not self._requiere_dek():              # Gate: exige sesion + llave desbloqueada.
            return                                # Sale si no cumple.
        sel = self.tree.selection()               # Toma la fila seleccionada.
        if not sel:                               # Si no hay seleccion...
            messagebox.showwarning("Atencion", "Selecciona una entrada de la boveda.")  # Avisa.
            return                                # Sale.
        indice = int(sel[0])                      # El id de la fila es el indice de la entrada.
        eliminar_entrada(sesion["usuario"], sesion["dek"], indice)  # Elimina y re-cifra la boveda.
        self._refrescar_boveda()                  # Actualiza la tabla.

    def accion_copiar_entrada(self, event=None):
        """Copia al portapapeles la contrasena de la entrada con doble clic."""
        if sesion["dek"] is None:                 # Si la boveda esta bloqueada...
            return                                # ...no hace nada.
        sel = self.tree.selection()               # Toma la fila seleccionada.
        if not sel:                               # Si no hay seleccion...
            return                                # ...sale.
        indice = int(sel[0])                      # Indice de la entrada.
        clave = self.entradas[indice]["contrasena"]  # Toma la contrasena real.
        self.root.clipboard_clear()               # Limpia el portapapeles.
        self.root.clipboard_append(clave)         # Copia la contrasena.
        messagebox.showinfo("Copiado", "Contrasena copiada al portapapeles.")  # Confirma.

    def _refrescar_boveda(self):
        """Vuelve a leer la boveda (descifrandola con la DEK) y llena la tabla."""
        for item in self.tree.get_children():     # Recorre las filas actuales...
            self.tree.delete(item)                # ...y las borra.
        if sesion["usuario"] is None or sesion["dek"] is None:  # Si no hay llave desbloqueada...
            self.entradas = []                    # ...deja la lista vacia.
            return                                # ...y no muestra nada (boveda bloqueada).
        self.entradas = leer_entradas(sesion["usuario"], sesion["dek"])  # Descifra las entradas.
        for i, e in enumerate(self.entradas):     # Recorre cada entrada...
            clave_mostrada = e["contrasena"] if self.mostrar_claves else "•" * 10  # Real u oculta.
            self.tree.insert("", "end", iid=str(i),  # Inserta la fila (iid = indice)...
                             values=(e["proposito"], clave_mostrada, e.get("fecha", "")))

    # ----------------------------------------------------------------
    #  ACCIONES - Cifrado de archivos
    # ----------------------------------------------------------------
    def seleccionar_archivo_cifrar(self):
        """Abre el explorador para elegir el archivo a cifrar/descifrar."""
        if not self._requiere_dek():              # Gate: exige sesion + llave desbloqueada.
            return                                # Sale si no cumple.
        ruta = filedialog.askopenfilename()       # Muestra el dialogo de seleccion.
        if ruta:                                  # Si el usuario eligio un archivo...
            self.archivo_cifrar = ruta            # Guarda la ruta.
            self.cif_ruta.config(text=ruta)       # La muestra en pantalla.

    def accion_cifrar(self):
        """Cifra el archivo seleccionado EN EL MISMO lugar (requiere llave)."""
        if not self._requiere_dek():              # Gate: exige sesion + llave desbloqueada.
            return                                # Sale si no cumple.
        if not self.archivo_cifrar:               # Si no hay archivo seleccionado...
            messagebox.showwarning("Atencion", "Selecciona un archivo primero.")  # Avisa.
            return                                # Sale.
        clave = self.cif_clave.get()              # Lee la contrasena del archivo.
        if len(clave) < 8:                        # Si la contrasena es corta...
            messagebox.showwarning("Atencion", "La contrasena debe tener al menos 8 caracteres.")  # Rechaza: contrasena de archivo muy corta.
            return                                # Sale.
        try:                                      # Intenta cifrar.
            cifrar_archivo(self.archivo_cifrar, clave)  # Cifra EN EL MISMO archivo.
            self.cif_resultado.config(text="Archivo cifrado en su lugar (sin crear copias).",
                                      foreground=VERDE_OK)        # Mensaje en verde.
        except Exception as e:                    # Si hay error...
            self.cif_resultado.config(text=f"Error: {e}", foreground=ROJO_ERR)  # Lo muestra en rojo.

    def accion_descifrar(self):
        """Descifra el archivo seleccionado EN EL MISMO lugar (requiere llave)."""
        if not self._requiere_dek():              # Gate: exige sesion + llave desbloqueada.
            return                                # Sale si no cumple.
        if not self.archivo_cifrar:               # Si no hay archivo...
            messagebox.showwarning("Atencion", "Selecciona un archivo primero.")  # Avisa.
            return                                # Sale.
        clave = self.cif_clave.get()              # Lee la contrasena del archivo.
        if not clave:                             # Si no escribio contrasena...
            messagebox.showwarning("Atencion", "Escribe la contrasena del archivo.")  # Avisa.
            return                                # Sale.
        try:                                      # Intenta descifrar.
            descifrar_archivo(self.archivo_cifrar, clave)  # Descifra EN EL MISMO archivo.
            self.cif_resultado.config(text="Archivo descifrado en su lugar (mismo archivo).",
                                      foreground=VERDE_OK)        # Mensaje en verde.
        except Exception as e:                    # Si hay error (alteracion, clave mala)...
            self.cif_resultado.config(text=f"Error: {e}", foreground=ROJO_ERR)  # Lo muestra en rojo.

    # ----------------------------------------------------------------
    #  ACCIONES - Integridad
    # ----------------------------------------------------------------
    def seleccionar_archivo_verificar(self):
        """Abre el explorador para elegir el archivo a firmar/verificar."""
        if not self._requiere_dek():              # Gate: exige sesion + llave desbloqueada.
            return                                # Sale si no cumple.
        ruta = filedialog.askopenfilename()       # Dialogo de seleccion.
        if ruta:                                  # Si eligio archivo...
            self.archivo_verificar = ruta         # Guarda la ruta.
            self.int_ruta.config(text=ruta)       # La muestra.

    def accion_firmar(self):
        """Genera la firma HMAC del archivo seleccionado (requiere llave)."""
        if not self._requiere_dek():              # Gate: exige sesion + llave desbloqueada.
            return                                # Sale si no cumple.
        if not self.archivo_verificar:            # Si no hay archivo...
            messagebox.showwarning("Atencion", "Selecciona un archivo primero.")  # Avisa.
            return                                # Sale.
        clave = self.int_clave.get()              # Lee la contrasena de firma.
        if not clave:                             # Si no escribio contrasena...
            messagebox.showwarning("Atencion", "Escribe la contrasena de firma.")  # Avisa.
            return                                # Sale.
        try:                                      # Intenta firmar.
            firmar_archivo(self.archivo_verificar, clave)  # Calcula y guarda el HMAC.
            self.int_resultado.config(text="Firma HMAC generada y guardada.",  # Mensaje.
                                      foreground=VERDE_OK)  # En verde.
        except Exception as e:                    # Si hay error...
            self.int_resultado.config(text=f"Error: {e}", foreground=ROJO_ERR)  # En rojo.

    def accion_verificar(self):
        """Verifica la firma HMAC del archivo (requiere llave)."""
        if not self._requiere_dek():              # Gate: exige sesion + llave desbloqueada.
            return                                # Sale si no cumple.
        if not self.archivo_verificar:            # Si no hay archivo...
            messagebox.showwarning("Atencion", "Selecciona un archivo primero.")  # Avisa.
            return                                # Sale.
        clave = self.int_clave.get()              # Lee la contrasena de firma.
        if not clave:                             # Si no escribio contrasena...
            messagebox.showwarning("Atencion", "Escribe la contrasena de firma.")  # Avisa.
            return                                # Sale.
        if verificar_firma(self.archivo_verificar, clave):  # Si la firma coincide...
            self.int_resultado.config(text="INTACTO: la firma coincide, el archivo no fue alterado.",  # Muestra resultado: archivo intacto (verde).
                                      foreground=VERDE_OK)        # En verde.
        else:                                     # Si no coincide, no hay firma o la clave es mala...
            self.int_resultado.config(text="ALTERADO, sin firma registrada o clave incorrecta.",  # Muestra resultado: archivo alterado (rojo).
                                      foreground=ROJO_ERR)        # En rojo.

    # ----------------------------------------------------------------
    #  ACCIONES - Llave maestra
    # ----------------------------------------------------------------
    def accion_crear_llave(self):
        """Boton 'Crear llave maestra' de la pestana Llave maestra."""
        if sesion["usuario"] is None:             # Si no hay sesion...
            messagebox.showwarning("Acceso restringido", "Primero inicia sesion o registrate.")  # Exige iniciar sesion antes de crear la llave.
            return                                # Sale.
        if self._flujo_crear_llave_maestra(sesion["usuario"]):  # Intenta crear la llave.
            messagebox.showinfo("Llave maestra", "Llave maestra creada y desbloqueada.")  # Confirma.
        self._post_autenticacion()                # Actualiza la interfaz.

    def accion_desbloquear(self):
        """Boton 'Desbloquear' de la pestana Llave maestra."""
        if sesion["usuario"] is None:             # Si no hay sesion...
            messagebox.showwarning("Acceso restringido", "Primero inicia sesion.")  # Avisa.
            return                                # Sale.
        if not tiene_llave_maestra(sesion["usuario"]):  # Si no tiene llave maestra...
            messagebox.showinfo("Llave maestra", "Este usuario no tiene llave maestra. Crea una.")  # Avisa que no hay llave maestra que desbloquear.
            return                                # Sale.
        if self._flujo_desbloquear(sesion["usuario"]):  # Intenta desbloquear.
            messagebox.showinfo("Llave maestra", "Llave maestra desbloqueada.")  # Confirma.
        self._post_autenticacion()                # Actualiza la interfaz.

    def accion_bloquear(self):
        """Boton 'Bloquear': borra la DEK de la memoria (cierra la boveda)."""
        sesion["dek"] = None                      # Borra la DEK de la memoria.
        self.entradas = []                        # Vacia la copia de entradas.
        self._post_autenticacion()                # Actualiza la interfaz.
        messagebox.showinfo("Llave maestra", "Boveda bloqueada.")  # Confirma.

    # ----------------------------------------------------------------
    #  ACCIONES - Demostraciones
    # ----------------------------------------------------------------
    def accion_demos(self):
        """Ejecuta las demostraciones y muestra el resultado en el area de texto."""
        texto = ejecutar_demos()                  # Obtiene el reporte completo.
        self.demo_salida.delete("1.0", "end")     # Limpia el area de texto.
        self.demo_salida.insert("1.0", texto)     # Inserta el reporte.

    # ----------------------------------------------------------------
    #  Utilidades de actualizacion de la interfaz
    # ----------------------------------------------------------------
    def _actualizar_estado_sesion(self):
        """Actualiza la etiqueta del encabezado con el usuario y estado de la llave."""
        if sesion["usuario"] is None:             # Si no hay sesion...
            texto = "Sesion: invitado"            # ...muestra invitado.
        elif sesion["dek"] is None:               # Si hay sesion pero la llave esta bloqueada...
            texto = f"Sesion: {sesion['usuario']} (bloqueada)"  # ...lo indica.
        else:                                     # Si esta todo desbloqueado...
            texto = f"Sesion: {sesion['usuario']} (desbloqueada)"  # ...lo indica.
        self.lbl_sesion.config(text=texto)        # Aplica el texto en el encabezado.

    def _actualizar_estado_llave(self):
        """Actualiza la etiqueta de estado en la pestana Llave maestra."""
        if not hasattr(self, "llave_estado"):     # Si aun no existe la etiqueta...
            return                                # ...no hace nada.
        if sesion["usuario"] is None:             # Si no hay sesion...
            self.llave_estado.config(text="Estado: sin sesion iniciada.", foreground=NAVY)  # Estado: sin sesion iniciada.
        elif sesion["dek"] is not None:           # Si la llave esta desbloqueada...
            self.llave_estado.config(text="Estado: llave maestra desbloqueada.", foreground=VERDE_OK)  # Estado: llave desbloqueada (verde).
        elif tiene_llave_maestra(sesion["usuario"]):  # Si tiene llave pero esta bloqueada...
            self.llave_estado.config(text="Estado: tiene llave maestra, pero esta bloqueada.",  # Estado: llave creada pero bloqueada (rojo).
                                     foreground=ROJO_ERR)
        else:                                     # Si no tiene llave maestra todavia...
            self.llave_estado.config(text="Estado: aun no has creado tu llave maestra.",  # Estado: sin llave maestra todavia (rojo).
                                     foreground=ROJO_ERR)


# ====================================================================
#  PUNTO DE ENTRADA DEL PROGRAMA
# ====================================================================
def main():
    """Crea la ventana principal y arranca la aplicacion grafica."""
    root = tk.Tk()                  # Crea la ventana raiz de Tkinter.
    app = FortinApp(root)          # Construye la aplicacion sobre esa ventana.
    root.mainloop()                # Bucle principal: mantiene la ventana abierta.


# Esta condicion es verdadera solo si se ejecuta este archivo directamente.
if __name__ == "__main__":          # Punto de entrada.
    main()                          # Lanza la interfaz grafica.
