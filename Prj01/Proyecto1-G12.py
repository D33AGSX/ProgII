# bcript & token & cipher + digital signature.

import tkinter as tk  # Importa la librería para crear ventanas y componentes visuales.
from tkinter import messagebox  # Importa el módulo para desplegar cuadros de alerta y ventanas flotantes.
import os  # Importa funciones del sistema operativo para interactuar con archivos en el disco.
import json  # Importa utilidades para leer, estructurar y escribir texto en formato JSON.
import bcrypt  # Importa las funciones criptográficas para hashear y verificar contraseñas.
import secrets  # Importa la librería criptográfica para generar tokens aleatorios e impredecibles.
import time  # Importa la librería de control de tiempo para capturar marcas de reloj del sistema.
from cryptography.fernet import Fernet  # Importa el algoritmo de cifrado simétrico AES-Fernet.
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # Importa la función de derivación de claves PBKDF2.
from cryptography.hazmat.primitives import hashes  # Importa el módulo de algoritmos hash para la KDF y HMAC.
from cryptography.hazmat.primitives.hmac import HMAC  # Importa el módulo para generar y verificar firmas HMAC.
import base64  # Importa la librería para codificar la llave generada en formato Base64 estándar.

ARCHIVO_USUARIOS = "usuarios_boveda.txt"  # Asigna a una variable constante el nombre del archivo de base de datos local.
ARCHIVO_FIRMA = "firma_boveda.txt"  # Asigna a una variable constante el nombre del archivo donde se guardará la firma digital.

# ==========================================
# VARIABLES GLOBALES EN MEMORIA PARA TOKENS
# ==========================================
TOKEN_SISTEMA = { # Un Diccionario
    "valor": "",  # Guardará la cadena de texto aleatoria generada.
    "tiempo_creacion": 0.0  # Guardará el segundo exacto en el que se creó.
}

TIEMPO_EXPIRACION = 15  # Define la constante de tiempo máximo de vida del token en segundos.


# ==========================================
# LÓGICA DE APOYO CRIPTOGRÁFICO: KDF REAL
# ==========================================

def derivar_llave(contrasena_texto, salt):  # Declara la función encargada de transformar una contraseña común en una llave AES válida usando un salt dinámico.
    contrasena_bytes = contrasena_texto.encode('utf-8')  # Convierte la contraseña de texto plano introducida a formato de bytes.
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Define que usará SHA-256 como base interna de hashing.
        length=32,  # Especifica que la llave final resultante debe medir exactamente 32 bytes (requerido por AES).
        salt=salt,  # Se utiliza el salt único provisto por parámetro para esta operación específica.
        iterations=100000  # Define el número de vueltas de procesamiento para mitigar ataques de fuerza bruta.
    )
    
    llave_bytes = kdf.derive(contrasena_bytes)  # Ejecuta los cálculos matemáticos de derivación sobre los bytes de la contraseña.
    return base64.urlsafe_b64encode(llave_bytes)  # Devuelve la llave codificada en Base64 seguro, lista para ser usada por Fernet.


# ==========================================
# LÓGICA DE CIBERSEGURIDAD: BCRYPT
# ==========================================

def cargar_usuarios():  # Declara la función de apoyo encargada de leer los datos guardados en disco de forma segura.
    if not os.path.exists(ARCHIVO_USUARIOS):  # Evalúa mediante el sistema operativo si el archivo no se encuentra en la ruta.
        return {}  # Detiene la función retornando un diccionario vacío si el archivo físico no existe.
    try:  # Inicia un bloque de prueba por si el contenido del archivo está dañado o mal estructurado.
        with open(ARCHIVO_USUARIOS, "r") as archivo:  # Abre el archivo físico en modo exclusivo de lectura ("r").
            return json.load(archivo)  # Decodifica la cadena JSON del archivo y la transforma en un diccionario nativo de Python.
    except Exception:  # Si el archivo está cifrado o corrupto, captura el fallo y retorna vacío protegiendo el flujo del programa.
        return {}  # Retorna un diccionario vacío para prevenir que el sistema se caiga.

def guardar_usuarios(usuarios_dict):  # Asegura la existencia del archivo y escribe el diccionario de vuelta al disco.
    with open(ARCHIVO_USUARIOS, "w") as archivo:  # Abre el archivo en modo escritura ("w") para actualizarlo con los datos en claro.
        json.dump(usuarios_dict, archivo, indent=4)  # Convierte el diccionario a texto JSON estructurado visualmente con 4 espacios de sangría.

def registrar_contrasena():  # Declara la función principal que procesa y registra nuevas cuentas.
    usuario = entry_usuario_reg.get().strip()  # Extrae el texto escrito del campo del usuario y borra espacios accidentales en bordes.
    contrasena = entry_pass_reg.get()  # Extrae la cadena de texto exacta escrita en la caja de la contraseña sin alterar espacios.
    
    if not usuario or not contrasena:  # Comprueba lógicamente si alguna de las dos variables obtenidas se quedó vacía.
        messagebox.showwarning("Advertencia", "Por favor, llene ambos campos (Usuario y Contraseña) para registrar.")  # Lanza una ventana flotante de alerta.
        return  # Interrumpe de inmediato la ejecución de la función para impedir registros incompletos.
    
    usuarios = cargar_usuarios()  # Llama a la función que recupera la base de datos de usuarios actual en memoria.
    
    if usuario in usuarios:  # Valida mediante una búsqueda en el diccionario si el nombre de usuario ingresado ya está registrado.
        messagebox.showwarning("Advertencia", f"El usuario '{usuario}' ya está registrado.")  # Muestra una ventana de advertencia de duplicidad.
        return  # Detiene el flujo de la función para proteger la integridad de los registros existentes.
    
    try:  # Inicia un bloque de prueba para capturar errores durante los cálculos criptográficos del hash.
        password_bytes = contrasena.encode('utf-8')  # Codifica la contraseña de texto plano transformándola en la matriz de bytes requerida por bcrypt.
        salt = bcrypt.gensalt()  # Invoca al módulo criptográfico para generar una semilla aleatoria (Salt) única y robusta.
        hash_generado = bcrypt.hashpw(password_bytes, salt).decode('utf-8')  # Mezcla y tritura los bytes calculando el hash, y lo pasa a texto legible.
        
        usuarios[usuario] = hash_generado  # Inserta la clave del nombre del usuario vinculada a su hash correspondiente dentro del diccionario.
        guardar_usuarios(usuarios)  # Pasa el diccionario actualizado a la función encargada de guardarlo físicamente en disco.
        
        print(f"[REGISTRO] Usuario '{usuario}' registrado con éxito.")  # Imprime un registro detallado en la consola interna.
        messagebox.showinfo("Éxito", f"Usuario '{usuario}' registrado correctamente en texto claro dentro del JSON.")  # Muestra ventana flotante de éxito.
        
        entry_usuario_reg.delete(0, tk.END)  # Limpia todo el texto visible contenido en el campo de entrada del usuario de registro.
        entry_pass_reg.delete(0, tk.END)  # Limpia todo el texto visible contenido en el campo de entrada de la contraseña de registro.
        
    except Exception as e:  # Captura cualquier error derivado de problemas en la librería o falta de memoria.
        messagebox.showerror("Error", f"No se pudo registrar el usuario: {e}")  # Despliega una alerta roja detallando la falla criptográfica.

def verificar_contrasena():  # Declara la función encargada de autenticar las solicitudes de acceso al sistema.
    usuario = entry_usuario_ver.get().strip()  # Extrae la entrada de texto de la caja de verificación y limpia espacios accidentales.
    contrasena = entry_pass_ver.get()  # Obtiene la contraseña escrita para la prueba de acceso tal y como fue introducida.
    
    if not usuario or not contrasena:  # Revisa si la persona intentó presionar el botón dejando entradas vacías.
        messagebox.showwarning("Advertencia", "Por favor, llene ambos campos para verificar el acceso.")  # Despliega cuadro visual de advertencia.
        return  # Interrumpe la autenticación inmediatamente al no contar con los datos mínimos obligatorios.
        
    usuarios = cargar_usuarios()  # Lee el archivo de texto y trae el diccionario de usuarios a memoria.
    
    if usuario not in usuarios:  # Implementa mitigación OWASP: si el usuario no existe en la base de datos, detiene el flujo rápido.
        print(f"[VERIFICACIÓN] Intento fallido: El usuario '{usuario}' no existe en esta sesión.")  # Registra el motivo exacto solo en la consola interna.
        messagebox.showerror("Resultado", "Acceso Denegado.\nUsuario o contraseña incorrectos.")  # Lanza un error genérico para despistar atacantes.
        return  # Finaliza la función evitando ejecutar cálculos innecesarios o revelar información sensible.
        
    try:  # Abre un bloque de prueba para manejar el procesamiento criptográfico de la autenticación.
        hash_guardado = usuarios[usuario].encode('utf-8')  # Busca el hash asociado al usuario y lo convierte de vuelta a bytes para la comparación.
        password_prueba_bytes = contrasena.encode('utf-8')  # Transforma la contraseña que se está probando de texto plano a formato de bytes.
        
        if bcrypt.checkpw(password_prueba_bytes, hash_guardado):  # Ejecuta la comprobación matemática interna extrayendo de forma segura el salt del hash guardado.
            print(f"[VERIFICACIÓN] ¡Acceso Permitido! La contraseña de '{usuario}' coincide.")  # Imprime la validación exitosa en terminal.
            messagebox.showinfo("Resultado", f"¡Acceso Permitido!\nLa contraseña coincide para el usuario '{usuario}'.")  # Muestra ventana flotante aprobando el acceso.
        else:  # Se ejecuta si la contraseña de prueba no produce una coincidencia matemática con el hash guardado.
            print(f"[VERIFICACIÓN] Intento fallido: Contraseña incorrecta para '{usuario}'.")  # Registra en la terminal del programador que falló la clave.
            messagebox.showerror("Resultado", "Acceso Denegado.\nUsuario o contraseña incorrectos.")  # Muestra el mismo mensaje genérico idéntico por seguridad.
            
        entry_usuario_ver.delete(0, tk.END)  # Vierte en blanco la caja de texto del usuario de la subsección de login.
        entry_pass_ver.delete(0, tk.END)  # Vierte en blanco la caja de texto de la contraseña de la subsección de login.
        
    except Exception as e:  # Captura fallos inesperados en la codificación de caracteres o problemas internos.
        messagebox.showerror("Error", f"Ocurrió un problema al verificar: {e}")  # Informa mediante cuadro visual del fallo técnico imprevisto.


# ==========================================
# LÓGICA DE CIBERSEGURIDAD: TOKENS EXPIRABLES
# ==========================================

def generar_token():  # Declara la función encargada de crear tokens seguros con expiración controlada.
    token_generado = secrets.token_hex(4)  # Genera una cadena aleatoria criptográficamente segura de 8 caracteres hexadecimales.
    tiempo_actual = time.time()  # Captura la marca exacta de tiempo del reloj del sistema operativo.
    
    TOKEN_SISTEMA["valor"] = token_generado  # Almacena el valor del token en la variable global dentro de la memoria RAM.
    TOKEN_SISTEMA["tiempo_creacion"] = tiempo_actual  # Almacena el segundo exacto de la creación en la memoria RAM.
    
    print(f"[TOKENS] Token generado: '{token_generado}' en el segundo {tiempo_actual}")  # Imprime logs de control en la consola interna.
    
    entry_token.delete(0, tk.END)  # Vacía completamente la caja de texto en la interfaz gráfica para evitar sobreescrituras visuales.
    entry_token.insert(0, token_generado)  # Popula automáticamente el código generado en la casilla para que sea visible.
    
    messagebox.showinfo("Tokens", f"¡Token generado con éxito!\nCódigo: {token_generado}\nTiene exactamente {TIEMPO_EXPIRACION} segundos para verificarlo.")  

def verificar_token():  # Declara la función encargada de comprobar la validez y expiración del token ingresado.
    token_ingresado = entry_token.get().strip()  # Lee la casilla de texto de la interfaz y remueve espacios accidentales.
    tiempo_actual = time.time()  # Registra el segundo exacto en el que el usuario hace clic en el botón de validación.
    
    if not token_ingresado:  # Evalúa si la casilla interactiva se encuentra completamente en blanco.
        messagebox.showwarning("Advertencia", "Por favor, genere o introduzca un token para validar.")  # Lanza alerta informativa.
        return  # Detiene la ejecución.
        
    if TOKEN_SISTEMA["valor"] == "":  # Revisa si la memoria RAM no tiene ningún registro de token activo.
        messagebox.showerror("Error", "No existe ningún token activo en el sistema. Genere uno primero.")  # Alerta roja de error de sesión.
        return  # Detiene la ejecución.
        
    segundos_transcurridos = tiempo_actual - TOKEN_SISTEMA["tiempo_creacion"]  # Calcula la diferencia exacta entre el reloj actual y la hora de creación.
    
    print(f"[TOKENS] Validando: Transcurridos {segundos_transcurridos:.2f} segundos de {TIEMPO_EXPIRACION} permitidos.")  # Imprime análisis en consola.
    
    if segundos_transcurridos > TIEMPO_EXPIRACION:  # Evalúa matemáticamente si el tiempo transcurrido supera el límite establecido.
        print("[TOKENS] Resultado: Acceso Denegado. El token ha expirado.")  # Registra el vencimiento del token en la terminal técnica.
        messagebox.showerror("Token Expirado", f"Acceso Denegado.\nEl token ha expirado. (Pasaron {segundos_transcurridos:.1f} segundos).")  # Alerta visual de expiración.
        
        TOKEN_SISTEMA["valor"] = ""  # Limpia la memoria RAM para invalidarlo de forma permanente en el sistema.
        entry_token.delete(0, tk.END)  # Limpia la caja de texto de la pantalla ya que este token no sirve más.
    else:  # Bloque de código ejecutado si la validación ocurre dentro del rango válido de los 15 segundos.
        if token_ingresado == TOKEN_SISTEMA["valor"]:  # Compara si los caracteres de la caja coinciden estrictamente con los de la RAM.
            print("[TOKENS] Resultado: ¡Acceso Permitido! Token válido.")  # Notifica el éxito en la terminal interna del sistema.
            messagebox.showinfo("Éxito", "¡Acceso Permitido!\nEl token es correcto y se encuentra activo.")  # Ventana de confirmación de acceso aprobado.
        else:  # Se ejecuta si los caracteres ingresados no coinciden con el token del sistema.
            print("[TOKENS] Resultado: Token incorrecto.")  # Envía el fallo de coincidencia a la terminal.
            messagebox.showerror("Error", "Acceso Denegado.\nEl token introducido no coincide o es inválido.")  # Ventana flotante de rechazo.


# ==========================================
# LÓGICA DE CIBERSEGURIDAD: CIFRADO AES-KDF
# ==========================================

def cifrar_archivos():  # Declara la función principal para bloquear la base de datos con AES cifrado e inyección de Salt.
    clave_usuario = entry_clave_cifrado.get()  # Captura la contraseña manual escrita por el usuario en la caja gráfica.
    
    if not clave_usuario:  # Verifica si la persona dejó vacío el campo de la clave secreta.
        messagebox.showwarning("Advertencia", "Por favor, escriba una clave en el campo para proceder a cifrar.")  # Lanza aviso visual.
        return  # Frena la función de inmediato.
        
    if not os.path.exists(ARCHIVO_USUARIOS):  # Valida si el archivo de base de datos no se encuentra físicamente.
        guardar_usuarios({})  # Si el archivo fue borrado, inicializamos uno vacío estructuralmente para que no tire error.
        
    try:  # Abre bloque de protección para capturar fallos operacionales o de permisos en disco.
        with open(ARCHIVO_USUARIOS, "rb") as archivo:  # Abre el archivo de usuarios en modo lectura de bytes ("rb").
            datos_claros = archivo.read()  # Lee por completo el contenido binario actual del archivo JSON legible.
            
        # REGLA DE INTEGRIDAD CONTROLADA (ESCUDO ANTISOBREESCRITURA MODIFICADO)
        # Evaluamos el bloque saltando los 16 bytes iniciales correspondientes al Salt aleatorio para buscar la firma "gAAAAA".
        if datos_claros[16:22] == b"gAAAAA":  
            messagebox.showwarning("Información", "El archivo ya se encuentra cifrado actualmente.")  # Lanza aviso.
            return  # Frena la ejecución.
            
        salt_aleatorio = secrets.token_bytes(16)  # Genera un Salt criptográfico de 16 bytes único y aleatorio para esta operación.
        llave_perfecta = derivar_llave(clave_usuario, salt_aleatorio)  # Envía la contraseña y el Salt aleatorio a la KDF para fabricar la llave AES.
        motor_aes = Fernet(llave_perfecta)  # Instancia el motor criptográfico AES alimentándolo con la llave derivada.
        datos_cifrados = motor_aes.encrypt(datos_claros)  # Encripta matemáticamente los bytes del archivo JSON pasándolos a texto ilegible.
        
        with open(ARCHIVO_USUARIOS, "wb") as archivo:  # Abre el mismo archivo en modo escritura de bytes ("wb") reemplazando lo anterior.
            archivo.write(salt_aleatorio + datos_cifrados)  # Escribe físicamente el Salt pegado al bloque cifrado en el disco duro.
            
        print("[CIFRADO] ¡Éxito! El archivo ha sido cifrado con un Salt aleatorio dinámico.")  # Registra el log técnico en consola.
        messagebox.showinfo("Éxito", "Archivo 'usuarios_boveda.txt' cifrado con éxito usando un Salt único aleatorio.")  # Alerta flotante verde.
    except Exception as e:  # Captura fallos críticos imprevistos del sistema de archivos.
        messagebox.showerror("Error", f"Fallo al cifrar: {e}")  # Muestra el error exacto en la GUI.

def descifrar_archivos():  # Declara la función encargada de revertir el cifrado extrayendo el Salt del archivo.
    clave_usuario = entry_clave_cifrado.get()  # Captura la contraseña de la caja para intentar la operación matemática.
    
    if not clave_usuario:  # Valida que la caja de texto de la contraseña no esté vacía.
        messagebox.showwarning("Advertencia", "Por favor, escriba la clave para poder intentar descifrar el archivo.")  # Alerta.
        return  # Frena el flujo.
        
    if not os.path.exists(ARCHIVO_USUARIOS):  # Valida la existencia física del archivo antes de intentar abrirlo.
        messagebox.showerror("Error", "El archivo no existe en el disco.")  # Alerta de archivo faltante.
        return  # Detiene la ejecución.
        
    try:  # Abre un bloque de prueba crítico para capturar si la contraseña colocada genera una llave inválida.
        with open(ARCHIVO_USUARIOS, "rb") as archivo:  # Abre el archivo bloqueado en modo de lectura binaria ("rb").
            contenido_completo = archivo.read()  # Absorbe todo el bloque binario del disco duro hacia la memoria.
            
        salt_extraido = contenido_completo[:16]  # Separa los primeros 16 bytes que corresponden al Salt único utilizado al cifrar.
        datos_bloqueados = contenido_completo[16:]  # Extrae del byte 16 en adelante que representa el texto cifrado puro de AES.
        
        llave_perfecta = derivar_llave(clave_usuario, salt_extraido)  # Re-deriva la llave usando la contraseña manual y el Salt extraído del archivo.
        motor_aes = Fernet(llave_perfecta)  # Alista el motor AES de Fernet con la llave calculada.
        datos_recuperados = motor_aes.decrypt(datos_bloqueados)  # Intenta revertir el descifrado. Si falla un bit o la contraseña, salta al error.
        
        with open(ARCHIVO_USUARIOS, "wb") as archivo:  # Abre el archivo en modo binario de escritura para restaurarlo.
            archivo.write(datos_recuperados)  # Escribe de vuelta el texto plano JSON legible en el disco.
            
        print("[CIFRADO] ¡Éxito! El archivo ha sido descifrado correctamente.")  # Reporta el éxito en consola.
        messagebox.showinfo("Éxito", "Archivo descifrado correctamente.\nLos datos vuelven a estar legibles en formato JSON.")  # Alerta visual de éxito.
    except Exception:  # Captura automáticamente si la llave fue incorrecta o el archivo ya estaba legible.
        print("[CIFRADO] Fallo: Intento de descifrado con clave incorrecta.")  # Registra el error en terminal interna.
        messagebox.showerror("Error de Clave", "Acceso Denegado.\nLa clave introducida es incorrecta, el archivo fue manipulado o ya está descifrado.")  # Bloquea visualmente.


# ==========================================
# LÓGICA DE CIBERSEGURIDAD: INTEGRIDAD (HMAC)
# ==========================================

def firmar_archivo():  # Declara la función encargada de plasmar el sello matemático de integridad sobre el archivo.
    clave_usuario = entry_clave_cifrado.get()  # Lee la clave colocada en la interfaz gráfica para autenticar el origen del HMAC.
    if not clave_usuario:  # Valida que haya un secreto escrito para correr la firma.
        messagebox.showwarning("Advertencia", "Escriba una clave en la sección de Protección de Archivos para firmar.")
        return
    if not os.path.exists(ARCHIVO_USUARIOS):  # Evita errores si intentan firmar un archivo que no existe en disco.
        messagebox.showerror("Error", "El archivo de usuarios no existe para ser firmado.")
        return
    try:
        with open(ARCHIVO_USUARIOS, "rb") as archivo:  # Abre la base de datos en modo binario de lectura.
            contenido = archivo.read()
        
        # Genera una llave de firma simétrica limpia usando la contraseña compartida y un Salt estático para HMAC.
        llave_firma = derivar_llave(clave_usuario, b'SALT_INTEGRIDAD_HMAC')
        h = HMAC(llave_firma, hashes.SHA256())  # Instancia el objeto HMAC configurando SHA-256 como motor criptográfico.
        h.update(contenido)  # Alimenta el HMAC pasando los bytes crudos del archivo completo.
        firma_bytes = h.finalize()  # Ejecuta los cálculos finales y genera la firma digital binaria resultante.
        
        # Convierte los bytes de la firma a formato hexadecimal seguro para guardarlo de manera legible.
        firma_hex = firma_bytes.hex()
        with open(ARCHIVO_FIRMA, "w") as archivo_f:  # Guarda la firma en su archivo propio en disco.
            archivo_f.write(firma_hex)
            
        print(f"[INTEGRIDAD] Firma guardada correctamente: {firma_hex[:15]}...")  # Imprime los primeros caracteres del hash en consola.
        messagebox.showinfo("Éxito", "¡Archivo Firmado Digitalmente!\nSe ha generado y guardado el sello de integridad de manera correcta.")
    except Exception as e:
        messagebox.showerror("Error", f"Fallo al firmar: {e}")

def verificar_firma():  # Declara la función que evalúa si el archivo sufrió alteraciones comparándolo con la firma guardada.
    clave_usuario = entry_clave_cifrado.get()  # Reclama la clave de verificación de la pantalla.
    if not clave_usuario:
        messagebox.showwarning("Advertencia", "Escriba la clave para poder recalcular y verificar la firma.")
        return
    if not os.path.exists(ARCHIVO_USUARIOS) or not os.path.exists(ARCHIVO_FIRMA):  # Valida la existencia de ambas piezas del rompecabezas.
        messagebox.showerror("Error", "Faltan archivos esenciales (la base de datos o el archivo de firma).")
        return
    try:
        with open(ARCHIVO_USUARIOS, "rb") as archivo:  # Carga los bytes actuales de la base de datos.
            contenido_actual = archivo.read()
        with open(ARCHIVO_FIRMA, "r") as archivo_f:  # Lee la firma digital hexadecimal guardada previamente.
            firma_guardada_hex = archivo_f.read().strip()
            
        firma_guardada_bytes = bytes.fromhex(firma_guardada_hex)  # Transforma la firma de texto hexadecimal de vuelta a bytes crudos.
        llave_firma = derivar_llave(clave_usuario, b'SALT_INTEGRIDAD_HMAC')  # Recalcula la llave simétrica con la contraseña provista.
        
        h = HMAC(llave_firma, hashes.SHA256())  # Prepara un validador HMAC SHA-256.
        h.update(contenido_actual)  # Introduce los bytes del archivo actual.
        
        h.verify(firma_guardada_bytes)  # Intenta validar. Si un solo carácter cambió, tira una excepción matemática inmediata de error.
        
        print("[INTEGRIDAD] Resultado: ¡Firma Válida! El archivo está íntegro.")
        messagebox.showinfo("Integridad Validada", "✅ ¡ÉXITO: INTEGRIDAD CONFIRMADA!\nEl archivo no ha sufrido alteraciones. La firma digital coincide perfectamente.")
    except Exception:  # Captura de forma automática el error si la verificación criptográfica del HMAC fracasa.
        print("[INTEGRIDAD] Resultado: ¡ALERTA! Firma Inválida o datos corruptos.")
        messagebox.showerror("Fallo de Integridad", "❌ ¡ALERTA DE SEGURIDAD!\nLa firma digital NO coincide. El archivo ha sido manipulado, modificado de forma no autorizada o la clave es incorrecta.")


# ==========================================
# CONFIGURACIÓN DE LA INTERFAZ GRÁFICA (GUI)
# ==========================================
root = tk.Tk()  # Inicializa el motor gráfico construyendo la ventana principal base de la aplicación.
root.title("Bóveda Segura - Proyecto #1")  # Configura la cadena de texto fija que se muestra arriba en el borde superior de la ventana.
root.geometry("520x940")  # Ajustado a 940 de alto para asegurar que el botón final se dibuje completo en pantalla.
root.resizable(False, False)  # Deshabilita la redimensión manual anulando los botones de agrandamiento para evitar layouts desordenados.

lbl_titulo = tk.Label(root, text="BÓVEDA SEGURA", font=("Arial", 16, "bold"))  # Crea una etiqueta de texto jerárquica con tipografía destacada.
lbl_titulo.pack(pady=15)  # Acopla el título a la ventana principal aplicando una holgura vertical espaciada de 15 píxeles.

# --- SECCIÓN 1: CONTRASEÑAS Y REGISTRO (BCRYPT) ---
frame_pass = tk.LabelFrame(root, text=" Gestión de Contraseñas y Registro (bcrypt) ", padx=10, pady=10)  # Marco contenedor para bcrypt.
frame_pass.pack(fill="x", padx=20, pady=5)  # Introduce el contenedor obligándolo a abarcar el ancho completo.

lbl_modo = tk.Label(frame_pass, text="⚠️ MODO DEMOSTRACIÓN: Entradas en texto claro (Persistente)", font=("Arial", 9, "italic"), fg="#E65100")  # Modela la etiqueta de advertencia naranja.
lbl_modo.pack(anchor="w", pady=2)  # Fija la etiqueta alineada hacia la izquierda.

lbl_reg_title = tk.Label(frame_pass, text="Registrar Nuevo Usuario:", font=("Arial", 10, "bold"))  # Encabezado indicador del registro de cuentas.
lbl_reg_title.pack(anchor="w", pady=2)  # Empaqueta la etiqueta visual.

lbl_user_reg = tk.Label(frame_pass, text="Usuario:")  # Indicador para escribir el nombre de usuario.
lbl_user_reg.pack(anchor="w")  # Coloca el texto informativo alineado a la izquierda.
entry_usuario_reg = tk.Entry(frame_pass, font=("Arial", 11))  # Campo interactivo de entrada de datos para el registro.
entry_usuario_reg.pack(fill="x", pady=2)  # Expande horizontalmente el widget de entrada.

lbl_pass_reg = tk.Label(frame_pass, text="Contraseña:")  # Indicador para escribir la contraseña de registro.
lbl_pass_reg.pack(anchor="w")  # Posiciona el texto informativo.
entry_pass_reg = tk.Entry(frame_pass, font=("Arial", 11))  # Construye el campo interactivo para el registro.
entry_pass_reg.pack(fill="x", pady=2)  # Lo incorpora dándole relleno a lo ancho.

btn_registrar = tk.Button(frame_pass, text="🔐 Registrar Usuario", font=("Arial", 10, "bold"), bg="#4CAF50", fg="white", command=registrar_contrasena)  # Enlaza el botón verde a la función registrar.
btn_registrar.pack(fill="x", pady=6)  # Añade el botón a la GUI ocupando todo el ancho de línea.

lbl_ver_title = tk.Label(frame_pass, text="Verificar Acceso de Usuario:", font=("Arial", 10, "bold"))  # Rótulo divisorio para el área de login.
lbl_ver_title.pack(anchor="w", pady=4)  # Coloca el separador gráfico.

lbl_user_ver = tk.Label(frame_pass, text="Usuario:")  # Indicador visual para loguearse.
lbl_user_ver.pack(anchor="w")  # Posiciona la etiqueta informativa.
entry_usuario_ver = tk.Entry(frame_pass, font=("Arial", 11))  # Recuadro interactivo para recibir el login.
entry_usuario_ver.pack(fill="x", pady=2)  # Lo añade extendiéndolo a los márgenes horizontales.

lbl_pass_ver = tk.Label(frame_pass, text="Contraseña:")  # Configura la etiqueta estática de contraseña para login.
lbl_pass_ver.pack(anchor="w")  # Coloca la advertencia literal hacia la izquierda.
entry_pass_ver = tk.Entry(frame_pass, font=("Arial", 11))  # Habilita la caja de captura para la clave de inicio de sesión.
entry_pass_ver.pack(fill="x", pady=2)  # Fija el componente estirándolo horizontalmente.

btn_verificar = tk.Button(frame_pass, text="🔑 Verificar Contraseña", font=("Arial", 10, "bold"), bg="#2196F3", fg="white", command=verificar_contrasena)  # Enlaza el botón azul a verificar.
btn_verificar.pack(fill="x", pady=6)  # Lo sirve estirado horizontalmente.

# --- SECCIÓN 2: TOKENS DE RECUPERACIÓN ---
frame_tokens = tk.LabelFrame(root, text=" Tokens de Recuperación (Expirable) ", padx=10, pady=10)  # Marco enfocado en contraseñas OTP.
frame_tokens.pack(fill="x", padx=20, pady=5)  # Acopla el agrupador configurando márgenes.

btn_gen_token = tk.Button(frame_tokens, text="🎟️ Generar Token", font=("Arial", 10, "bold"), bg="#9C27B0", fg="white", command=generar_token)  # Vincula el botón morado a generar_token.
btn_gen_token.pack(fill="x", pady=4)  # Coloca el disparador ensanchado.

entry_token = tk.Entry(frame_tokens, font=("Arial", 11))  # Celda interactiva para introducir el token.
entry_token.pack(fill="x", pady=2)  # Inserta el widget.

btn_ver_token = tk.Button(frame_tokens, text="🎫 Verificar Token", font=("Arial", 10, "bold"), bg="#E91E63", fg="white", command=verificar_token)  # Vincula el botón rosado a verificar_token.
btn_ver_token.pack(fill="x", pady=4)  # Integra el botón estirándolo horizontalmente.

# --- SECCIÓN 3: PROTECCIÓN DE ARCHIVOS (CIFRADO ANTES QUE FIRMA) ---
frame_otras = tk.LabelFrame(root, text=" Protección de Archivos ", padx=10, pady=10)  # Agrupa el tercer bloque de la interfaz.
frame_otras.pack(fill="x", padx=20, pady=5)  # Posiciona el agrupador.

lbl_clave_cifrado = tk.Label(frame_otras, text="Clave Secreta Compartida (Cifrado / HMAC):")  # Rótulo guía para ingresar la clave manual de la bóveda.
lbl_clave_cifrado.pack(anchor="w")  # Alinea el texto informativo a la izquierda.
entry_clave_cifrado = tk.Entry(frame_otras, font=("Arial", 11))  # Caja interactiva mostrando caracteres en claro para fines didácticos en la presentación.
entry_clave_cifrado.pack(fill="x", pady=2)  # La expande horizontalmente cubriendo el ancho disponible.

btn_cifrar = tk.Button(frame_otras, text="📁 Cifrar usuarios_boveda (AES)", font=("Arial", 10, "bold"), bg="#FF9800", fg="white", command=cifrar_archivos)  # Vincula el botón naranja a cifrar_archivos.
btn_cifrar.pack(fill="x", pady=4)  # Dispone el disparador extendido a todo lo ancho.

btn_descifrar = tk.Button(frame_otras, text="🔓 Descifrar usuarios_boveda (AES)", font=("Arial", 10, "bold"), bg="#009688", fg="white", command=descifrar_archivos)  # Vincula el botón turquesa a descifrar_archivos.
btn_descifrar.pack(fill="x", pady=4)  # Dispone el disparador extendido a todo lo ancho.

# --- SECCIÓN 4: FIRMA DIGITAL E INTEGRIDAD (CIERRA ABAJO) ---
frame_firma = tk.LabelFrame(root, text=" Firma Digital y No Repudio (HMAC-SHA256) ", padx=10, pady=10)  # Agrupador visual para el control de firmas colocado al final.
frame_firma.pack(fill="x", padx=20, pady=10)

btn_firmar = tk.Button(frame_firma, text="✍️ Firmar Base de Datos (Generar Sello)", font=("Arial", 10, "bold"), bg="#3F51B5", fg="white", command=firmar_archivo)  # Botón Indigo para firmar.
btn_firmar.pack(fill="x", pady=4)

btn_verificar_f = tk.Button(frame_firma, text="🧐 Verificar Firma (Control de Integridad)", font=("Arial", 10, "bold"), bg="#00897B", fg="white", command=verificar_firma)  # Botón verde oscuro para verificar.
btn_verificar_f.pack(fill="x", pady=4)

root.mainloop()  # Ejecuta el ciclo de eventos permanente que intercepta clics y mantiene viva la interfaz gráfica.