import streamlit as st
import bcrypt
import datetime

# ====================================================================
#  GRUPO 1: GESTIÓN DE USUARIOS, AUTENTICACIÓN Y CENTRO DE MONITOREO
# --------------------------------------------------------------------
#  Todas las funciones core y vistas trabajan sobre 'shared' (el estado
#  GLOBAL compartido). Los datos de este grupo (usuarios_db, soc_logs)
#  son globales: se ven igual para todas las sesiones conectadas.
#  Este módulo NO exige login (acceso libre según el diseño del SOC).
# ====================================================================

# ====================================================================
#  FUNCIONES DE INICIALIZACIÓN DE DATOS (SEMILLAS DEL BACKEND)
# ====================================================================

# Inicializa la base de datos de usuarios con la cuenta semilla de cybershield
def inicializar_usuarios():
    # Define el mapa de usuarios en memoria con sus hashes criptográficos
    usuarios = {
        "cybershield": {
            "rol": "Administrador",
            # Hash bcrypt binario correspondiente a la contraseña 'Panama01'
            "hash": b"$2b$12$ODJAr/RhvRESYJwyu3mY1evRQStcBFmZp/s2Apk.4.SNqw1twhCD2",
            "pregunta": "¿Cuál es tu ciudad natal?",
            # Hash bcrypt binario correspondiente a la respuesta 'panama'
            "respuesta_hash": b"$2b$12$mreUeO15Tsc9pDmsM8zKse5A4L/E6R9Z9z9W6XmHn1C9lPAom3Wee"
        }
    }
    # Retorna el diccionario estructurado para guardarlo en el estado global
    return usuarios


# Arranca el contenedor de historial de logs limpio y vacío para el inicio del SOC
def inicializar_logs():
    # Retorna una lista vacía para que el SIEM registre eventos reales en tiempo real
    return []

# ====================================================================
#  LÓGICA CORE DEL MÓDULO (OPERAN SOBRE EL ESTADO GLOBAL 'shared')
# ====================================================================

# Registra un evento de auditoría insertándolo al principio del historial global del SIEM
def registrar_evento(shared, usuario, accion, ip, tipo="INFO"):
    # Crea un diccionario con la estructura estandarizada de un evento de seguridad
    nuevo_log = {
        # Captura la fecha y hora exacta del evento
        "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        # Si no hay sesión iniciada, marca el registro como un usuario anónimo
        "Usuario": usuario if usuario else "ANÓNIMO",
        # Almacena la descripción de la acción del operador o sistema
        "Acción": accion,
        # Guarda la dirección IP de origen de la solicitud
        "IP": ip,
        # Define la severidad del evento para los filtros visuales del SOC
        "Tipo": tipo
    }
    # Inyecta el log al inicio de la lista GLOBAL (mutación in-place sobre shared)
    shared["soc_logs"].insert(0, nuevo_log)


# Valida el login comparando la contraseña ingresada contra el hash seguro en la base global
def verificar_credenciales(shared, usuario, password, ip):
    # Carga la base de datos de usuarios global
    usuarios = shared["usuarios_db"]

    # Si el nombre de usuario no existe, se mitiga el riesgo de enumeración de cuentas
    if usuario not in usuarios:
        # Registra el fallo en el SIEM con categoría sospechosa
        registrar_evento(shared, usuario, "Fallo de autenticación: Credenciales inválidas.", ip, "SOSPECHOSO")
        # Envía la IP al motor de análisis para detectar posibles ráfagas automáticas
        evaluar_fuerza_bruta(shared, ip)
        # Retorna falso de forma genérica para no dar pistas al atacante
        return False, None

    # Convierte la contraseña ingresada en el formulario web a formato de bytes
    password_bytes = password.encode('utf-8')
    # Extrae el hash criptográfico binario guardado para este usuario
    hash_guardado = usuarios[usuario]["hash"]

    # Intenta validar la coincidencia del hash de forma segura
    try:
        # Ejecuta la comparación criptográfica de bcrypt extrayendo la sal del hash
        if bcrypt.checkpw(password_bytes, hash_guardado):
            # Si coincide, guarda un evento informativo de acceso concedido
            registrar_evento(shared, usuario, "Autenticación exitosa. Acceso concedido.", ip, "INFO")
            # Concede el acceso exitoso junto con el nivel de rol del usuario
            return True, usuarios[usuario]["rol"]
        # Si la contraseña no coincide con el hash guardado
        else:
            # Almacena el log de credenciales inválidas para auditoría
            registrar_evento(shared, usuario, "Fallo de autenticación: Credenciales inválidas.", ip, "SOSPECHOSO")
            # Envía la IP de origen a evaluación de fuerza bruta en el SIEM
            evaluar_fuerza_bruta(shared, ip)
            # Deniega el inicio de sesión
            return False, None
    # Captura fallos imprevistos de procesamiento criptográfico
    except Exception:
        # Mantiene la política de seguridad registrando el fallo genérico
        registrar_evento(shared, usuario, "Fallo de autenticación: Credenciales inválidas.", ip, "SOSPECHOSO")
        # Bloquea el login retornando denegado
        return False, None


# Hashea los datos de un nuevo analista y lo registra de forma segura en la base global
def registrar_usuario(shared, usuario, password, rol, pregunta, respuesta):
    # Limpia los espacios en blanco adicionales del nombre de usuario
    usuario_clean = usuario.strip()
    # Verifica si el nombre de usuario ya se encuentra registrado
    if usuario_clean in shared["usuarios_db"]:
        # Retorna un error preventivo para evitar sobreescribir cuentas
        return False, "Error de registro: Credenciales o datos de usuario no válidos."

    # Aplica hash seguro con una sal aleatoria usando un factor de costo de 12
    hash_pass = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
    # Estandariza la respuesta en minúsculas y aplica el hash criptográfico seguro
    hash_resp = bcrypt.hashpw(respuesta.strip().lower().encode('utf-8'), bcrypt.gensalt(rounds=12))

    # Almacena el mapa del nuevo operador en la base GLOBAL (mutación in-place)
    shared["usuarios_db"][usuario_clean] = {
        "rol": rol,
        "hash": hash_pass,
        "pregunta": pregunta,
        "respuesta_hash": hash_resp
    }
    # Retorna confirmación exitosa de almacenamiento seguro
    return True, "Usuario registrado de manera segura."


# Permite el cambio de contraseña validando la respuesta secreta del canal de recuperación
def recuperar_password(shared, usuario, respuesta_ingresada, nuevo_password):
    # Define una respuesta de error estandarizada para no revelar información
    error_generico = "Error de credenciales o datos de recuperación no válidos."
    # Si el nombre de usuario ingresado no existe en el repositorio global
    if usuario not in shared["usuarios_db"]:
        # Deniega la solicitud usando el mensaje genérico estándar
        return False, error_generico

    # Carga el diccionario de datos del usuario validado
    user_data = shared["usuarios_db"][usuario]
    # Convierte la respuesta ingresada a minúsculas, limpia espacios y la pasa a bytes
    resp_bytes = respuesta_ingresada.strip().lower().encode('utf-8')

    # Compara criptográficamente la respuesta ingresada contra el hash guardado
    if bcrypt.checkpw(resp_bytes, user_data["respuesta_hash"]):
        # Si es válida, genera un nuevo hash seguro para la nueva contraseña operativa
        nuevo_hash = bcrypt.hashpw(nuevo_password.encode('utf-8'), bcrypt.gensalt(rounds=12))
        # Actualiza el campo hash en la base GLOBAL del operador (mutación in-place)
        shared["usuarios_db"][usuario]["hash"] = nuevo_hash
        # Retorna confirmación positiva del cambio de clave
        return True, "Contraseña restablecida con éxito."
    # Si la respuesta secreta ingresada no coincide con el hash
    else:
        # Deniega el cambio con el mensaje genérico anti-reconocimiento
        return False, error_generico


# Monitor automatizado del SIEM que detecta patrones repetitivos de fallos desde una IP
def evaluar_fuerza_bruta(shared, ip_origen):
    # Inicializa el contador correlativo de fallos seguidos
    fallos_recientes = 0
    # Itera sobre la lista completa de eventos registrados en el SIEM global
    for log in shared["soc_logs"]:
        # Si el log pertenece a la IP atacante y es un fallo de credenciales
        if log["IP"] == ip_origen and "Fallo de autenticación" in log["Acción"]:
            # Incrementa el contador de métrica de riesgo
            fallos_recientes += 1
        # Si encuentra un acceso legítimo previo de esa misma IP
        elif log["IP"] == ip_origen and "Autenticación exitosa" in log["Acción"]:
            # Rompe el bucle para evaluar únicamente fallos continuos recientes
            break

    # Gatillo de alerta automática: si se acumulan 3 o más fallos consecutivos
    if fallos_recientes >= 3:
        # Dispara e inyecta una alerta de criticidad máxima en la base de logs global
        registrar_evento(
            shared,
            usuario="SISTEMA_SIEM",
            accion=f"ALERTA CRÍTICA: Posible ataque de fuerza bruta detectado desde la IP {ip_origen}.",
            ip=ip_origen,
            tipo="ATAQUE"
        )

# ====================================================================
#  PANTALLAS VISUALES ENCAPSULADAS (RECIBEN 'shared' DESDE MAIN O LOCAL)
# ====================================================================

# Renderiza la interfaz de alta de personal y visor de base de datos criptográfica
def vista_gestion_usuarios(shared):
    # Pinta el título de cabecera del módulo del Grupo 1
    st.title("👥 Módulo de Gestión de Usuarios (Grupo 1)")
    # Muestra el subencabezado técnico de la pantalla
    st.subheader("Administración de identidades, roles y control criptográfico")
    # Genera una línea de separación horizontal
    st.write("---")

    # Instancia las pestañas internas de navegación para el analista
    pestana_reg, pestana_ver_db = st.tabs(["➕ Registrar Operador SOC", "📋 Base de Datos Criptográfica"])

    # Contenedor visual para el formulario de registro de operadores
    with pestana_reg:
        # Subtítulo de sección en Markdown
        st.markdown("### Formulario de Alta de Personal")
        # Declara el formulario de captura de datos agrupados
        with st.form("form_modulo_registro"):
            # Input de texto limpio para registrar el nuevo nombre de usuario
            nuevo_user = st.text_input("Nombre de Usuario (Username):").strip()
            # Input enmascarado para la contraseña del nuevo operador
            nuevo_pass = st.text_input("Contraseña Operativa:", type="password")
            # Selector desplegable con los niveles de rol del sistema
            nuevo_rol = st.selectbox("Rol Asignado:", ["Administrador", "Analista", "Usuario"])
            # Selector desplegable con las preguntas secretas predefinidas
            nueva_preg = st.selectbox("Pregunta de Seguridad:", [
                "¿Cuál es tu ciudad natal?",
                "¿Nombre de tu primera mascota?",
                "¿Marca de tu primer auto?"
            ])
            # Input enmascarado para guardar la respuesta de recuperación
            nueva_resp = st.text_input("Respuesta de Recuperación:", type="password")

            # Crea el botón primario de guardado y ejecución del formulario
            btn_modulo_reg = st.form_submit_button("Aplicar Hash y Guardar Operador", type="primary")

            # Si el botón de registro es presionado
            if btn_modulo_reg:
                # Valida que los campos obligatorios de la credencial no estén vacíos
                if nuevo_user == "" or nuevo_pass == "" or nueva_resp == "":
                    # Muestra un cartel de error en la interfaz
                    st.error("Error de registro: Credenciales o datos de usuario no válidos.")
                # Si pasa la validación visual de campos llenos
                else:
                    # Llama a la función core para hashear y almacenar de forma segura en el estado global
                    exito, msg = registrar_usuario(shared, nuevo_user, nuevo_pass, nuevo_rol, nueva_preg, nueva_resp)
                    # Si el guardado criptográfico se ejecutó de forma correcta
                    if exito:
                        # Extrae la IP asignada al contexto web local de la sesión
                        ip_actual = st.session_state.get("ip_cliente", "127.0.0.1")
                        # Identifica qué operador en sesión realizó la acción de registro
                        user_actual = st.session_state.get("usuario_actual") or "ANÓNIMO"
                        # Intenta registrar la bitácora de auditoría en el SIEM global
                        try:
                            registrar_evento(shared, user_actual, f"Registró un nuevo usuario: {nuevo_user} ({nuevo_rol})", ip_actual, "INFO")
                        # Evita caídas de interfaz si ocurre un fallo de logs
                        except Exception:
                            pass
                        # Muestra una notificación verde de éxito en pantalla
                        st.success("Operador guardado de manera segura en el sistema.")
                    # Si la lógica core deniega el registro (ej. usuario existente)
                    else:
                        # Pinta el mensaje de error devuelto por el backend
                        st.error(msg)

    # Contenedor visual para la inspección y demostración técnica de hashes
    with pestana_ver_db:
        # Cuenta el número total de operadores guardados en el repositorio global
        total_cuentas = len(shared["usuarios_db"])
        # Muestra una tarjeta métrica interactiva con el total de registros
        st.metric(label="📊 Total de Cuentas en Repositorio", value=f"{total_cuentas} Registros")
        # Línea divisoria
        st.write("---")

        # Encabezado informativo de auditoría criptográfica
        st.markdown("### Inspección de Credenciales Hasheadas")
        st.write("Esta vista demuestra al evaluador que el sistema aplica salting y hashing seguro:")

        # Lista vacía para dar formato de tabla limpia al dataframe visual
        datos_visibles = []
        # Itera el diccionario criptográfico de usuarios global
        for usr, datos in shared["usuarios_db"].items():
            # Intenta decodificar el hash binario para mostrarlo como cadena UTF-8
            try:
                hash_str = datos["hash"].decode('utf-8')
            # Si el formato binario difiere, fuerza un casting de texto directo
            except Exception:
                hash_str = str(datos["hash"])

            # Agrega los metadatos formateados listos para visualización
            datos_visibles.append({
                "Nombre de Usuario": usr,
                "Rol del Sistema": datos["rol"],
                "Hash Criptográfico (bcrypt)": hash_str,
                "Pregunta Secreta": datos["pregunta"]
            })
        # Renderiza la tabla responsiva que muestra las claves seguras en vivo
        st.dataframe(datos_visibles, use_container_width=True)


# Renderiza el visor interactivo de logs del SIEM CyberShield
def vista_centro_monitoreo(shared):
    # Título principal de la pantalla de monitoreo
    st.title("⚙️ Centro de Monitoreo & Logs (Grupo 1)")
    # Subencabezado técnico
    st.subheader("Registro de eventos de auditoría y detección automatizada de anomalías")
    # Línea divisoria
    st.write("---")
    # Subtítulo de sección
    st.markdown("### 📋 Historial Completo del SIEM")

    # Caja de selección múltiple interactiva para filtrar los logs por severidad en vivo
    filtro_tipo = st.multiselect(
        "Filtrar por Severidad del Evento:",
        ["INFO", "WARNING", "SOSPECHOSO", "ATAQUE"],
        default=["INFO", "WARNING", "SOSPECHOSO", "ATAQUE"]
    )
    # Comprensión de listas que filtra los logs GLOBALES en tiempo real según la selección web
    logs_filtrados = [log for log in shared["soc_logs"] if log["Tipo"] in filtro_tipo]
    # Dibuja la tabla dinámica con los logs filtrados ocupando todo el ancho disponible
    st.dataframe(logs_filtrados, use_container_width=True)

# ====================================================================
#  MODO AUTÓNOMO (EJECUCIÓN DIRECTA 'streamlit run grp01.py')
# --------------------------------------------------------------------
#  Entra DIRECTO, sin login (según diseño: solo el escáner exige sesión).
# ====================================================================

# Valida si el script se está ejecutando de forma directa e independiente
if __name__ == "__main__":
    # Importa el módulo de estado compartido para obtener el diccionario global
    import share_state

    # Inicializa la configuración de la ventana del navegador web para modo aislado
    st.set_page_config(page_title="Módulo Autónomo - Grupo 1", page_icon="👥", layout="wide")

    # Obtiene el estado GLOBAL compartido (cacheado como recurso único del proceso)
    shared = share_state.obtener_estado_global()
    # Prepara el contexto local de la sesión (IP, punteros locales)
    share_state.preparar_contexto_local(shared)

    # BARRA LATERAL: navegación local de las dos pantallas del Grupo 1
    st.sidebar.title("🛡️ CyberShield SOC")
    st.sidebar.write("Módulo Grupo 1 (Autónomo)")
    st.sidebar.write("---")

    # Lista de navegación limitada a las pantallas del Grupo 1
    opciones_locales = [
        "👥 Gestión de Usuarios (Grupo 1)",
        "⚙️ Centro de Monitoreo & Logs (Grupo 1)"
    ]
    # Instancia el menú radial de navegación en la barra lateral
    menu_sel = st.sidebar.radio("Navegación del Grupo:", opciones_locales)

    # ENRUTADOR LOCAL: renderiza la pantalla seleccionada pasando el estado global
    if menu_sel == "👥 Gestión de Usuarios (Grupo 1)":
        # Invoca el formulario de registro y la tabla de hashes
        vista_gestion_usuarios(shared)
    elif menu_sel == "⚙️ Centro de Monitoreo & Logs (Grupo 1)":
        # Invoca la tabla de logs dinámicos del SIEM
        vista_centro_monitoreo(shared)
