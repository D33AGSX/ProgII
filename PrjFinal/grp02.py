import streamlit as st
import socket
import sys
import subprocess
import importlib

# ====================================================================
#  GRUPO 2: ESCÁNER DE RED, PUERTOS Y VULNERABILIDADES
# --------------------------------------------------------------------
#  ÚNICO módulo que EXIGE login (sesión iniciada).
#
#  Modelo del "Mapa de Correlación de Dispositivos":
#   - BASE GLOBAL: se construye siempre a partir de shared["sesiones_activas"]
#     (los usuarios autenticados 🟢). Se ve poblado por defecto y se
#     actualiza solo cuando alguien entra/sale de sesión.
#   - CAPA PRIVADA por sesión: al correr MI ping sweep se agregan los
#     dispositivos SIN sesión (🟡 desconocidos / 🔴 huérfanos). Esa capa
#     vive en st.session_state.mapa_escaneo_privado y solo la veo yo.
#
#  El reporte de puertos/vulnerabilidades y sus contadores de alertas
#  también son privados por sesión.
# ====================================================================

# Importa dinámicamente el Grupo 1 para enlazar la seguridad (login) del SOC
try:
    g1 = importlib.import_module("grp01")
except ModuleNotFoundError:
    st.error("❌ No se encontró el archivo 'grp01.py'. Asegúrate de que esté en la misma carpeta que este script.")
    st.stop()

# =====================================================================
# BASE DE DATOS COMPACTA DE VULNERABILIDADES REALES (NIST / MITRE)
# =====================================================================
DICCIONARIO_VULNERABILIDADES = {
    "vsftpd 2.3.4": {
        "cve": "CVE-2011-2523",
        "severidad": "CRÍTICA",
        "descripcion": "Presencia de un backdoor malicioso en el paquete de instalación original que permite la ejecución remota de comandos al enviar una secuencia específica en el nombre de usuario."
    },
    "openssh 7.4": {
        "cve": "CVE-2018-15473",
        "severidad": "MEDIA",
        "descripcion": "Vulnerabilidad de enumeración de usuarios en OpenSSH que permite a atacantes remotos adivinar nombres de usuario válidos en el sistema operativo mediante el análisis de paquetes de autenticación mal formados."
    },
    "apache/2.4.41": {
        "cve": "CVE-2020-11984",
        "severidad": "ALTA",
        "descripcion": "Desbordamiento de búfer en el módulo mod_proxy_uwsgi de Apache HTTP Server que podría permitir a un atacante remoto lograr la divulgación de información confidencial o la ejecución de código."
    },
    "nginx/1.14.0": {
        "cve": "CVE-2018-16843",
        "severidad": "MEDIA",
        "descripcion": "Fuga de memoria y potencial denegación de servicio (DoS) en el módulo HTTP/2 de Nginx mediante el envío de solicitudes excesivas y maliciosas."
    }
}

# =====================================================================
# 1. DESCUBRIMIENTO DE RED (PING SWEEP)
# =====================================================================
def descubrir_red(subred_base="192.168.137."):
    # Array local para coleccionar las direcciones IP que respondan al barrido
    dispositivos_vivos = []
    # Determina el parámetro correcto de ping dependiendo del sistema operativo
    parametro_count = "-n" if sys.platform.lower().startswith("win") else "-c"

    # Itera de forma secuencial sobre el rango de hosts utilizables en la subred (/24)
    for i in range(1, 255):
        # Concatena la subred base con el host actual de la iteración
        ip_objetivo = f"{subred_base}{i}"
        try:
            # Configura los parámetros de espera cortos para agilizar el barrido
            if sys.platform.lower().startswith("win"):
                comando = ["ping", parametro_count, "1", "-w", "150", ip_objetivo]
            else:
                comando = ["ping", parametro_count, "1", "-W", "1", ip_objetivo]

            # Ejecuta de forma silenciosa el comando del sistema operativo
            resultado = subprocess.run(comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            # Si el código de retorno es 0, el host de destino está encendido y respondiendo
            if resultado.returncode == 0:
                dispositivos_vivos.append(ip_objetivo)
        except Exception:
            continue

    # Retorna la lista con los dispositivos descubiertos
    return dispositivos_vivos

# =====================================================================
# 2. BASE GLOBAL DEL MAPA: USUARIOS AUTENTICADOS (SESIONES ACTIVAS)
# =====================================================================
def construir_base_sesiones(sesiones_globales):
    # Lista que contendrá SIEMPRE a los usuarios conectados como base del mapa.
    # Es una LISTA (no un dict por IP) para que dos sesiones con la misma IP
    # aparezcan en filas separadas, una por cada operador conectado.
    base_mapa = []
    # Recorre las sesiones activas globales para marcar cada sesión como autenticada
    for usuario, info in sesiones_globales.items():
        # Extrae la IP de origen registrada al iniciar sesión
        ip_origen = info.get("IP de Origen")
        # Solo incorpora la entrada si la sesión tiene una IP asociada
        if ip_origen:
            base_mapa.append({
                # Dirección IP física de la sesión
                "ip": ip_origen,
                # Estado verde: dispositivo con sesión válida y autenticada
                "estado": "🟢 Activo y Autenticado",
                # Nombre del operador dueño de la sesión
                "usuario": usuario,
                # Rol del operador dentro del SOC
                "rol": info.get("Rol", "Operador")
            })
    # Retorna la base global de dispositivos autenticados (una fila por sesión)
    return base_mapa

# =====================================================================
# 3. CAPA PRIVADA DEL MAPA: DISPOSITIVOS DESCUBIERTOS POR EL PING SWEEP
# =====================================================================
def generar_capa_escaneo(ips_descubiertas, sesiones_globales):
    # IPs que sí tienen sesión activa (para no marcarlas como desconocidas)
    ips_con_sesion = set()
    # Recolecta las IPs de todas las sesiones activas globales
    for usuario, info in sesiones_globales.items():
        ip_origen = info.get("IP de Origen")
        if ip_origen:
            ips_con_sesion.add(ip_origen)

    # Lista para la capa privada de dispositivos hallados por el escaneo (una fila por IP)
    capa_privada = []
    # Evalúa cada IP física descubierta por el ping sweep
    for ip in ips_descubiertas:
        # Si la IP descubierta NO tiene una sesión firmada, es un desconocido/intruso
        if ip not in ips_con_sesion:
            capa_privada.append({
                # Dirección IP física descubierta
                "ip": ip,
                # Estado amarillo: responde en red pero sin autenticación activa
                "estado": "🟡 Desconocido (Sin Sesión)",
                "usuario": "Desconocido",
                "rol": "Posible Intruso / Externo"
            })

    # Retorna la capa privada del escaneo de esta sesión (una fila por dispositivo desconocido)
    return capa_privada

# =====================================================================
# 4. FUSIÓN DEL MAPA: BASE GLOBAL + CAPA PRIVADA DE ESTA SESIÓN
# =====================================================================
def fusionar_mapa(sesiones_globales, capa_escaneo_privada):
    # Arranca siempre desde la base global de usuarios autenticados (lista de filas)
    mapa_final = construir_base_sesiones(sesiones_globales)
    # Recolecta las IPs que ya tienen sesión activa para no duplicarlas como desconocidas
    ips_autenticadas = {fila["ip"] for fila in mapa_final}
    # Superpone la capa privada del escaneo (dispositivos desconocidos de MI sesión)
    for fila in capa_escaneo_privada:
        # La capa de escaneo no agrega una IP que ya está autenticada en la base
        if fila["ip"] not in ips_autenticadas:
            mapa_final.append(fila)
    # Retorna el mapa consolidado (lista de filas) listo para renderizar
    return mapa_final

# =====================================================================
# 5. ESCANEO DE PUERTO, SERVICIO, VERSIÓN Y VULNERABILIDADES
# =====================================================================
def escanear_puerto_individual(ip_objetivo, puerto, timeout=0.3):
    # Estructura el esquema de datos por defecto para un puerto analizado
    resultado_puerto = {
        "puerto": puerto,
        "estado": "Cerrado",
        "servicio": "Desconocido",
        "version": "N/A",
        "vulnerabilidad": "Ninguna detectada",
        "cve": "N/A",
        "severidad": "INFORMATIVO"
    }

    # Diccionario auxiliar de servicios estándar asociados a sus respectivos puertos
    servicios_comunes = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        80: "HTTP", 443: "HTTPS", 1433: "MSSQL", 3306: "MySQL",
        3389: "RDP", 5000: "UPnP / Flask", 8000: "Django / Dev",
        8080: "HTTP-Proxy", 8501: "Streamlit"
    }

    # Asigna la etiqueta del servicio estimado basándose en el puerto objetivo
    if puerto in servicios_comunes:
        resultado_puerto["servicio"] = servicios_comunes[puerto]

    # Declara el objeto socket de red utilizando la familia IPv4 y el protocolo TCP
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Define la tolerancia máxima de espera en segundos para evitar congelar el hilo
    sock.settimeout(timeout)

    try:
        # Intenta la conexión TCP de tres vías contra la IP y puerto objetivo
        codigo_conexion = sock.connect_ex((ip_objetivo, puerto))

        # Si el código de conexión es 0, el puerto TCP está expuesto y abierto
        if codigo_conexion == 0:
            resultado_puerto["estado"] = "Abierto"

            try:
                # Envía una cabecera de petición HTTP básica si el puerto responde a servicios web
                if puerto in [80, 443, 8080, 8501]:
                    sock.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")

                # Intenta capturar el banner del servicio que envía el socket de destino
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()

                # Si se logró interceptar información del banner
                if banner:
                    resultado_puerto["version"] = banner

                    # Normaliza e infiere de forma precisa el tipo de servicio basándose en el banner
                    if "ssh" in banner.lower():
                        resultado_puerto["servicio"] = "SSH"
                    elif "ftp" in banner.lower():
                        resultado_puerto["servicio"] = "FTP"
                    elif "apache" in banner.lower():
                        resultado_puerto["servicio"] = "HTTP (Apache)"
                    elif "nginx" in banner.lower():
                        resultado_puerto["servicio"] = "HTTP (Nginx)"
                    elif "streamlit" in banner.lower() or "http" in banner.lower():
                        resultado_puerto["servicio"] = servicios_comunes.get(puerto, "HTTP Web Service")

                    # Realiza el cruce de firmas buscando coincidencias dentro de la base de datos de CVEs
                    for llave_firma, info_vuln in DICCIONARIO_VULNERABILIDADES.items():
                        if llave_firma in banner.lower():
                            resultado_puerto["vulnerabilidad"] = info_vuln["descripcion"]
                            resultado_puerto["cve"] = info_vuln["cve"]
                            resultado_puerto["severidad"] = info_vuln["severidad"]
                            break
            except Exception:
                pass
    except Exception:
        pass
    finally:
        # Garantiza el cierre del descriptor de archivo del socket para liberar recursos
        sock.close()

    # Retorna el reporte estructurado del puerto TCP analizado
    return resultado_puerto

# =====================================================================
# 6. ORQUESTADOR DE ALCANCE Y PARSEO DE PUERTOS
# =====================================================================
def ejecutar_escaneo_alcance(alcance, mapa_red, modo_puertos, cadena_manual="", sesiones_globales=None):
    # Vector estático con los puertos críticos para auditorías rápidas
    puertos_estandar = [21, 22, 23, 25, 80, 443, 3306, 3389]
    # Vector ampliado con puertos de servicios comunes y servidores web de desarrollo
    puertos_comunes = [21, 22, 23, 25, 80, 443, 1433, 3306, 3389, 5000, 8000, 8080, 8501]

    # Array que contendrá los puertos definitivos que se van a auditar
    puertos_a_escanear = []

    # Aplica las reglas del perfil de puertos seleccionado en la interfaz
    if modo_puertos == "Puertos Estándar":
        puertos_a_escanear = puertos_estandar
    elif modo_puertos == "Todos los Puertos Comunes":
        puertos_a_escanear = puertos_comunes
    else:
        try:
            # Parsea y limpia la cadena de puertos ingresada de forma manual por comas
            puertos_a_escanear = [int(p.strip()) for p in cadena_manual.split(",") if p.strip().isdigit()]
        except Exception:
            puertos_a_escanear = puertos_estandar

    # Extrae las IPs con sesión del repositorio para enfocar el alcance si se solicita
    ips_con_sesion = []
    if sesiones_globales:
        for usuario, info in sesiones_globales.items():
            ip_origen = info.get("IP de Origen")
            if ip_origen:
                ips_con_sesion.append(ip_origen)

    # Determina los objetivos (IPs) sobre los cuales se ejecutará el escaneo de red
    ips_objetivo = []

    if alcance == "Solo Dispositivos en Sesión":
        ips_objetivo = ips_con_sesion
    elif alcance == "Todos los Dispositivos Detectados":
        # Recorre la lista de filas del mapa y toma IPs únicas (evita escanear duplicados)
        ips_vistas = []
        for fila in mapa_red:
            if fila["ip"] not in ips_vistas:
                ips_vistas.append(fila["ip"])
        ips_objetivo = ips_vistas
    else:
        ips_objetivo = [alcance]

    # Diccionario para agrupar los resultados categorizados por dirección IP
    reporte_final = {}
    # Itera y escanea cada puerto sobre las direcciones IP seleccionadas
    for ip in ips_objetivo:
        reporte_final[ip] = []
        for puerto in puertos_a_escanear:
            res = escanear_puerto_individual(ip, puerto)
            # Solo registra los resultados si el puerto TCP se encuentra expuesto/abierto
            if res["estado"] == "Abierto":
                reporte_final[ip].append(res)

    # Retorna el mapa final de hallazgos del escaneo
    return reporte_final

# =====================================================================
# INTERFAZ VISUAL DEL MÓDULO (CON DASHBOARD SUPERIOR INTEGRADO)
# =====================================================================

# Renderiza la consola técnica del Grupo 2 con el dashboard ejecutivo en la parte superior
def vista_escaneo_seguridad(shared):
    st.title("🛡️ Consola de Auditoría y Escáner de Red (Grupo 2)")
    st.subheader("Módulo de detección de activos, análisis de puertos y vulnerabilidades")
    st.write("---")

    # Construye el MAPA visible = base global (sesiones) + capa privada (mi escaneo)
    # La base se recalcula en cada render leyendo shared["sesiones_activas"], por eso
    # se actualiza sola cuando alguien entra o sale de sesión.
    mapa_dispositivos = fusionar_mapa(
        shared["sesiones_activas"],
        st.session_state.mapa_escaneo_privado
    )

    # =====================================================================
    # DASHBOARD ANALÍTICO DEL GRUPO 2 (VISTA SUPERIOR UNIFICADA)
    # =====================================================================
    st.markdown("### 📊 Dashboard Ejecutivo de Ciberseguridad")

    # Divide el bloque del dashboard superior en dos grandes columnas simétricas
    col_kpis, col_metricas_red = st.columns([1, 1])

    # Panel Izquierdo: Tarjetas de datos analíticos (Métricas operativas del SOC)
    with col_kpis:
        st.markdown("#### **Indicadores del Entorno**")

        # Recupera el total de operadores registrados desde el estado global
        total_usuarios = len(shared["usuarios_db"])
        st.info(f"🧑‍💻 **Usuarios Registrados en el Sistema:** `{total_usuarios}`")

        # Muestra el total de USUARIOS CONECTADOS en este momento (sesiones activas globales)
        total_conectados = len(shared["sesiones_activas"])
        st.success(f"🟢 **Usuarios Conectados Ahora:** `{total_conectados}`")

        # METRICA AMARILLA: alertas de severidad ALTA de MI escaneo (privado por sesión)
        total_alertas_altas = st.session_state.alertas_altas_db
        st.warning(f"📋 **Alertas de Vulnerabilidades Altas:** `{total_alertas_altas}`")

        # METRICA ROJA: alertas críticas de MI escaneo (privado por sesión)
        total_alertas_criticas = st.session_state.alertas_criticas_db
        st.error(f"🚨 **Alertas de Vulnerabilidades Críticas:** `{total_alertas_criticas}`")

    # Panel Derecho: Estado de dispositivos físicos en la red
    with col_metricas_red:
        st.markdown("#### **Clasificación de Activos en Red (Tiempo Real)**")

        # Inicializadores para los acumuladores estadísticos
        activos_auth = 0
        desconocidos = 0

        # Cuenta los estados recorriendo la lista de filas del mapa fusionado
        for fila in mapa_dispositivos:
            if "🟢" in fila["estado"]:
                activos_auth += 1
            elif "🟡" in fila["estado"]:
                desconocidos += 1

        # Divide el panel derecho en dos subcolumnas horizontales para los números limpios
        subcol1, subcol2 = st.columns(2)

        with subcol1:
            st.metric(label="🟢 Autenticados", value=activos_auth)
        with subcol2:
            st.metric(label="🟡 Desconocidos", value=desconocidos)

        # Mensaje de ayuda dinámico debajo de las métricas de red
        if not st.session_state.mapa_escaneo_privado:
            st.markdown("<p style='color: gray; font-size: 13px; text-align: center; margin-top: 15px;'>⚠️ Base cargada con sesiones activas. Ejecuta un ping sweep para detectar dispositivos sin sesión.</p>", unsafe_allow_html=True)
        else:
            st.markdown("<p style='color: #10B981; font-size: 13px; text-align: center; margin-top: 15px;'>✅ Datos de red actualizados según tu último descubrimiento.</p>", unsafe_allow_html=True)

    st.write("---")

    # =====================================================================
    # SECCIONES OPERATIVAS EN COLUMNAS (DESCUBRIMIENTO Y CONFIGURACIÓN)
    # =====================================================================
    col_izquierda, col_derecha = st.columns([1, 1.2])

    # Columna de Entrada (Configuraciones de red y puertos)
    with col_izquierda:
        st.markdown("### 📡 1. Descubrimiento de Activos")
        # Campo de entrada para definir el segmento local a auditar
        subred = st.text_input("Segmento de Red (Subred Base):", value="192.168.0.", help="Ejemplo: 192.168.1. o 10.0.0.")
        # Botón para detonar el barrido ICMP de forma síncrona
        btn_sweep = st.button("🚀 Iniciar Descubrimiento de Red", use_container_width=True)

        # Procesa las acciones del botón de descubrimiento de dispositivos
        if btn_sweep:
            with st.spinner("Realizando barrido ICMP (Ping Sweep)..."):
                # Ejecuta la función de ping sweep para recabar hosts activos
                ips_vivas = descubrir_red(subred)
                # Genera la capa PRIVADA del escaneo (desconocidos + huérfanos) y la guarda
                # en session_state -> es privada de ESTA sesión, otros usuarios no la ven
                st.session_state.mapa_escaneo_privado = generar_capa_escaneo(ips_vivas, shared["sesiones_activas"])
                # Registra el evento del escaneo en el SIEM global (auditoría compartida)
                operador = st.session_state.get("usuario_actual") or "ANÓNIMO"
                try:
                    g1.registrar_evento(shared, operador, f"Ejecutó un ping sweep sobre {subred}0/24", st.session_state.get("ip_cliente", "127.0.0.1"), "INFO")
                except Exception:
                    pass
                st.success(f"¡Barrido finalizado! Se encontraron {len(ips_vivas)} dispositivos activos.")
                st.rerun()

        st.write("---")
        st.markdown("### 🛡️ 2. Configuración del Escáner")

        # Arma dinámicamente las opciones de alcance leyendo las IPs del mapa fusionado
        opciones_alcance = ["Todos los Dispositivos Detectados", "Solo Dispositivos en Sesión"]
        for fila in mapa_dispositivos:
            # Evita repetir una IP si dos sesiones comparten la misma dirección
            if fila["ip"] not in opciones_alcance:
                opciones_alcance.append(fila["ip"])

        # Desplegable para seleccionar el target de la auditoría
        alcance_sel = st.selectbox("Alcance del Escáner de Puertos:", opciones_alcance)
        # Selectores de tipo exclusivo para definir los perfiles de puertos TCP
        modo_puertos = st.radio("Modo de Selección de Puertos:", ["Puertos Estándar", "Todos los Puertos Comunes", "Puertos Manuales"])

        # Inicializa la variable de puertos personalizados
        cadena_manual = ""
        # Habilita un control de entrada de texto si se escoge el perfil manual
        if modo_puertos == "Puertos Manuales":
            cadena_manual = st.text_input("Puertos separados por comas (Ej: 21,22,80):", value="80,443")

        # Diseño limpio de fondo blanco para visualizar los puertos estándar a evaluar
        if modo_puertos == "Puertos Estándar":
            st.markdown("""
            <div style="background-color: #FFFFFF; padding: 12px; border-radius: 6px; border: 1px solid #E2E8F0; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                <div style="margin-bottom: 8px; color: #1E293B; font-size: 13px;">📋 <b>Puertos estándar que se van a escanear:</b></div>
                <div style="line-height: 2;">
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">21 // FTP</code>
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">22 // SSH</code>
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">23 // Telnet</code>
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">25 // SMTP</code>
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">80 // HTTP</code>
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">443 // HTTPS</code>
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">3306 // MySQL</code>
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">3389 // RDP</code>
                </div>
            </div>
            """, unsafe_allow_html=True)

        # Diseño limpio de fondo blanco para visualizar todos los puertos comunes a evaluar
        if modo_puertos == "Todos los Puertos Comunes":
            st.markdown("""
            <div style="background-color: #FFFFFF; padding: 12px; border-radius: 6px; border: 1px solid #E2E8F0; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                <div style="margin-bottom: 8px; color: #1E293B; font-size: 13px;">📋 <b>Puertos comunes que se van a escanear:</b></div>
                <div style="line-height: 2;">
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">21 // FTP</code>
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">22 // SSH</code>
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">23 // Telnet</code>
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">25 // SMTP</code>
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">80 // HTTP</code>
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">443 // HTTPS</code>
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">1433 // MSSQL</code>
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">3306 // MySQL</code>
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">3389 // RDP</code>
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">5000 // Flask</code>
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">8000 // Django</code>
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">8080 // Proxy</code>
                    <code style="background-color: #F1F5F9; color: #1E293B; padding: 4px 8px; border-radius: 4px; border: 1px solid #CBD5E1; font-size: 12px;">8501 // Streamlit</code>
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.write("---")
        # Botón para ejecutar el análisis de sockets TCP Connect Scan
        btn_escanear = st.button("🔍 Ejecutar Escaneo de Sockets", type="primary", use_container_width=True)

    # Columna de Salida (Mapa de dispositivos y Reportes de vulnerabilidades)
    with col_derecha:
        st.markdown("### 🗺️ Mapa de Correlación de Dispositivos")

        # El mapa SIEMPRE tiene contenido porque su base son las sesiones activas globales.
        # Cada sesión es una fila propia, así dos operadores con la misma IP se ven separados.
        if mapa_dispositivos:
            filas_tabla = []
            for fila in mapa_dispositivos:
                filas_tabla.append({
                    "Dirección IP": fila["ip"],
                    "Estado Operativo": fila["estado"],
                    "Usuario": fila["usuario"],
                    "Rol de Acceso": fila["rol"]
                })
            st.dataframe(filas_tabla, use_container_width=True)
        else:
            st.info("No hay usuarios en sesión ni dispositivos descubiertos todavía.")

        # Disparador principal para iniciar la auditoría sobre los sockets
        if btn_escanear:
            if not mapa_dispositivos:
                st.error("Error: No hay dispositivos en el mapa para escanear.")
            else:
                with st.spinner("Escaneando puertos, banners e identificando servicios..."):
                    # Ejecuta el escaneo de puertos y guarda el reporte en el estado PRIVADO de la sesión
                    st.session_state.ultimo_reporte_g2 = ejecutar_escaneo_alcance(
                        alcance_sel,
                        mapa_dispositivos,
                        modo_puertos,
                        cadena_manual,
                        shared["sesiones_activas"]
                    )

                    # Inicializa los acumuladores de alertas para alimentar el dashboard privado
                    alertas_criticas_totales = 0
                    alertas_altas_totales = 0

                    # Cuenta y clasifica las severidades del reporte
                    for ip, resultados in st.session_state.ultimo_reporte_g2.items():
                        for r in resultados:
                            if r["severidad"] == "CRÍTICA":
                                alertas_criticas_totales += 1
                            elif r["severidad"] == "ALTA":
                                alertas_altas_totales += 1

                    # Almacena el número consolidado de alertas en el estado privado de la sesión
                    st.session_state.alertas_criticas_db = alertas_criticas_totales
                    st.session_state.alertas_altas_db = alertas_altas_totales
                    # Refresca el flujo web para que los resultados persistan y suban las métricas
                    st.rerun()

        # Renderizado persistente del reporte final (privado de esta sesión)
        if st.session_state.ultimo_reporte_g2 is not None:
            st.write("---")
            st.markdown("### 📋 Reporte Detallado de Vulnerabilidades Encontradas")

            # Bandera lógica para comprobar si se detectó al menos un puerto TCP expuesto
            hay_resultados = False

            # Recorre el reporte fijo que se encuentra guardado en la sesión
            for ip, resultados in st.session_state.ultimo_reporte_g2.items():
                if resultados:
                    hay_resultados = True
                    st.markdown(f"#### **Host: {ip}**")

                    for r in resultados:
                        # Asigna colores dinámicos HTML según el nivel de severidad del CVE encontrado
                        if r["severidad"] == "CRÍTICA":
                            color_severidad = "#EF4444"
                        elif r["severidad"] == "ALTA":
                            color_severidad = "#F97316"
                        elif r["severidad"] == "MEDIA":
                            color_severidad = "#EAB308"
                        else:
                            color_severidad = "#10B981"

                        # Limpia el banner eliminando caracteres nulos e intercepta los saltos de línea
                        banner_limpio = str(r['version']).replace('\x00', '').strip()
                        banner_html = banner_limpio.replace('\r\n', '<br>').replace('\n', '<br>')

                        # Imprime la tarjeta con el diseño y el banner formateado renglón por renglón
                        html_vulnerabilidad = f"""
                        <div style="border-left: 6px solid {color_severidad}; background-color: #FFFFFF; padding: 15px; border-radius: 6px; margin-bottom: 12px; border-top: 1px solid #E2E8F0; border-right: 1px solid #E2E8F0; border-bottom: 1px solid #E2E8F0; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #F1F5F9; padding-bottom: 8px; margin-bottom: 10px;">
                                <span style="font-size: 15px; font-weight: bold; color: #1E293B;">🔌 Puerto {r['puerto']} // {r['servicio']}</span>
                                <span style="background-color: {color_severidad}; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: #FFFFFF; letter-spacing: 0.5px;">
                                    {r['severidad']}
                                </span>
                            </div>
                            <div style="font-size: 13px; line-height: 1.6; color: #334155;">
                                <div style="margin-bottom: 8px;">
                                    🧬 <i><b>Versión Identificada (Banner):</b></i>
                                    <div style="background-color: #F8FAFC; color: #0F172A; padding: 10px; border-radius: 4px; border: 1px solid #E2E8F0; font-family: 'Courier New', Courier, monospace; font-size: 12px; margin-top: 5px; max-height: 250px; overflow-y: auto;">
                                        {banner_html}
                                    </div>
                                </div>
                                <div style="margin-bottom: 4px;">
                                    🏷️ <i><b>Código CVE:</b></i> <code style="background-color: #F1F5F9; color: #1E293B; padding: 2px 6px; border-radius: 4px; font-size: 12px; border: 1px solid #E2E8F0;">{r['cve']}</code>
                                </div>
                                <div>
                                    📝 <i><b>Vulnerabilidad Encontrada:</b></i> <span style="font-weight: 500; color: #1E293B;">{r['vulnerabilidad']}</span>
                                </div>
                            </div>
                        </div>
                        """
                        st.markdown(html_vulnerabilidad, unsafe_allow_html=True)

            # Si no se detectaron puertos abiertos expuestos tras la ejecución del análisis
            if not hay_resultados:
                st.info("No se encontraron puertos TCP expuestos en el alcance analizado.")

# =====================================================================
# MODO AUTÓNOMO (EJECUCIÓN DIRECTA 'streamlit run grp02.py')
# ---------------------------------------------------------------------
# ESTE módulo SÍ exige login (es el único con autenticación obligatoria).
# =====================================================================
if __name__ == "__main__":
    import share_state

    st.set_page_config(page_title="Módulo Autónomo - Grupo 2", page_icon="🛡️", layout="wide")

    # Obtiene el estado GLOBAL compartido (cacheado como recurso único del proceso)
    shared = share_state.obtener_estado_global()
    # Prepara el contexto local de la sesión (IP, punteros locales y estado privado del escáner)
    share_state.preparar_contexto_local(shared)

    # Interruptor perimetral de autenticación local del escáner (bloqueado por defecto)
    if "autenticado_local_g2" not in st.session_state:
        st.session_state.autenticado_local_g2 = False

    # Valida el perímetro de seguridad forzando el login local del analista
    if not st.session_state.autenticado_local_g2:
        st.markdown("<h1 style='text-align: center;'>🛡️ CyberShield SOC - Grupo 2</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; color: gray;'>Control de Acceso de Módulo Local Dedicado (Escáner)</p>", unsafe_allow_html=True)
        st.write("---")

        col_login, _ = st.columns([2, 1])
        with col_login:
            with st.form("form_login_local_g2"):
                input_user = st.text_input("Usuario Operador:", placeholder="Ej. cybershield").strip()
                input_pass = st.text_input("Contraseña Operativa:", type="password")
                btn_login = st.form_submit_button("Acceder al Escáner", type="primary", width="stretch")

                if btn_login:
                    # Delega la verificación criptográfica con bcrypt al Grupo 1 usando el estado global
                    exito, rol = g1.verificar_credenciales(shared, input_user, input_pass, st.session_state.ip_cliente)
                    if exito:
                        st.session_state.autenticado_local_g2 = True
                        st.session_state.usuario_actual = input_user
                        # Registra la sesión en el estado GLOBAL para que aparezca en el mapa de todos
                        shared["sesiones_activas"][input_user] = {"IP de Origen": st.session_state.ip_cliente, "Rol": rol}
                        st.success("¡Acceso concedido al módulo!")
                        st.rerun()
                    else:
                        st.error("Error de credenciales o datos de usuario no válidos.")
        st.stop()

    # Barra lateral de navegación dedicada para aislar el módulo durante las pruebas individuales
    st.sidebar.title("🛡️ CyberShield SOC")
    st.sidebar.write(f"👤 **Usuario:** `{st.session_state.usuario_actual}`")
    st.sidebar.write("---")

    opciones_locales = ["🛡️ Escáner de Seguridad"]
    menu_sel = st.sidebar.radio("Navegación del Grupo:", opciones_locales)

    st.sidebar.write("---")
    # Botón para salir y purgar las variables del estado de autenticación local
    if st.sidebar.button("🚪 Cerrar Sesión Local", width="stretch"):
        # Elimina la sesión del registro GLOBAL para que desaparezca del mapa de todos
        if st.session_state.usuario_actual in shared["sesiones_activas"]:
            del shared["sesiones_activas"][st.session_state.usuario_actual]
        st.session_state.autenticado_local_g2 = False
        st.session_state.usuario_actual = None
        st.rerun()

    # Enrutador que renderiza la consola con el dashboard unificado
    if menu_sel == "🛡️ Escáner de Seguridad":
        vista_escaneo_seguridad(shared)
