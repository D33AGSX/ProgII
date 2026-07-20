import streamlit as st
import socket
import importlib

# ====================================================================
#  MÓDULO DE ESTADO COMPARTIDO GLOBAL (SHARE STATE)
# --------------------------------------------------------------------
#  Centraliza el estado del SOC y define claramente qué es GLOBAL
#  (compartido entre todas las sesiones) y qué es PRIVADO por sesión.
#
#  ESTADO GLOBAL (vive en 'shared' vía st.cache_resource, un solo
#  objeto en memoria para todo el proceso, igual para todos):
#    - usuarios_db      -> usuarios/credenciales (Grupo 1)
#    - soc_logs         -> cola de eventos del SIEM (Grupo 1)
#    - incidentes_db    -> tickets del SOC (Grupo 3)
#    - sesiones_activas -> quién está conectado y desde qué IP
#
#  ESTADO PRIVADO por sesión (vive en st.session_state, distinto por
#  cada navegador; solo lo ve quien lo generó):
#    - mapa_escaneo_privado -> dispositivos SIN sesión hallados por MI
#                              ping sweep (🟡 desconocidos / 🔴 huérfanos)
#    - ultimo_reporte_g2    -> MI reporte de puertos/vulnerabilidades
#    - alertas_criticas_db  -> contador de críticas de MI escaneo
#    - alertas_altas_db     -> contador de altas de MI escaneo
#
#  Regla de oro: el estado GLOBAL se MUTA in-place sobre 'shared'
#  (shared["x"]=... / .append / [k]=v). NUNCA se reasigna una copia
#  local que luego haya que "sincronizar". Eso era la causa del bug
#  original del ping sweep.
# ====================================================================

# Importa dinámicamente el Grupo 1 para reutilizar sus semillas de datos (usuarios/logs)
try:
    # Carga el módulo grp01 con las funciones de inicialización criptográfica
    _g1 = importlib.import_module("grp01")
except ModuleNotFoundError:
    # Si no se encuentra grp01, deja el puntero vacío y se usarán semillas mínimas
    _g1 = None


# Construye y devuelve el diccionario de estado GLOBAL; cacheado como recurso único del proceso
@st.cache_resource
def obtener_estado_global():
    # Prepara la base de usuarios y logs usando las semillas del Grupo 1 si está disponible
    if _g1 is not None:
        # Reutiliza la función oficial de inicialización de usuarios de grp01
        usuarios_iniciales = _g1.inicializar_usuarios()
        # Reutiliza la función oficial de inicialización de la cola de logs de grp01
        logs_iniciales = _g1.inicializar_logs()
    else:
        # Semilla mínima de respaldo por si grp01 no pudo importarse
        usuarios_iniciales = {}
        logs_iniciales = []

    # Retorna el diccionario maestro SOLO con las variables verdaderamente globales del SOC
    return {
        # Base de datos de usuarios/credenciales (Grupo 1) - GLOBAL
        "usuarios_db": usuarios_iniciales,
        # Cola de eventos del SIEM (Grupo 1) - GLOBAL
        "soc_logs": logs_iniciales,
        # Repositorio de tickets/incidentes del SOC (Grupo 3) - GLOBAL
        "incidentes_db": [],
        # Registro de sesiones activas: operador conectado + IP - GLOBAL
        "sesiones_activas": {}
    }


# Detecta de forma segura la dirección IPv4 privada de la máquina que corre el servidor
def obtener_ip_local():
    try:
        # Abre un socket UDP para consultar por cuál interfaz saldría el tráfico
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Simula una conexión de salida hacia un DNS público (no envía datos reales)
        s.connect(("8.8.8.8", 80))
        # Extrae la IPv4 local de la interfaz elegida por el sistema operativo
        ip = s.getsockname()[0]
        # Cierra el descriptor del socket para liberar el recurso de red
        s.close()
        # Devuelve la IP privada detectada
        return ip
    # Si la máquina no tiene red activa o el socket falla
    except Exception:
        # Retorna la dirección loopback estándar como valor seguro por defecto
        return "127.0.0.1"


# Prepara el contexto local de la sesión: detecta IP y arranca punteros locales por-navegador
def preparar_contexto_local(shared):
    # Detecta la IP de esta sesión solo la primera vez (evita repetir el socket en cada rerun)
    if "ip_cliente" not in st.session_state:
        # Guarda la IP detectada como dato local de este navegador
        st.session_state.ip_cliente = obtener_ip_local()

    # Garantiza un puntero al operador actual en el estado local de la sesión
    if "usuario_actual" not in st.session_state:
        # Arranca sin operador identificado hasta que alguien inicie sesión
        st.session_state.usuario_actual = None

    # Inicializa el estado PRIVADO del escáner de esta sesión (no compartido)
    if "mapa_escaneo_privado" not in st.session_state:
        # Capa privada del mapa: dispositivos sin sesión hallados por MI ping sweep
        st.session_state.mapa_escaneo_privado = {}
    if "ultimo_reporte_g2" not in st.session_state:
        # MI último reporte de puertos/vulnerabilidades (privado de esta sesión)
        st.session_state.ultimo_reporte_g2 = None
    if "alertas_criticas_db" not in st.session_state:
        # Contador de vulnerabilidades críticas de MI escaneo (privado)
        st.session_state.alertas_criticas_db = 0
    if "alertas_altas_db" not in st.session_state:
        # Contador de vulnerabilidades altas de MI escaneo (privado)
        st.session_state.alertas_altas_db = 0

    # Devuelve el diccionario global compartido para trabajar directamente sobre él
    return shared
