import streamlit as st
import grp01
import grp02
import grp03
import share_state

# ====================================================================
#  MAIN: ORQUESTADOR GLOBAL DEL SOC CYBERSHIELD
# --------------------------------------------------------------------
#  - El estado GLOBAL vive en share_state.obtener_estado_global() y es
#    la única fuente de verdad compartida entre todas las sesiones.
#  - LOGIN OBLIGATORIO: el programa bloquea TODO su contenido hasta que
#    el operador inicie sesión (cuenta semilla: cybershield / Panama01).
#  - Al iniciar sesión, la sesión se registra en shared["sesiones_activas"]
#    para que aparezca en el mapa del escáner de todos los operadores.
#  - El escaneo de red es privado por sesión; el resto de datos
#    (usuarios, logs, tickets, sesiones) es global y compartido.
# ====================================================================

# Configuración de página
st.set_page_config(page_title="CyberShield SOC - Orquestador Global", page_icon="🛡️", layout="wide")

# Obtiene el estado GLOBAL compartido (un solo objeto en memoria para todo el proceso)
shared = share_state.obtener_estado_global()
# Prepara el contexto local de la sesión (IP detectada + estado privado del escáner)
share_state.preparar_contexto_local(shared)

# Variable de control local: indica si ESTA sesión ha iniciado sesión
if "autenticado_global" not in st.session_state:
    st.session_state.autenticado_global = False

# ====================================================================
#  LOGIN GLOBAL OBLIGATORIO (BLOQUEA TODO EL PROGRAMA)
# ====================================================================
if not st.session_state.autenticado_global:
    # Cabecera centrada de la pantalla de acceso
    st.markdown("<h1 style='text-align: center;'>🛡️ CyberShield SOC</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: gray;'>Centro de Operaciones de Seguridad — Acceso Restringido</p>", unsafe_allow_html=True)
    st.write("---")

    # Divide la pantalla dejando un tercio libre a la derecha para centrar el formulario
    col_login, _ = st.columns([2, 1])
    with col_login:
        # Formulario agrupado para el envío seguro de credenciales
        with st.form("form_login_global"):
            # Captura el usuario limpiando espacios
            input_user = st.text_input("Usuario:", placeholder="Ej. cybershield").strip()
            # Captura la contraseña ocultando los caracteres
            input_pass = st.text_input("Contraseña:", type="password")
            # Botón primario de envío del formulario de acceso
            if st.form_submit_button("Iniciar Sesión", type="primary", use_container_width=True):
                # Verifica las credenciales contra el estado global (bcrypt del Grupo 1)
                exito, rol = grp01.verificar_credenciales(shared, input_user, input_pass, st.session_state.ip_cliente)
                if exito:
                    # Activa la sesión local de este navegador
                    st.session_state.autenticado_global = True
                    st.session_state.usuario_actual = input_user
                    # Registra la sesión en el estado GLOBAL para que aparezca en el mapa de todos
                    shared["sesiones_activas"][input_user] = {"IP de Origen": st.session_state.ip_cliente, "Rol": rol}
                    st.rerun()
                else:
                    st.error("Error de credenciales.")
    # Detiene la ejecución aquí: nada más del programa se renderiza sin sesión
    st.stop()

# ====================================================================
#  BARRA LATERAL: NAVEGACIÓN (solo visible ya autenticado)
# ====================================================================
st.sidebar.title("🛡️ CyberShield SOC")
# Muestra el operador que tiene la sesión activa en este navegador
st.sidebar.write(f"👤 Operador: `{st.session_state.usuario_actual}`")
st.sidebar.write("---")

# Menú de navegación con todas las secciones del SOC
menu_sel = st.sidebar.radio("Navegación:", [
    "🏠 Panel Global",
    "👤 Gestión de Accesos",
    "🛡️ Escáner de Red",
    "🎟️ Gestión de Incidentes",
    "📜 Auditoría de Logs"
])

st.sidebar.write("---")
# Botón de cierre de sesión que limpia la sesión global compartida
if st.sidebar.button("🚪 Cerrar Sesión", use_container_width=True):
    # Elimina la sesión del registro global para que desaparezca del mapa de todos
    if st.session_state.usuario_actual in shared["sesiones_activas"]:
        del shared["sesiones_activas"][st.session_state.usuario_actual]
    # Apaga el interruptor de sesión local
    st.session_state.autenticado_global = False
    st.session_state.usuario_actual = None
    st.rerun()

# ====================================================================
#  PANEL GLOBAL (CENTRO DE MANDO) - LEE TODO DE 'shared'
# ====================================================================
if menu_sel == "🏠 Panel Global":
    st.title("🏠 Panel Global de Seguridad")

    st.markdown("### 📊 Indicadores Maestros")
    col1, col2, col3 = st.columns(3)
    # Usuarios conectados = sesiones activas globales (igual para todas las sesiones)
    with col1:
        st.metric("👥 Usuarios Conectados", len(shared["sesiones_activas"]))
    # Total de usuarios registrados en la base global
    with col2:
        st.metric("🧑‍💻 Usuarios Registrados", len(shared["usuarios_db"]))
    # Total de tickets en el repositorio global
    with col3:
        st.metric("🎟️ Tickets Totales", len(shared["incidentes_db"]))

    st.write("---")

    st.markdown("### ⏱️ Estado del SLA de Incidentes")
    c1, c2, c3 = st.columns(3)
    # Consolida los estatus de SLA leyendo los tickets globales
    t_a_tiempo = sum(1 for t in shared["incidentes_db"] if grp03.calcular_estatus_ticket(t) == "En progreso (a tiempo)")
    t_fuera = sum(1 for t in shared["incidentes_db"] if grp03.calcular_estatus_ticket(t) == "En progreso (superaron el SLA)")
    t_comp = sum(1 for t in shared["incidentes_db"] if grp03.calcular_estatus_ticket(t) == "Completados")

    c1.metric("⏱️ En Progreso (A Tiempo)", t_a_tiempo)
    c2.metric("🚨 Superaron el SLA", t_fuera)
    c3.metric("✅ Completados", t_comp)

    st.write("---")

    st.markdown("### 👥 Sesiones Activas en el SOC")
    # Muestra la tabla de operadores conectados (dato global compartido)
    if shared["sesiones_activas"]:
        filas_sesiones = []
        for usuario, info in shared["sesiones_activas"].items():
            filas_sesiones.append({
                "Operador": usuario,
                "IP de Origen": info.get("IP de Origen", "N/A"),
                "Rol": info.get("Rol", "N/A")
            })
        st.dataframe(filas_sesiones, use_container_width=True)
    else:
        st.info("No hay operadores con sesión iniciada en este momento.")

    st.write("---")

    st.markdown("### 📜 Actividad Reciente del SIEM")
    # Muestra los últimos eventos del log global (mismos datos que Auditoría de Logs)
    if shared["soc_logs"]:
        # Toma solo los 10 eventos más recientes para no saturar el panel principal
        logs_recientes = shared["soc_logs"][:10]
        st.dataframe(logs_recientes, use_container_width=True)
        # Enlace mental a la vista completa para el resto del historial
        st.caption("Mostrando los 10 eventos más recientes. Ve a 'Auditoría de Logs' para el historial completo.")
    else:
        st.info("Aún no se han registrado eventos en el SIEM.")

# ====================================================================
#  ENRUTAMIENTO DE MÓDULOS (todos accesibles ya autenticado)
# ====================================================================
# Gestión de Accesos (Grupo 1)
elif menu_sel == "👤 Gestión de Accesos":
    grp01.vista_gestion_usuarios(shared)

# Escáner de Red (Grupo 2)
elif menu_sel == "🛡️ Escáner de Red":
    grp02.vista_escaneo_seguridad(shared)

# Gestión de Incidentes (Grupo 3)
elif menu_sel == "🎟️ Gestión de Incidentes":
    grp03.vista_gestion_incidentes(shared)

# Auditoría de Logs (Grupo 1)
elif menu_sel == "📜 Auditoría de Logs":
    grp01.vista_centro_monitoreo(shared)
