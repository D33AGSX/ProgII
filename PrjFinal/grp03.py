import streamlit as st
import datetime
import importlib

# ====================================================================
#  GRUPO 3: GESTIÓN DE INCIDENTES (TICKETS Y SLA)
# --------------------------------------------------------------------
#  Los tickets (incidentes_db) son estado GLOBAL: si alguien abre un
#  ticket, todas las sesiones lo ven. Las funciones core mutan
#  shared["incidentes_db"] in-place. Este módulo NO exige login.
# ====================================================================

# Importa dinámicamente el Grupo 1 para reutilizar el registro de eventos del SIEM
try:
    g1 = importlib.import_module("grp01")
except ModuleNotFoundError:
    st.error("❌ No se encontró el archivo 'grp01.py'. Asegúrate de que esté en la misma carpeta que este script.")
    st.stop()

# ====================================================================
#  LÓGICA CORE DEL MÓDULO (OPERAN SOBRE EL ESTADO GLOBAL 'shared')
# ====================================================================

# Genera la estructura de datos base para un ticket aplicando prefijos y configuraciones de SLA
def inicializar_ticket(clasificacion, detalle, descripcion, prioridad):
    # Captura la marca de tiempo exacta del sistema para la estampa cronológica
    marca_tiempo = datetime.datetime.now().strftime('%Y%m%d%H%M%S')

    # Aplica el prefijo estricto REQ si es un requerimiento, o INC si es un incidente
    if clasificacion == "Requerimiento":
        ticket_id = f"REQ-{marca_tiempo}"
    else:
        ticket_id = f"INC-{marca_tiempo}"

    # Asigna los minutos permitidos para la resolución antes de romper el SLA
    if prioridad == "Crítica":
        minutos_sla = 2
    elif prioridad == "Alta":
        minutos_sla = 5
    elif prioridad == "Medio":
        minutos_sla = 10
    else:
        minutos_sla = 15

    # Retorna la estructura de diccionario estandarizada con la lista de notas vacía
    return {
        "ID": ticket_id,
        "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Clasificación": clasificacion,
        "Detalle": detalle,
        "Descripción": descripcion,
        "Prioridad": prioridad,
        "Estado": "Abierto",
        "AsignadoA": "Sin Asignar",
        "Minutos_SLA": minutos_sla,
        "Notas": []
    }


# Registra el ticket colocándolo en la primera posición del repositorio GLOBAL
def inyectar_ticket(shared, clasificacion, detalle, descripcion, prioridad):
    # Invoca la función core para construir el esquema estructurado del ticket
    nuevo_ticket = inicializar_ticket(clasificacion, detalle, descripcion, prioridad)
    # Agrega el registro al inicio del arreglo GLOBAL (mutación in-place)
    shared["incidentes_db"].insert(0, nuevo_ticket)
    # Retorna el identificador final asignado para la bitácora del SIEM
    return nuevo_ticket["ID"]


# Modifica el estado del ticket y registra al operador como el encargado del caso
def asignar_ticket_operador(shared, ticket_id, usuario_asignado):
    # Recorre la lista GLOBAL de tickets almacenados en el SOC
    for ticket in shared["incidentes_db"]:
        # Valida la coincidencia exacta del identificador de ticket
        if ticket["ID"] == ticket_id:
            # Escribe el nombre del usuario operador en el campo de asignación
            ticket["AsignadoA"] = usuario_asignado
            # Actualiza el estado del ciclo de vida a atención activa
            ticket["Estado"] = "En Progreso"
            return True
    return False


# Finaliza el ticket actualizando su estatus operacional a Completado de forma permanente
def finalizar_ticket_operador(shared, ticket_id):
    # Busca el ticket objetivo iterando el arreglo GLOBAL de memoria
    for ticket in shared["incidentes_db"]:
        # Encuentra el identificador exacto seleccionado por el analista
        if ticket["ID"] == ticket_id:
            # Asigna el estado final de cierre del flujo de soporte
            ticket["Estado"] = "Completado"
            return True
    return False


# Añade un comentario de seguimiento con fecha y firma de operador dentro de la bitácora del ticket
def agregar_nota_ticket(shared, ticket_id, usuario, texto_nota):
    # Itera las solicitudes guardadas en la cola GLOBAL de atención
    for ticket in shared["incidentes_db"]:
        # Encuentra el ticket destino mediante la validación de su identificador
        if ticket["ID"] == ticket_id:
            # Estructura el objeto de la nota con metadatos cronológicos completos
            nueva_nota = {
                "Fecha": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Autor": usuario,
                "Mensaje": texto_nota.strip()
            }
            # Inserta el comentario al final de la lista interna de notas del ticket
            ticket["Notas"].append(nueva_nota)
            return True
    return False


# Evalúa dinámicamente el estatus del SLA midiendo el tiempo transcurrido en minutos
def calcular_estatus_ticket(ticket):
    # Si el ticket ya se encuentra en su fase final de cierre, conserva el estatus definitivo
    if ticket["Estado"] == "Completado":
        return "Completados"

    # Si el caso no ha sido tomado por ningún miembro del personal de ciberseguridad
    if ticket["Estado"] == "Abierto":
        return "Abierto (Sin Asignar)"

    try:
        # Convierte el string del Timestamp a un formato nativo de objeto datetime
        hora_creacion = datetime.datetime.strptime(ticket["Timestamp"], "%Y-%m-%d %H:%M:%S")
        # Obtiene la brecha de tiempo exacta restando el valor contra la hora del sistema
        diferencia = datetime.datetime.now() - hora_creacion
        # Pasa los segundos de la brecha a unidades de minutos flotantes
        minutos_transcurridos = diferencia.total_seconds() / 60

        # Compara el consumo de tiempo real contra el límite acordado según la prioridad
        if minutos_transcurridos > ticket["Minutos_SLA"]:
            # Retorna la alerta de incumplimiento de tiempos del SOC
            return "En progreso (superaron el SLA)"
        else:
            # Retorna el estado regular de atención bajo control horario
            return "En progreso (a tiempo)"
    # Control preventivo si ocurre un fallo en el procesamiento de las cadenas de tiempo
    except Exception:
        return "En progreso (a tiempo)"

# ====================================================================
#  PANTALLAS EMERGENTES E INTERACTIVIDAD DE TICKETS (DIALOGS)
# ====================================================================

# Declara la ventana emergente nativa para la captura limpia de nuevos tickets
@st.dialog("➕ Crear Nuevo Ticket de Soporte")
def formulario_crear_ticket(shared):
    # Menú selector exclusivo para definir el tipo de solicitud inicial
    tipo_ticket = st.radio("Clasificación del Ticket:", ["Incidente", "Requerimiento"])
    # Entrada de texto compacta para registrar el título del caso
    txt_detalle = st.text_input("Detalle (Título Corto):", placeholder="Ej: Fuga de datos o Alta de cuenta")
    # Entrada de texto multilínea para la descripción detallada del problema
    txt_desc = st.text_area("Descripción:", placeholder="Coloca aquí los antecedentes detallados...")

    # Filtra dinámicamente las prioridades autorizadas según el tipo de flujo operativo
    if tipo_ticket == "Incidente":
        # Bloquea las prioridades de incidentes únicamente a rangos de criticidad alta
        lista_prioridades = ["Alta", "Crítica"]
    else:
        # Permite únicamente prioridades de rutina para las solicitudes de servicio
        lista_prioridades = ["Baja", "Medio"]

    # Desplegable interactivo que renderiza el vector de prioridades permitido
    sel_prioridad = st.selectbox("Prioridad del Ticket:", lista_prioridades)
    # Botón de confirmación para procesar y enviar el formulario
    btn_guardar = st.button("Enviar Ticket al Repositorio", type="primary")

    # Si el analista acciona el envío de datos
    if btn_guardar:
        # Valida estructuralmente que no existan entradas vacías en los campos requeridos
        if txt_detalle.strip() == "" or txt_desc.strip() == "":
            st.error("Error: Todos los campos del formulario son obligatorios.")
        else:
            # Ejecuta la inyección del ticket en el estado GLOBAL aplicando la nomenclatura
            ticket_id = inyectar_ticket(shared, tipo_ticket, txt_detalle.strip(), txt_desc.strip(), sel_prioridad)
            # Identifica al operador que crea el ticket (o ANÓNIMO si no hay sesión)
            autor = st.session_state.get("usuario_actual") or "ANÓNIMO"
            # Intenta enviar el reporte de evento a la bitácora del SIEM global
            try:
                g1.registrar_evento(shared, autor, f"Abrió un ticket de {tipo_ticket}: {ticket_id}", st.session_state.get("ip_cliente", "127.0.0.1"), "WARNING")
            except Exception:
                pass
            st.success(f"¡Ticket {ticket_id} generado de manera exitosa!")
            # Recarga la aplicación para actualizar el dashboard analítico
            st.rerun()


# Declara la interfaz emergente detallada para inspección de bitácoras y gestión de notas
@st.dialog("🔍 Inspección y Seguimiento del Ticket")
def modal_detalle_ticket(shared, ticket_id):
    # Puntero para referenciar el objeto del ticket recuperado en la búsqueda
    ticket_activo = None
    # Recorre el repositorio GLOBAL para extraer el ticket seleccionado
    for t in shared["incidentes_db"]:
        if t["ID"] == ticket_id:
            ticket_activo = t
            break

    # Detiene la ejecución visual si el ticket no existe en el almacenamiento
    if not ticket_activo:
        st.error("No se pudo cargar la información del ticket.")
        st.stop()

    # Calcula el estatus actual de tiempos de forma dinámica en la ventana
    estatus_actual = calcular_estatus_ticket(ticket_activo)

    # Renderiza la ficha técnica estructurada en texto limpio dentro del contenedor
    st.markdown(f"### **Detalle:** {ticket_activo['Detalle']}")
    st.write(f"📄 **Descripción:** {ticket_activo['Descripción']}")
    st.write("---")

    # Divide la vista en dos columnas pequeñas para desplegar los metadatos fijos
    col_inf1, col_inf2 = st.columns(2)
    with col_inf1:
        st.write(f"🆔 **ID:** `{ticket_activo['ID']}`")
        st.write(f"📁 **Clasificación:** {ticket_activo['Clasificación']}")
        st.write(f"🚨 **Prioridad:** {ticket_activo['Prioridad']}")
    with col_inf2:
        st.write(f"📅 **Creado:** {ticket_activo['Timestamp']}")
        st.write(f"⏱️ **SLA Permitido:** {ticket_activo['Minutos_SLA']} minutos")
        st.write(f"📊 **Estatus SLA:** {estatus_actual}")

    st.write("---")

    # Determina el operador actual de la sesión (o ANÓNIMO si no hay login)
    operador_actual = st.session_state.get("usuario_actual") or "ANÓNIMO"

    # Bloque funcional que maneja los botones de cambio de estado en vivo
    if ticket_activo["Estado"] == "Abierto":
        # Botón para que el operador firme el ticket e inicie la atención
        if st.button("🤝 Asignarme este caso", use_container_width=True):
            asignar_ticket_operador(shared, ticket_id, operador_actual)
            try:
                g1.registrar_evento(shared, operador_actual, f"Se asignó el ticket {ticket_id}", st.session_state.get("ip_cliente", "127.0.0.1"), "INFO")
            except Exception:
                pass
            st.rerun()
    elif ticket_activo["Estado"] == "En Progreso":
        # Botón para finalizar las actividades y cerrar la solicitud permanentemente
        if st.button("🏁 Completar y Cerrar Ticket", type="primary", use_container_width=True):
            finalizar_ticket_operador(shared, ticket_id)
            try:
                g1.registrar_evento(shared, operador_actual, f"Completó la atención del ticket {ticket_id}", st.session_state.get("ip_cliente", "127.0.0.1"), "INFO")
            except Exception:
                pass
            st.rerun()

    st.write("---")

    # Sección dedicada a la lectura y escritura de comentarios en la bitácora
    st.markdown("💬 **Bitácora de Notas de Seguimiento**")

    # Itera y dibuja de forma elegante el historial de notas agregadas previamente
    for nota in ticket_activo["Notas"]:
        st.markdown(f"""
        <div style="background-color: #1E293B; padding: 8px 12px; border-radius: 6px; margin-bottom: 8px; border: 1px solid #334155;">
            <div style="display: flex; justify-content: space-between; font-size: 11px; color: #9CA3AF; margin-bottom: 4px;">
                <b>🧑‍💻 {nota['Autor']}</b>
                <span>🕒 {nota['Fecha']}</span>
            </div>
            <div style="font-size: 13px; color: #F3F4F6;">{nota['Mensaje']}</div>
        </div>
        """, unsafe_allow_html=True)

    # Formulario interno compacto exclusivo para la adición de comentarios sin cerrar el modal
    with st.form("form_agregar_nota_soc", clear_on_submit=True):
        input_nota = st.text_input("Redactar nueva nota de seguimiento:")
        btn_nota = st.form_submit_button("Agregar Nota", width="stretch")

        # Si el operador guarda la nota de texto
        if btn_nota:
            if input_nota.strip() != "":
                # Inserta la nota vinculándola al autor y al ID en el estado global
                agregar_nota_ticket(shared, ticket_id, operador_actual, input_nota)
                st.rerun()

# ====================================================================
#  PANTALLA VISUAL ENCAPSULADA (LLAMADA DESDE EL MAIN O LOCAL)
# ====================================================================

# Construye e imprime la consola operativa unificada del sistema de tickets del SOC
def vista_gestion_incidentes(shared):
    st.title("📋 Consola de Gestión de Incidentes (Grupo 3)")
    st.subheader("Panel unificado de seguimiento de niveles de servicio y ciclo de vida de tickets")
    st.write("---")

    # Inicializa las variables contadoras base exigidas por el panel de analítica de texto
    total_a_tiempo = 0
    total_fuera_sla = 0
    total_completados = 0

    # Recorre la base GLOBAL de tickets para consolidar las métricas de estado
    for t in shared["incidentes_db"]:
        estatus_dinamico = calcular_estatus_ticket(t)
        if estatus_dinamico == "En progreso (a tiempo)":
            total_a_tiempo += 1
        elif estatus_dinamico == "En progreso (superaron el SLA)":
            total_fuera_sla += 1
        elif estatus_dinamico == "Completados":
            total_completados += 1

    # Divide el bloque superior en columnas para estampar los indicadores numéricos rápidos
    col_kpi1, col_kpi2, col_kpi3, col_btn = st.columns([1, 1, 1, 1])
    with col_kpi1:
        st.metric(label="⏱️ En Progreso (A Tiempo)", value=total_a_tiempo)
    with col_kpi2:
        st.metric(label="🚨 Superaron el SLA", value=total_fuera_sla)
    with col_kpi3:
        st.metric(label="✅ Completados", value=total_completados)
    with col_btn:
        st.markdown("<p style='margin-bottom: 25px;'></p>", unsafe_allow_html=True)
        # Invoca la apertura del catálogo de creación de tickets en ventana emergente
        if st.button("➕ Crear Ticket", type="primary", use_container_width=True):
            formulario_crear_ticket(shared)

    st.write("---")

    # Dibuja el gráfico de barras nativo procesando la información del diccionario
    st.markdown("### 📊 Distribución General de Estatus")
    datos_grafico = {
        "En progreso (a tiempo)": total_a_tiempo,
        "En progreso (superaron el SLA)": total_fuera_sla,
        "Completados": total_completados
    }
    st.bar_chart(datos_grafico, use_container_width=True)

    st.write("---")

    st.markdown("### 📋 Bandeja de Seguimiento e Historial SOC")

    # Instancia el selector desplegable con las opciones dinámicas de filtrado
    filtro_seleccionado = st.selectbox(
        "Filtrar cola de trabajo por:",
        ["Ver Todos", "Solo Abiertos / Sin Asignar", "Solo en Progreso", "Solo Mis Tickets", "Solo Completados"]
    )

    # Determina el operador actual para el filtro "Solo Mis Tickets"
    operador_actual = st.session_state.get("usuario_actual") or "ANÓNIMO"

    # Array temporal para almacenar los registros que pasen los criterios de filtrado
    tickets_filtrados = []

    # Recorre y evalúa cada caso GLOBAL según la regla seleccionada en la interfaz
    for ticket in shared["incidentes_db"]:
        estatus_fila = calcular_estatus_ticket(ticket)

        if filtro_seleccionado == "Ver Todos":
            tickets_filtrados.append(ticket)
        elif filtro_seleccionado == "Solo Abiertos / Sin Asignar" and ticket["Estado"] == "Abierto":
            tickets_filtrados.append(ticket)
        elif filtro_seleccionado == "Solo en Progreso" and estatus_fila in ["En progreso (a tiempo)", "En progreso (superaron el SLA)"]:
            tickets_filtrados.append(ticket)
        elif filtro_seleccionado == "Solo Mis Tickets" and ticket["AsignadoA"] == operador_actual and ticket["Estado"] != "Completado":
            tickets_filtrados.append(ticket)
        elif filtro_seleccionado == "Solo Completados" and estatus_fila == "Completados":
            tickets_filtrados.append(ticket)

    # Valida si existen registros autorizados listos para su impresión
    if tickets_filtrados:
        # Array intermedio para dar estructura limpia de filas y celdas a la tabla compacta
        tabla_compacta = []

        # Procesa cada ticket filtrado rellenando los campos informativos esenciales
        for t in tickets_filtrados:
            estatus_visual = calcular_estatus_ticket(t)

            # Formatea visualmente la etiqueta del responsable de forma explícita
            if t["AsignadoA"] == "Sin Asignar":
                responsable_celda = "🟡 Sin Asignar"
            else:
                responsable_celda = f"🧑‍💻 {t['AsignadoA']}"

            # Inserta la fila mapeando las columnas claves elegidas para la optimización de pantalla
            tabla_compacta.append({
                "ID Ticket": t["ID"],
                "Tipo": t["Clasificación"],
                "Detalle (Asunto)": t["Detalle"],
                "Prioridad": t["Prioridad"],
                "Estatus de SLA": estatus_visual,
                "Asignado A": responsable_celda
            })

        # Renderiza la tabla optimizada nativa utilizando el ancho completo de la ventana
        st.dataframe(tabla_compacta, use_container_width=True)

        st.write("---")
        st.markdown("⚙️ **Acciones de Inspección Directa**")
        # Genera un vector con los identificadores activos para rellenar un selector de fila rápido
        lista_ids_filtrados = [reg["ID Ticket"] for reg in tabla_compacta]
        # Columnas para organizar el selector de fila al lado de su disparador
        col_sel, col_act = st.columns([3, 1])

        with col_sel:
            # Desplegable para seleccionar el ID exacto que se desea inspeccionar a detalle
            id_inspeccionar = st.selectbox("Selecciona el ID del Ticket que deseas abrir:", lista_ids_filtrados)
        with col_act:
            st.markdown("<p style='margin-bottom: 25px;'></p>", unsafe_allow_html=True)
            # Botón secundario que invoca el modal interactivo pasando el ID elegido
            if st.button("👁️ Abrir Ticket Seleccionado", use_container_width=True):
                modal_detalle_ticket(shared, id_inspeccionar)
    else:
        st.info("No se encontraron tickets en el repositorio que cumplan con la regla de filtrado seleccionada.")

# ====================================================================
#  MODO AUTÓNOMO (EJECUCIÓN DIRECTA 'streamlit run grp03.py')
# --------------------------------------------------------------------
#  Entra DIRECTO, sin login (según diseño: solo el escáner exige sesión).
# ====================================================================

# Bloque de aislamiento perimetral que concede independencia operacional al script web
if __name__ == "__main__":
    # Importa el módulo de estado compartido para obtener el diccionario global
    import share_state

    st.set_page_config(page_title="Módulo Autónomo - Grupo 3", page_icon="📋", layout="wide")

    # Obtiene el estado GLOBAL compartido (cacheado como recurso único del proceso)
    shared = share_state.obtener_estado_global()
    # Prepara el contexto local de la sesión (IP, punteros locales)
    share_state.preparar_contexto_local(shared)

    # Barra lateral privada para la entrega aislada del módulo ante el evaluador
    st.sidebar.title("🛡️ CyberShield SOC")
    st.sidebar.write("Módulo Grupo 3 (Autónomo)")
    st.sidebar.write("---")

    opciones_locales = ["📋 Gestión de Incidentes (Grupo 3)"]
    menu_sel = st.sidebar.radio("Navegación del Grupo:", opciones_locales)

    # Enrutador local dedicado que dibuja la pantalla principal del Grupo 3
    if menu_sel == "📋 Gestión de Incidentes (Grupo 3)":
        vista_gestion_incidentes(shared)
