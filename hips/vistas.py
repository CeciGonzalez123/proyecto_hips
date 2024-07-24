import os
import subprocess
import shutil
from flask import Blueprint, render_template, request, redirect, url_for, flash
import hashlib
import json
import random
import string
import re
from collections import defaultdict
from datetime import datetime
from flask_login import login_user, login_required, logout_user, current_user, UserMixin
import smtplib
from email.mime.text import MIMEText

main = Blueprint('main', __name__)
CUARENTENA_DIR = '/tmp/cuarentena'

# Configuración para acceso a páginas
ACCESS_LOG_FILE = '/var/log/access_log'
MAX_ERRORS = 5

# Configuración para archivo de correos
MAIL_LOG_FILE = '/var/log/maillog'
MAX_EMAILS = 100  # Máximo número de correos permitidos antes de bloquear

# Configuración para archivos de autenticación
SECURE_LOG_FILE = '/var/log/secure'
MAX_AUTH_ERRORS = 20

# Configuración para archivo de tcpdump
TCPDUMP_LOG_FILE = '/var/log/tcpdump.txt'
UMBRAL_DDOS = 5  # Ejemplo de máximo de entradas permitidas

# Configuracion para archivo de accesos no validos
REMOTE_LOG_FILE = "/var/log/remote_connection.log"
MAX_AUTH_ERRORS = 5

UMBRAL_COLA_CORREOS = 1  # Ajustar esto según sea necesario






# Paths para archivos en partición encriptada
hashes_guardados_path = '/home/cecilia/carpeta_montaje/hashes_guardados.json'
procesos_permitidos_path = '/home/cecilia/carpeta_montaje/procesos_permitidos.json'
blacklist_emails_path = '/home/cecilia/carpeta_montaje/blacklist_emails.json'


with open('/home/cecilia/carpeta_montaje/config.json', 'r') as f:
    config = json.load(f)

EMAIL_FROM = config["EMAIL_FROM"]
EMAIL_PASSWORD = config["EMAIL_PASSWORD"]
ADMIN_EMAIL = config["ADMIN_EMAIL"]
SMTP_SERVER = config["SMTP_SERVER"]
SMTP_PORT = config["SMTP_PORT"]

class User(UserMixin):
    def __init__(self, id):
        self.id = id
users = config["users"]



@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username]['password'] == password:
            user = User(username)
            login_user(user)
            return redirect(url_for('main.inicio'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))

def enviar_correo(asunto, mensaje):
    msg = MIMEText(mensaje)
    msg['Subject'] = asunto
    msg['From'] = EMAIL_FROM
    msg['To'] = ADMIN_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_FROM, EMAIL_PASSWORD)
            server.sendmail(EMAIL_FROM, ADMIN_EMAIL, msg.as_string())
    except Exception as e:
        print(f"Error al enviar correo: {e}")

def log_alarma(tipo_alarma, ip_origen, mensaje):
    timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
    log_message = f"{timestamp} :: {tipo_alarma} :: {ip_origen} :: {mensaje}"
    try:
        with open("/var/log/hips/alarmas.log", 'a') as f:
            f.write(log_message + "\n")
        enviar_correo(f"Alarma: {tipo_alarma}", log_message)
    except Exception as e:
        print(f"Error al escribir en el log de alarmas: {e}")

def log_prevencion(tipo_prevencion, ip_origen, mensaje):
    timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
    log_message = f"{timestamp} :: {tipo_prevencion} :: {ip_origen} :: {mensaje}"
    try:
        with open("/var/log/hips/prevencion.log", 'a') as f:
            f.write(log_message + "\n")
        enviar_correo(f"Prevención: {tipo_prevencion}", log_message)
    except Exception as e:
        print(f"Error al escribir en el log de prevención: {e}")

def leer_hashes_guardados():
    try:
        with open(hashes_guardados_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error al leer hashes guardados: {e}")
        return {}

def guardar_hashes_guardados(hashes):
    try:
        with open(hashes_guardados_path, 'w') as f:
            json.dump(hashes, f)
    except Exception as e:
        print(f"Error al guardar hashes: {e}")

def obtener_contenido(archivo):
    try:
        with open(archivo, 'r') as f:
            return f.read()
    except Exception as e:
        return None

def obtener_usuarios_conectados():
    resultado = subprocess.run(['who', '-u'], stdout=subprocess.PIPE)
    usuarios = resultado.stdout.decode('utf-8').strip().split('\n')
    usuarios_conectados = []
    
    for usuario in usuarios:
        partes = usuario.split()
        if len(partes) >= 6:
            usuario_info = {
                'nombre_usuario': partes[0],
                'tipo_conexion': partes[1],
                'host': partes[2],
                'hora_inicio': partes[3] + ' ' + partes[4],
                'estado': partes[5]
            }
            if len(partes) > 6:
                usuario_info['ip'] = partes[5]
            else:
                usuario_info['ip'] = 'localhost'
            usuarios_conectados.append(usuario_info)
    
    return usuarios_conectados

def leer_procesos_permitidos():
    try:
        with open(procesos_permitidos_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error al leer procesos permitidos: {e}")
        return []

def obtener_procesos_consumo():
    resultado = subprocess.run(['ps', 'aux', '--sort=-%mem'], stdout=subprocess.PIPE)
    procesos = resultado.stdout.decode('utf-8').strip().split('\n')
    encabezado = procesos[0]
    procesos = procesos[1:]
    return encabezado, procesos[:10]  # Devuelve los 10 primeros procesos

def matar_proceso(pid):
    try:
        subprocess.run(['kill', '-9', pid], check=True)
        return f"Proceso {pid} terminado."
    except subprocess.CalledProcessError as e:
        return f"Error al terminar el proceso {pid}: {e}"

def es_nombre_sospechoso(nombre):
    # Define aquí los patrones de nombres sospechosos
    nombres_sospechosos = ['hack', 'exploit', 'malware', 'virus', '.sh']
    return any(sospechoso in nombre for sospechoso in nombres_sospechosos)

def es_contenido_sospechoso(contenido):
    # Define aquí patrones de contenido sospechoso
    patrones_sospechosos = ['#!/bin/bash', 'eval', 'base64']
    return any(patron in contenido for patron in patrones_sospechosos)

def verificar_tmp():
    mensajes = []
    archivos_sospechosos = []
    cambios = False
    
    for root, dirs, files in os.walk('/tmp'):
        for nombre in files:
            ruta_completa = os.path.join(root, nombre)
            try:
                with open(ruta_completa, 'r') as archivo:
                    contenido = archivo.read()
                if es_nombre_sospechoso(nombre) or es_contenido_sospechoso(contenido):
                    archivos_sospechosos.append(ruta_completa)
            except (OSError, IOError) as e:
                pass

    if archivos_sospechosos:
        if not os.path.exists(CUARENTENA_DIR):
            os.makedirs(CUARENTENA_DIR, exist_ok=True)
            os.chmod(CUARENTENA_DIR, 0o700)

        for archivo in archivos_sospechosos:
            destino = os.path.join(CUARENTENA_DIR, os.path.basename(archivo))
            if os.path.exists(destino):
                log_prevencion("Archivo Sospechoso", "localhost", f'Archivo {archivo} ya está en cuarentena.')
            else:
                try:
                    shutil.move(archivo, CUARENTENA_DIR)
                    mensaje = f'Archivo sospechoso movido a cuarentena: {archivo}'
                    mensajes.append(mensaje)
                    log_prevencion("Archivo Sospechoso", "localhost", mensaje)
                    cambios = True
                except Exception as e:
                    mensaje = f'Error al mover {archivo} a cuarentena: {e}'
                    mensajes.append(mensaje)
                    log_alarma("Error al Mover a Cuarentena", "localhost", mensaje)

    if cambios:
        log_alarma("Modificación en /tmp", "localhost", "Se detectaron y movieron archivos sospechosos en /tmp.")
    else:
        mensajes.append("No se encontraron archivos sospechosos en /tmp.")

    return mensajes

def bloquear_ip(ip):
    try:
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
        mensaje = f"La IP {ip} fue bloqueada."
        log_prevencion("Bloqueo de IP", ip, mensaje)
        enviar_correo("Bloqueo de IP", mensaje)
        return True
    except subprocess.CalledProcessError as e:
       print(f"Error al bloquear la IP {ip}: {e}")
       return False
def bloquear_usuario(usuario):
    try:
        subprocess.run(['sudo', 'usermod', '-L', usuario], check=True)  # Bloquea al usuario
        print(f"Usuario {usuario} bloqueado.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error al bloquear al usuario {usuario}: {e}")
        return False

def analizar_access_log():
    ip_errors = {}
    mensajes_terminal = []
    mensajes_web = []

    if not os.path.exists(ACCESS_LOG_FILE):
        mensajes_web.append(f'Error: No se encontró el archivo de log en {ACCESS_LOG_FILE}.')
        return mensajes_web, mensajes_terminal

    with open(ACCESS_LOG_FILE, 'r') as f:
        for line in f:
            if ' 404 ' in line:
                ip = line.split()[0]
                if ip not in ip_errors:
                    ip_errors[ip] = 0
                ip_errors[ip] += 1

    for ip, errors in ip_errors.items():
        timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
        mensaje_web = f'{timestamp} :: En el archivo access_log se encontró que la dirección IP {ip} tuvo {errors} intentos fallidos al intentar conectarse al servidor web.'
        mensajes_web.append(mensaje_web)
        log_alarma("Intentos Fallidos", ip, mensaje_web)

        if errors > MAX_ERRORS:
            if bloquear_ip(ip):
                mensaje_terminal = f'{timestamp} :: IP {ip} bloqueada con {errors} errores.'
                mensajes_terminal.append(mensaje_terminal)
                log_prevencion("Bloqueo de IP", ip, mensaje_terminal)
            else:
                mensajes_terminal.append(f'Error al intentar bloquear la IP {ip} con {errors} errores.')

    return mensajes_web, mensajes_terminal

def leer_blacklist_emails():
    try:
        with open(blacklist_emails_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error al leer la lista negra de correos: {e}")
        return []

def guardar_blacklist_emails(blacklist):
    try:
        with open(blacklist_emails_path, 'w') as f:
            json.dump(blacklist, f)
    except Exception as e:
        print(f"Error al guardar la lista negra de correos: {e}")

def analizar_maillog():
    email_count = {}
    mensajes_terminal = []
    mensajes_web = []

    if not os.path.exists(MAIL_LOG_FILE):
        mensajes_web.append(f'Error: No se encontró el archivo de log en {MAIL_LOG_FILE}.')
        return mensajes_web, mensajes_terminal

    with open(MAIL_LOG_FILE, 'r') as f:
        for line in f:
            if 'from=' in line:
                start = line.find('from=') + 5
                end = line.find(' ', start)
                email = line[start:end]
                if email not in email_count:
                    email_count[email] = 0
                email_count[email] += 1

    blacklist = leer_blacklist_emails()

    for email, count in email_count.items():
        timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
        mensajes_web.append(f'{timestamp} :: En el archivo maillog se encontró que la dirección de correo {email} envió {count} correos.')
        log_alarma("Envio de Correos", email, f'{timestamp} :: En el archivo maillog se encontró que la dirección de correo {email} envió {count} correos.')

        # Bloquear cualquier dirección de correo que esté en la lista negra
        if email in blacklist:
            mensajes_terminal.append(f'{timestamp} :: Dirección de correo {email} ya está bloqueada.')
            log_prevencion("Correo en lista negra", email, f'{timestamp} :: Dirección de correo {email} ya está bloqueada.')
            enviar_correo("Correo en lista negra", f'{timestamp} :: Dirección de correo {email} ya está bloqueada.')

        # Bloquear cualquier dirección de correo que exceda el umbral de envíos
        elif count > MAX_EMAILS and email not in blacklist:
            blacklist.append(email)
            guardar_blacklist_emails(blacklist)
            mensajes_terminal.append(f'{timestamp} :: Dirección de correo {email} bloqueada con {count} correos enviados.')
            log_prevencion("Bloqueo de Correo", email, f'{timestamp} :: Dirección de correo {email} bloqueada con {count} correos enviados.')
            enviar_correo("Bloqueo de Correo", f'{timestamp} :: Dirección de correo {email} bloqueada con {count} correos enviados.')
        else:
            mensajes_terminal.append(f'{timestamp} :: Dirección de correo {email} envió {count} correos.')

    return mensajes_web, mensajes_terminal


def cambiar_contrasena(usuario):
    nueva_contrasena = generar_contrasena_aleatoria()
    try:
        subprocess.run(['sudo', 'chpasswd'], input=f'{usuario}:{nueva_contrasena}', text=True, check=True)
        return nueva_contrasena
    except subprocess.CalledProcessError as e:
        print(f"Error al cambiar la contraseña del usuario {usuario}: {e}")
        return None

def generar_contrasena_aleatoria():
    longitud = 12
    caracteres = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(caracteres) for i in range(longitud))

def analizar_errores_autenticacion():
    auth_errors = defaultdict(int)
    mensajes_terminal = []
    mensajes_web = []

    if not os.path.exists(SECURE_LOG_FILE):
        mensajes_web.append(f'Error: No se encontró el archivo de log en {SECURE_LOG_FILE}.')
        print(f'Error: No se encontró el archivo de log en {SECURE_LOG_FILE}.')
        return mensajes_web, mensajes_terminal

    print(f'Leyendo archivo de log: {SECURE_LOG_FILE}')
    with open(SECURE_LOG_FILE, 'r') as f:
        for line in f:
            print(f'Procesando línea: {line.strip()}')
            if 'authentication failure' in line:
                user_match = re.search(r'user=([^\s]+)', line)
                if user_match:
                    user = user_match.group(1).strip('[]')
                    if user:
                        auth_errors[user] += 1
                        print(f'Encontrado error de autenticación para el usuario {user}. Total: {auth_errors[user]}')

    for user, errors in auth_errors.items():
        if errors > MAX_AUTH_ERRORS:
            timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
            mensajes_web.append(f'{timestamp} :: En los archivos de log se encontró que el usuario {user} tuvo {errors} errores de autenticación.')
            print(f'{timestamp} :: Usuario {user} tuvo {errors} errores de autenticación.')
            log_alarma("Errores de Autenticación", user, f'{timestamp} :: Usuario {user} tuvo {errors} errores de autenticación.')

            nueva_contrasena = cambiar_contrasena(user)
            if nueva_contrasena:
                mensaje_terminal = f'{timestamp} :: Se encontraron {errors} errores de autenticación del usuario {user}. Contraseña cambiada a {nueva_contrasena}.'
                mensajes_terminal.append(mensaje_terminal)
                log_prevencion("Cambio de Contraseña", user, mensaje_terminal)
                enviar_correo("Cambio de Contraseña", mensaje_terminal)
            else:
                mensaje_terminal = f'{timestamp} :: Error al cambiar la contraseña del usuario {user}.'
                mensajes_terminal.append(mensaje_terminal)

    return mensajes_web, mensajes_terminal

def analizar_tcpdump():
    ip_conexiones = defaultdict(int)
    mensajes_web = []
    mensajes_terminal = []

    if not os.path.exists(TCPDUMP_LOG_FILE):
        mensajes_web.append(f'Error: No se encontró el archivo de log en {TCPDUMP_LOG_FILE}.')
        return mensajes_web, mensajes_terminal

    with open(TCPDUMP_LOG_FILE, 'r') as f:
        for line in f:
            match = re.search(r'(\d+\.\d+\.\d+\.\d+) > (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip_origen = match.group(1)
                ip_destino = match.group(2)
                ip_conexiones[(ip_origen, ip_destino)] += 1

    for (ip_origen, ip_destino), conexiones in ip_conexiones.items():
        timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
        if conexiones > UMBRAL_DDOS:
            bloquear_ip(ip_origen)
            mensaje_prevencion = (f'{timestamp} :: La IP {ip_origen} intentó conectarse a {ip_destino} {conexiones} veces. '
                                  f'Probable ataque DDoS. Se bloqueará la IP {ip_origen}.')
            mensajes_web.append(mensaje_prevencion)
            mensajes_terminal.append(f'{timestamp} :: IP {ip_origen} bloqueada con {conexiones} intentos de conexión a {ip_destino}.')
            log_prevencion("Prevención de ataque DDoS", ip_origen, mensaje_prevencion)
            enviar_correo("Prevención de ataque DDoS", mensaje_prevencion)
        else:
            mensaje_alarma = (f'{timestamp} :: No se encontraron ataques DDoS. La IP {ip_origen} intentó conectarse a {ip_destino} '
                              f'{conexiones} veces.')
            mensajes_web.append(mensaje_alarma)
            log_alarma("Actividad de conexión detectada", ip_origen, mensaje_alarma)
            enviar_correo("Actividad de conexión detectada", mensaje_alarma)

    return mensajes_web, mensajes_terminal

def analizar_archivos_cron():
    usuario = "cecilia"
    cron_path = f"/var/spool/cron/crontabs/{usuario}"
    cron_jobs = defaultdict(int)
    mensajes_web = []
    mensajes_terminal = []

    if os.path.exists(cron_path):
        with open(cron_path, 'r') as f:
            for line in f:
                if not line.startswith("#") and line.strip():
                    script_path = re.search(r'(\S+\s+){5}(\S+)', line)
                    if script_path:
                        script = script_path.group(2)
                        cron_jobs[script] += 1

        for script, frecuencia in cron_jobs.items():
            timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
            mensaje = (f'{timestamp} :: {usuario}, se encontró un archivo cron que ejecuta {script} '
                       f'con una frecuencia de {frecuencia} veces para el usuario {usuario}.')
            mensajes_web.append(mensaje)
            mensajes_terminal.append(mensaje)
            log_alarma("Archivo Cron Detectado", usuario, mensaje)
            enviar_correo("Detección de Archivo Cron", mensaje)
    else:
        timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
        mensajes_web.append(f'{timestamp} :: Error: No se encontró el archivo cron para el usuario {usuario}.')

    return mensajes_web, mensajes_terminal

def verificar_accesos_no_validos():
    ip_errores = defaultdict(int)
    mensajes_terminal = []
    mensajes_web = []

    if not os.path.exists(REMOTE_LOG_FILE):
        mensajes_web.append(f'Error: No se encontró el archivo de log en {REMOTE_LOG_FILE}.')
        return mensajes_web, mensajes_terminal

    with open(REMOTE_LOG_FILE, 'r') as f:
        for line in f:
            if 'Failed password' in line:
                match = re.search(r'Failed password for invalid user \S+ from (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip = match.group(1)
                    ip_errores[ip] += 1

    for ip, errores in ip_errores.items():
        timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
        mensaje_web = f'{timestamp} :: Se encontraron {errores} intentos de acceso desde la dirección IP {ip}.'
        mensajes_web.append(mensaje_web)
        log_alarma("Intentos de Acceso Fallidos", ip, mensaje_web)

        if errores > MAX_AUTH_ERRORS:
            if bloquear_ip(ip):
                mensaje_terminal = f'{timestamp} :: IP {ip} bloqueada con {errores} intentos de acceso fallidos.'
                mensajes_terminal.append(mensaje_terminal)
                log_prevencion("Bloqueo de IP", ip, mensaje_terminal)
            else:
                mensajes_terminal.append(f'Error al intentar bloquear la IP {ip} con {errores} errores.')

    return mensajes_web, mensajes_terminal

def verificar_cola_correos():
    mensajes_web = []
    mensajes_terminal = []
    cola_correos = []

    try:
        # Ejecutar el comando mailq y capturar la salida
        resultado = subprocess.run(['mailq'], stdout=subprocess.PIPE, text=True)
        salida = resultado.stdout

        # Parsear la salida del comando mailq
        for linea in salida.splitlines():
            match = re.match(r'^([A-F0-9]{10})\*?\s+', linea)
            if match:
                queue_id = match.group(1)
                cola_correos.append(queue_id)

        total_correos = len(cola_correos)
        timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
        mensajes_web.append(f"{timestamp} :: Se encontraron {total_correos} correos en la cola.")

        if total_correos > UMBRAL_COLA_CORREOS:
            mensajes_terminal.append(f"{timestamp} :: Alerta: La cola de correos tiene {total_correos} correos, supera el umbral de {UMBRAL_COLA_CORREOS}.")
            log_alarma("Cola de Correos", "localhost", f"{timestamp} :: La cola de correos tiene {total_correos} correos, supera el umbral.")
            
            for queue_id in cola_correos:
                eliminar_correo_cola(queue_id)
                mensajes_terminal.append(f"{timestamp} :: Correo con Queue ID {queue_id} eliminado por generar correos masivos.")
                log_prevencion("Eliminación de Correo", "localhost", f"{timestamp} :: Correo con Queue ID {queue_id} eliminado por generar correos masivos.")
                enviar_correo("Prevención de Correo Masivo", f"{timestamp} :: Correo con Queue ID {queue_id} eliminado por generar correos masivos.")
        else:
            mensajes_terminal.append(f"{timestamp} :: La cola de correos tiene {total_correos} correos, no supera el umbral.")

    except Exception as e:
        mensajes_web.append(f"Error al verificar la cola de correos: {e}")
        print(f"Error al verificar la cola de correos: {e}")

    return mensajes_web, mensajes_terminal

def eliminar_correo_cola(queue_id):
    try:
        subprocess.run(['sudo', 'postsuper', '-d', queue_id], check=True)
        mensaje = f"Correo con Queue ID {queue_id} eliminado."
        log_prevencion("Eliminación de Correo", "localhost", mensaje)
        enviar_correo("Eliminación de Correo", mensaje)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error al eliminar el correo con Queue ID {queue_id}: {e}")
        return False

def ejecutar_comando(comando):
    try:
        resultado = subprocess.run(comando, shell=True, capture_output=True, text=True)
        return resultado.stdout.strip()
    except Exception as e:
        print(f"Error al ejecutar comando: {e}")
        return ""

def detener_proceso(pid):
    try:
        subprocess.run(f"sudo kill -9 {pid}", shell=True)
        return True
    except Exception as e:
        print(f"Error al detener el proceso {pid}: {e}")
        return False

def verificar_procesos_sniffer():
    sniffers = ['tcpdump', 'wireshark', 'tshark']
    mensajes_web = []
    mensajes_terminal = []
    procesos_detectados = []

    for sniffer in sniffers:
        pids = ejecutar_comando(f"pgrep {sniffer}").split('\n')
        if pids and pids[0]:
            for pid in pids:
                usuario = ejecutar_comando(f"ps -o user= -p {pid}").strip()
                timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
                if usuario != "root":
                    mensaje = f"{timestamp} :: Se detectó el proceso {sniffer} en ejecución con PID {pid}. Probable presencia de sniffer. Se intentará detener el proceso."
                    mensajes_web.append(mensaje)
                    mensajes_terminal.append(mensaje)
                    if detener_proceso(pid):
                        log_alarma("Proceso sniffer detectado", "localhost", mensaje)
                        log_prevencion("Proceso sniffer detenido", "localhost", f"{timestamp} :: Proceso {sniffer} con PID {pid} detenido.")
                        enviar_correo("Alarma: Posible sniffer", mensaje)
                    procesos_detectados.append(sniffer)
                else:
                    mensajes_web.append(f"{timestamp} :: Proceso {sniffer} con PID {pid} en ejecución por root. No se terminará.")
                    mensajes_terminal.append(f"{timestamp} :: Proceso {sniffer} con PID {pid} en ejecución por root. No se terminará.")
                    log_alarma("Proceso sniffer en ejecución por root", "localhost", f"{timestamp} :: Proceso {sniffer} con PID {pid} en ejecución por root. No se terminará.")
        else:
            timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
            mensajes_web.append(f"{timestamp} :: No se encontró ningún proceso '{sniffer}' en ejecución.")
            mensajes_terminal.append(f"{timestamp} :: No se encontró ningún proceso '{sniffer}' en ejecución.")

    if not procesos_detectados:
        timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
        log_alarma("Verificación de sniffers", "localhost", f"{timestamp} :: No se detectó ningún sniffer en ejecución.")
    
    return mensajes_web, mensajes_terminal

def verificar_modo_promiscuo():
    resultado = ejecutar_comando("ip link show | grep -i promisc")
    mensajes_web = []
    mensajes_terminal = []

    if resultado:
        timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
        mensaje = f"{timestamp} :: El sistema está en modo promiscuo. Resultado: {resultado}. Se procederá a desactivarlo."
        mensajes_web.append(mensaje)
        mensajes_terminal.append(mensaje)
        log_alarma("Modo promiscuo detectado", "localhost", mensaje)
        ejecutar_comando("sudo ip link set dev eth0 promisc off")
        mensajes_web.append("El modo promiscuo ha sido desactivado.")
        log_prevencion("Modo promiscuo desactivado", "localhost", "El modo promiscuo ha sido desactivado.")
        enviar_correo("Alarma: Modo promiscuo detectado", mensaje)
    else:
        timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
        mensajes_web.append(f"{timestamp} :: El sistema no está en modo promiscuo.")
        mensajes_terminal.append(f"{timestamp} :: El sistema no está en modo promiscuo.")
        log_alarma("Verificación de modo promiscuo", "localhost", f"{timestamp} :: El sistema no está en modo promiscuo.")
    
    return mensajes_web, mensajes_terminal

@main.route('/')
@login_required
def inicio():
    return render_template('index.html')

@main.route('/verificar_hashes')
@login_required
def verificar_hashes():
    hashes_guardados = leer_hashes_guardados()
    modificado = False
    mensajes = []
    Nombre = 'Verificar Directorios'
    
    for archivo, hash_guardado in hashes_guardados.items():
        contenido = obtener_contenido(archivo)
        timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
        if contenido:
            hash_actual = hashlib.md5(contenido.encode()).hexdigest()
            if hash_actual == hash_guardado:
                mensaje = f'{timestamp} :: No se modificó el archivo: {archivo}'
                mensajes.append(mensaje)
                log_alarma("Verificación de Hashes", "localhost", mensaje)
            else:
                mensaje = f'{timestamp} :: Se modificó el archivo: {archivo}'
                mensajes.append(mensaje)
                log_alarma("Verificación de Hashes", "localhost", mensaje)
                hashes_guardados[archivo] = hash_actual  # Actualiza el hash guardado
                modificado = True
        else:
            mensaje = f'{timestamp} :: Archivo no encontrado o sin permisos: {archivo}'
            mensajes.append(mensaje)
            log_alarma("Verificación de Hashes", "localhost", mensaje)
            modificado = True

    if not modificado:
        mensaje = f"{timestamp} :: No se modificó ningún archivo."
        mensajes.append(mensaje)
        log_alarma("Verificación de Hashes", "localhost", mensaje)
    else:
        guardar_hashes_guardados(hashes_guardados)  # Guarda los hashes actualizados

    return render_template('resultados.html', Nombre=Nombre, hashes=hashes_guardados, mensajes=mensajes)

@main.route('/settings_logs')
@login_required
def settings_logs():
    Nombre = 'Configuración Inicial'
    hashes_guardados = leer_hashes_guardados()
    return render_template('resultados.html', Nombre=Nombre, hashes=hashes_guardados, mensajes=[])

@main.route('/verificar_usuarios')
@login_required
def verificar_usuarios_route():
    usuarios_actuales = obtener_usuarios_conectados()
    mensajes = []

    for usuario in usuarios_actuales:
        timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
        mensaje = f"{timestamp} :: Usuario: {usuario['nombre_usuario']}, IP: {usuario['ip']}, Hora de inicio: {usuario['hora_inicio']}"
        mensajes.append(mensaje)
        log_alarma("Usuario Conectado", usuario['ip'], mensaje)

    enviar_correo("Usuarios Conectados", "\n".join(mensajes))
    
    return render_template('resultados.html', Nombre='Usuarios Conectados', mensajes=mensajes)

@main.route('/verificar_procesos')
@login_required
def verificar_procesos():
    encabezado, procesos = obtener_procesos_consumo()
    umbral_memoria = 1.0  # Ajustar este valor según sea necesario, por ejemplo, 10.0 para 10%
    mensajes = []
    procesos_permitidos = leer_procesos_permitidos()

    for proceso in procesos:
        campos = proceso.split()
        if len(campos) > 10:
            pid = campos[1]
            uso_memoria = float(campos[3])
            nombre_proceso = campos[10]
            timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
            mensaje = f'{timestamp} :: PID: {pid}, Nombre: {nombre_proceso}, Uso de memoria: {uso_memoria}%, Tiempo: {campos[9]}'
            if uso_memoria > umbral_memoria:
                if nombre_proceso not in procesos_permitidos:
                    resultado_matar = matar_proceso(pid)
                    mensaje += f' - {resultado_matar}'
                    log_prevencion("Consumo de Memoria", "localhost", mensaje)
                else:
                    mensaje += ' - Proceso permitido'
            mensajes.append(mensaje)
            log_alarma("Registro de Proceso", "localhost", mensaje)

    if not mensajes:
        timestamp = datetime.now().strftime("%d/%m/%Y :: %H:%M:%S")
        mensajes.append(f"{timestamp} :: No se encontraron procesos que consuman mucha memoria o procesos desconocidos.")

    return render_template('resultados.html', Nombre='Verificación de Procesos', mensajes=mensajes)

@main.route('/verificar_tmp')
@login_required
def verificar_tmp_route():
    mensajes = verificar_tmp()
    return render_template('resultados.html', Nombre='Verificación de /tmp', mensajes=mensajes)

@main.route('/verificar_logs')
@login_required
def verificar_logs_route():
    mensajes_web, mensajes_terminal = analizar_access_log()
    for mensaje in mensajes_terminal:
        print(mensaje)
    return render_template('resultados.html', Nombre='Verificación de Logs', mensajes=mensajes_web)

@main.route('/verificar_mails')
@login_required
def verificar_mails_route():
    mensajes_web, mensajes_terminal = analizar_maillog()
    for mensaje in mensajes_terminal:
        print(mensaje)
    return render_template('resultados.html', Nombre='Verificación de Correos', mensajes=mensajes_web)

@main.route('/verificar_autenticacion')
@login_required
def verificar_autenticacion_route():
    mensajes_web, mensajes_terminal = analizar_errores_autenticacion()
    for mensaje in mensajes_terminal:
        print(mensaje)
    return render_template('resultados.html', Nombre='Verificación de Errores de Autenticación', mensajes=mensajes_web)

@main.route('/verificar_ddos')
@login_required
def verificar_ddos_route():
    mensajes_web, mensajes_terminal = analizar_tcpdump()
    for mensaje in mensajes_terminal:
        print(mensaje)
    return render_template('resultados.html', Nombre='Verificación de Ataques DDoS', mensajes=mensajes_web)

@main.route('/verificar_cron')
@login_required
def verificar_cron_route():
    mensajes_web, mensajes_terminal = analizar_archivos_cron()
    for mensaje in mensajes_terminal:
        print(mensaje)
    return render_template('resultados.html', Nombre='Verificación de Archivos Cron', mensajes=mensajes_web)

@main.route('/verificar_accesos_no_validos')
@login_required
def verificar_accesos_no_validos_route():
    mensajes_web, mensajes_terminal = verificar_accesos_no_validos()
    for mensaje in mensajes_terminal:
        print(mensaje)
    return render_template('resultados.html', Nombre='Verificación de Accesos No Válidos', mensajes=mensajes_web)

@main.route('/verificar_cola_correos')
@login_required
def verificar_cola_correos_route():
    mensajes_web, mensajes_terminal = verificar_cola_correos()
    for mensaje in mensajes_terminal:
        print(mensaje)
    return render_template('resultados.html', Nombre='Verificación de Cola de Correos', mensajes=mensajes_web)

@main.route('/verificar_sniffers')
@login_required
def verificar_sniffers_route():
    mensajes_web_sniffers, mensajes_terminal_sniffers = verificar_procesos_sniffer()
    mensajes_web_promiscuo, mensajes_terminal_promiscuo = verificar_modo_promiscuo()
    mensajes_web = mensajes_web_sniffers + mensajes_web_promiscuo
    mensajes_terminal = mensajes_terminal_sniffers + mensajes_terminal_promiscuo

    for mensaje in mensajes_terminal:
        print(mensaje)

    return render_template('resultados.html', Nombre='Verificación de Sniffers y Modo Promiscuo', mensajes=mensajes_web)
