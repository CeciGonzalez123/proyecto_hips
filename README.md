# Sistema de Detección y Prevención de Intrusiones (HIPS)

Este proyecto implementa un sistema de detección y prevención de intrusiones (HIPS) utilizando Python y Flask. El sistema está diseñado para monitorear y proteger un servidor detectando actividades sospechosas y respondiendo de manera proactiva.

## Requisitos

- Python 3.11 o superior
- Flask
- Flask-Login
- smtplib
- subprocess
- json
- collections
- datetime
- email.mime.text
- random
- string
- re
- os
- shutil

## Instalación

1. Clonar el repositorio:

    ```bash
    git clone <URL_DEL_REPOSITORIO>
    cd proyecto_hips
    ```

2. Crear un entorno virtual y actívar:

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3. Instalar las dependencias necesarias:

    ```bash
    pip install Flask Flask-Login
    ```

4. Configurar el archivo `config.json` en el directorio de montaje:

    ```json
    {
        "EMAIL_FROM": "tu_correo@gmail.com",
        "EMAIL_PASSWORD": "tu_contraseña",
        "ADMIN_EMAIL": "correo_admin@gmail.com",
        "SMTP_SERVER": "smtp.gmail.com",
        "SMTP_PORT": 587,
        "users": {
            "cecilia": {
                "password": "1234"
            }
        }
    }
    ```

## Uso

1. Ejecutar la aplicación:

    ```bash
    sudo python app.py
    ```

2. Abrir el navegador e ir a `http://127.0.0.1:5000`.

3. Iniciar sesión con las credenciales configuradas en `config.json`.

## Funcionalidades

### Verificación de Hashes

- Verifica los hashes de los archivos configurados para detectar cambios no autorizados.

### Verificación de Usuarios

- Muestra los usuarios actualmente conectados al sistema.

### Verificación de Procesos

- Monitorea el uso de memoria de los procesos y finaliza aquellos que superan el umbral configurado.

### Verificación de /tmp

- Escanea el directorio `/tmp` en busca de archivos sospechosos y los mueve a cuarentena si es necesario.

### Verificación de Logs

- Analiza el archivo de logs de acceso (`access_log`) para detectar intentos fallidos y bloquea las IPs que superan el umbral configurado.

### Verificación de Correos

- Monitorea el archivo de logs de correos (`maillog`) para detectar envíos masivos y bloquea las direcciones de correo que superan el umbral configurado.

### Verificación de Errores de Autenticación

- Analiza los archivos de logs de autenticación (`secure`) para detectar múltiples errores de autenticación y bloquea al usuario si es necesario.

### Verificación de Ataques DDoS

- Monitorea el archivo de logs de `tcpdump` para detectar posibles ataques DDoS y bloquea las IPs sospechosas.

### Verificación de Archivos Cron

- Escanea los archivos cron del usuario para detectar y registrar las tareas configuradas.

### Verificación de Accesos No Válidos

- Analiza los archivos de logs de conexiones remotas para detectar intentos fallidos y bloquea las IPs que superan el umbral configurado.

### Verificación de Cola de Correos

- Monitorea la cola de correos y elimina aquellos correos que generen un envío masivo.

### Verificación de Sniffers y Modo Promiscuo

- Detecta y finaliza los procesos de sniffers no autorizados y desactiva el modo promiscuo si está habilitado.

## Configuración de sudo

Configurar sudo para que los comandos necesarios se puedan ejecutar sin necesidad de contraseña. Añadir las siguientes líneas en el archivo `/etc/sudoers`:

```plaintext
cecilia ALL=(ALL) NOPASSWD: /sbin/iptables, /usr/sbin/usermod, /usr/sbin/chpasswd, /usr/sbin/postsuper
