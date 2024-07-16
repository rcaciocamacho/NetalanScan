# Network Scanner LAN

## Descripción

Network Scanner LAN es una aplicación web basada en Streamlit que permite escanear redes LAN, detectar dispositivos activos y mostrar información detallada sobre cada uno. La aplicación realiza escaneos periódicos, muestra los resultados en una interfaz web intuitiva y envía notificaciones cuando se detectan nuevos dispositivos.

## Características

- Escaneo de red LAN basado en rangos de IP
- Detección de dispositivos activos
- Muestra información detallada: IP, MAC, hostname y puertos abiertos
- Escaneo periódico automático (cada 5 minutos)
- Interfaz web interactiva con Streamlit
- Notificaciones en tiempo real en la interfaz
- Integración con Gotify para notificaciones externas

## Requisitos

- Python 3.7+
- Docker (opcional, para la ejecución containerizada)

## Instalación

### Método 1: Instalación local

1. Clona este repositorio:
```
git clone https://github.com/tu-usuario/network-scanner-lan.git
cd network-scanner-lan
```

2. Instala las dependencias:
```
pip install -r requirements.txt
```

3. Configura las variables de entorno para Gotify (opcional):
```
export GOTIFY_URL="https://tu-servidor-gotify.com"
export GOTIFY_TOKEN="tu-token-de-gotify"
```

4. Ejecuta la aplicación:
```
streamlit run network_scanner.py
```

### Método 2: Usando Docker

1. Clona este repositorio:
```
git clone https://github.com/tu-usuario/network-scanner-lan.git
cd network-scanner-lan
```

2. Construye y ejecuta el contenedor Docker:
```
docker-compose up --build
```

## Uso

1. Abre tu navegador y ve a `http://localhost:8501`.
2. Introduce el rango de IP que deseas escanear (por ejemplo, 192.168.1.0/24).
3. Haz clic en "Iniciar Escaneo" para comenzar el escaneo periódico.
4. La tabla de resultados se actualizará automáticamente cada 5 minutos.
5. Las alertas de nuevos dispositivos aparecerán en la interfaz y se enviarán a Gotify (si está configurado).

## Configuración de Gotify

Para habilitar las notificaciones de Gotify:

1. Configura un servidor Gotify.
2. Obtén una URL y un token de aplicación de Gotify.
3. Configura las variables de entorno `GOTIFY_URL` y `GOTIFY_TOKEN`.

## Advertencias de Seguridad

- Este script realiza escaneos de red activos. Asegúrate de tener permiso para escanear la red objetivo.
- El uso de `network_mode: "host"` en Docker puede tener implicaciones de seguridad. Úsalo con precaución.

## Contribuciones

Las contribuciones son bienvenidas. Por favor, abre un issue para discutir cambios mayores antes de crear un pull request.

## Licencia

[MIT License](LICENSE)

## Contacto

Tu Nombre - tu.email@ejemplo.com

Link del proyecto: https://github.com/tu-usuario/network-scanner-lan