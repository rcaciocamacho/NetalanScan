import streamlit as st
from scapy.all import ARP, Ether, srp
import socket
import pandas as pd
import asyncio
import time, os
from datetime import datetime
import requests

# Inicializar el estado de la sesión
if 'devices' not in st.session_state:
    st.session_state.devices = set()
if 'alerts' not in st.session_state:
    st.session_state.alerts = []

# Configuración de Gotify
GOTIFY_URL = os.environ.get("GOTIFY_URL")
GOTIFY_TOKEN = os.environ.get("GOTIFY_TOKEN")

def send_gotify_notification(message):
    url = f"{GOTIFY_URL}/message"
    headers = {
        "X-Gotify-Key": GOTIFY_TOKEN
    }
    data = {
        "message": message,
        "title": "Nueva IP Detectada",
        "priority": 5
    }
    try:
        response = requests.post(url, json=data, headers=headers)
        response.raise_for_status()
        st.success("Notificación enviada a Gotify")
    except requests.RequestException as e:
        st.error(f"Error al enviar notificación a Gotify: {e}")

async def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = await asyncio.get_event_loop().run_in_executor(None, lambda: srp(packet, timeout=3, verbose=0)[0])

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

async def get_device_info(ip):
    try:
        hostname = await asyncio.get_event_loop().run_in_executor(None, socket.gethostbyaddr, ip)
        hostname = hostname[0]
    except socket.herror:
        hostname = "Desconocido"

    open_ports = []
    for port in [80, 443, 22, 21]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = await asyncio.get_event_loop().run_in_executor(None, sock.connect_ex, (ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass

    return hostname, open_ports

async def periodic_scan(ip_range):
    while True:
        devices = await scan_network(ip_range)
        current_devices = set(device['ip'] for device in devices)
        
        new_devices = current_devices - st.session_state.devices
        if new_devices:
            for ip in new_devices:
                alert_message = f"Nueva IP detectada: {ip} en {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                st.session_state.alerts.append(alert_message)
                send_gotify_notification(alert_message)
        
        st.session_state.devices = current_devices

        data = []
        for device in devices:
            ip = device['ip']
            mac = device['mac']
            hostname, open_ports = await get_device_info(ip)
            data.append({
                'IP': ip,
                'MAC': mac,
                'Hostname': hostname,
                'Puertos Abiertos': ', '.join(map(str, open_ports)) if open_ports else 'Ninguno'
            })
        
        st.session_state.data = data
        
        await asyncio.sleep(300)  # Esperar 5 minutos

def main():
    st.title("Escáner de Red LAN")

    ip_range = st.text_input("Introduce el rango de IP a escanear (ej. 192.168.1.0/24):")

    if 'scan_task' not in st.session_state:
        st.session_state.scan_task = None

    if st.button("Iniciar/Detener Escaneo"):
        if st.session_state.scan_task is None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            st.session_state.scan_task = loop.create_task(periodic_scan(ip_range))
            st.success("Escaneo iniciado.")
        else:
            st.session_state.scan_task.cancel()
            st.session_state.scan_task = None
            st.success("Escaneo detenido.")

    if st.session_state.scan_task is not None:
        st.write("Estado: Escaneando...")
    else:
        st.write("Estado: Detenido")

    # Mostrar alertas
    for alert in st.session_state.alerts:
        st.warning(alert)

    # Mostrar tabla de dispositivos
    if 'data' in st.session_state:
        df = pd.DataFrame(st.session_state.data)
        st.subheader("Resultados del Escaneo")
        st.dataframe(
            df.style.set_properties(**{'background-color': 'lightblue',
                                       'color': 'black',
                                       'border-color': 'white'})
                     .set_table_styles([{'selector': 'th',
                                         'props': [('background-color', 'darkblue'),
                                                   ('color', 'white')]}])
        )

if __name__ == "__main__":
    main()