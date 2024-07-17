import streamlit as st
from scapy.all import ARP, Ether, srp
import socket, os
import pandas as pd
import asyncio
from datetime import datetime
import requests
import ipaddress
import aioping

# Inicializar el estado de la sesión
if 'devices' not in st.session_state:
    st.session_state.devices = set()
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'progress' not in st.session_state:
    st.session_state.progress = 0
if 'ip_count' not in st.session_state:
    st.session_state.ip_count = 0
if 'data' not in st.session_state:
    st.session_state.data = []
if 'scan_task' not in st.session_state:
    st.session_state.scan_task = None

# Configuración de Gotify
GOTIFY_URL = os.environ.get("GOTIFY_URL")
GOTIFY_TOKEN = os.environ.get("GOTIFY_TOKEN")

def send_gotify_notification(title, message):
    if GOTIFY_URL and GOTIFY_TOKEN:
        url = f"{GOTIFY_URL}/message"
        headers = {"X-Gotify-Key": GOTIFY_TOKEN}
        data = {
            "message": message,
            "title": title,
            "priority": 5
        }
        try:
            response = requests.post(url, json=data, headers=headers)
            response.raise_for_status()
            st.success("Notificación enviada a Gotify")
        except requests.RequestException as e:
            st.error(f"Error al enviar notificación a Gotify: {e}")
    else:
        st.warning("Gotify no está configurado. Omitiendo notificación.")

def get_local_ip_range():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    ip_network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return str(ip_network)

async def ping_ip(ip, total_ips):
    try:
        await aioping.ping(str(ip), timeout=0.5)
        st.session_state.ip_count += 1
        st.session_state.progress = st.session_state.ip_count / total_ips
        st.session_state.data.append({'IP': str(ip), 'MAC': 'Pendiente', 'Hostname': 'Pendiente', 'Puertos Abiertos': 'Pendiente'})
        return str(ip)
    except TimeoutError:
        return None

async def scan_network(ip_range):
    ip_network = ipaddress.ip_network(ip_range)
    total_ips = ip_network.num_addresses - 2  # Excluir la dirección de red y broadcast

    st.session_state.progress = 0
    st.session_state.ip_count = 0
    st.session_state.data = []

    tasks = [ping_ip(ip, total_ips) for ip in ip_network.hosts()]
    results = await asyncio.gather(*tasks)

    devices = [{'ip': ip} for ip in results if ip is not None]
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
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=0.5)
            open_ports.append(port)
            writer.close()
            await writer.wait_closed()
        except (asyncio.TimeoutError, ConnectionRefusedError):
            pass

    return hostname, open_ports

async def get_mac_address(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = await asyncio.get_event_loop().run_in_executor(None, lambda: srp(packet, timeout=1, verbose=0)[0])
    if result:
        return result[0][1].hwsrc
    return "Desconocido"

async def periodic_scan():
    ip_range = get_local_ip_range()
    while True:
        devices = await scan_network(ip_range)
        current_devices = set(device['ip'] for device in devices)
        
        new_devices = current_devices - st.session_state.devices
        if new_devices:
            for ip in new_devices:
                alert_message = f"Nueva IP detectada: {ip} en {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                st.session_state.alerts.append(alert_message)
                send_gotify_notification("Nueva IP Detectada", alert_message)
        
        st.session_state.devices = current_devices

        tasks = [asyncio.create_task(get_device_info(device['ip'])) for device in devices]
        mac_tasks = [asyncio.create_task(get_mac_address(device['ip'])) for device in devices]
        
        infos = await asyncio.gather(*tasks)
        macs = await asyncio.gather(*mac_tasks)

        data = []
        for device, (hostname, open_ports), mac in zip(devices, infos, macs):
            data.append({
                'IP': device['ip'],
                'MAC': mac,
                'Hostname': hostname,
                'Puertos Abiertos': ', '.join(map(str, open_ports)) if open_ports else 'Ninguno'
            })
        
        st.session_state.data = data
        
        await asyncio.sleep(300)  # Esperar 5 minutos

def main():
    st.title("NetalanScan - Escáner de Red LAN")

    ip_range = get_local_ip_range()
    st.write(f"Rango de IP local detectado: {ip_range}")

    if st.button("Iniciar/Detener Escaneo"):
        if st.session_state.scan_task is None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            st.session_state.scan_task = loop.create_task(periodic_scan())
            st.success("Escaneo iniciado.")
            send_gotify_notification("NetalanScan", f"Iniciando escaneo!! DateTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            st.session_state.scan_task.cancel()
            st.session_state.scan_task = None
            st.session_state.progress = 0
            st.session_state.ip_count = 0
            st.success("Escaneo detenido.")
            send_gotify_notification("NetalanScan", f"Escaneo finalizado!! DateTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if st.session_state.scan_task is not None:
        st.write("Estado: Escaneando...")
        # Mostrar progreso
        st.progress(st.session_state.progress)
        st.write(f"IPs encontradas: {st.session_state.ip_count}")
    else:
        st.write("Estado: Detenido")

    # Mostrar alertas
    for alert in st.session_state.alerts:
        st.warning(alert)

    # La tabla de dispositivos se actualizará automáticamente en la función ping_ip
    if st.session_state.data:
        st.write("Dispositivos detectados:")
        st.dataframe(pd.DataFrame(st.session_state.data))

if __name__ == "__main__":
    main()
