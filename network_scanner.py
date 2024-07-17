import streamlit as st
from scapy.all import ARP, Ether, srp
import socket, os
import pandas as pd
import asyncio
from datetime import datetime
import requests
import ipaddress
import aioping
import nest_asyncio
import csv
import uuid

nest_asyncio.apply()

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
if 'valid_ips' not in st.session_state:
    st.session_state.valid_ips = set()

# Configuración de Gotify
GOTIFY_URL = os.environ.get("GOTIFY_URL")
GOTIFY_TOKEN = os.environ.get("GOTIFY_TOKEN")

CSV_FILE = "valid_ips.csv"

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

def load_valid_ips():
    if os.path.exists(CSV_FILE):
        df = pd.read_csv(CSV_FILE)
        st.session_state.valid_ips = set(df['IP'].tolist())

def add_ip_to_csv(ip):
    with open(CSV_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([ip])

async def ping_ip(ip, total_ips):
    try:
        await aioping.ping(str(ip), timeout=0.5)
        if ip not in st.session_state.devices:
            unique_id = str(uuid.uuid4())
            st.session_state.devices.add(ip)
            st.session_state.data.append({
                'IP': str(ip),
                'MAC': 'Pendiente',
                'Hostname': 'Pendiente',
                'Puertos Abiertos': 'Pendiente',
                'unique_id': unique_id
            })
        st.session_state.ip_count += 1
        st.session_state.progress = st.session_state.ip_count / total_ips
        return str(ip)
    except TimeoutError:
        return None

async def scan_network(ip_range):
    ip_network = ipaddress.ip_network(ip_range)
    total_ips = ip_network.num_addresses - 2  # Excluir la dirección de red y broadcast

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
    while st.session_state.scan_task:
        devices = await scan_network(ip_range)
        current_devices = set(device['ip'] for device in devices)
        
        new_devices = current_devices - st.session_state.devices - st.session_state.valid_ips
        if new_devices:
            for ip in new_devices:
                alert_message = f"Nueva IP detectada: {ip} en {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                st.session_state.alerts.append(alert_message)
                send_gotify_notification("Nueva IP Detectada", alert_message)

        tasks = [asyncio.create_task(get_device_info(device['ip'])) for device in devices]
        mac_tasks = [asyncio.create_task(get_mac_address(device['ip'])) for device in devices]

        infos = await asyncio.gather(*tasks)
        macs = await asyncio.gather(*mac_tasks)

        for idx, (device, (hostname, open_ports), mac) in enumerate(zip(devices, infos, macs)):
            for data in st.session_state.data:
                if data['IP'] == device['ip']:
                    data['MAC'] = mac
                    data['Hostname'] = hostname
                    data['Puertos Abiertos'] = ', '.join(map(str, open_ports)) if open_ports else 'Ninguno'
        
        await asyncio.sleep(300)  # Esperar 5 minutos

def start_scan():
    load_valid_ips()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.create_task(periodic_scan())
    count_ip = 0 

    while st.session_state.scan_task:
        # Actualizar la interfaz cada segundo
        progress_bar.progress(st.session_state.progress)
        ip_count_placeholder.text(f"IPs encontradas: {st.session_state.ip_count}")
        ip_list_placeholder.empty()  # Clear the placeholder before updating
        with ip_list_placeholder:
            st.markdown("""
            <style>
            .flex-container {
                display: flex;
                flex-wrap: wrap;
            }
            .flex-item {
                border: 1px solid #ccc;
                border-radius: 10px;
                padding: 10px;
                margin: 10px;
                width: calc(50% - 40px); /* Two items per row */
                box-sizing: border-box;
            }
            .flex-item button {
                background-color: #4CAF50; /* Green */
                border: none;
                color: white;
                padding: 10px 20px;
                text-align: center;
                text-decoration: none;
                display: inline-block;
                font-size: 16px;
                margin: 4px 2px;
                cursor: pointer;
                border-radius: 5px;
            }
            </style>
            """, unsafe_allow_html=True)

            st.markdown('<div class="flex-container">', unsafe_allow_html=True)
            for idx, device in enumerate(st.session_state.data):
                ip = device['IP']
                count_ip += 1 
                unique_key = f"{device['unique_id']}_{count_ip}"
                st.markdown(f"""
                <div class="flex-item">
                    <h4>{ip}</h4>
                    <p><strong>MAC:</strong> {device['MAC']}</p>
                    <p><strong>Hostname:</strong> {device['Hostname']}</p>
                    <p><strong>Puertos Abiertos:</strong> {device['Puertos Abiertos']}</p>
                    """, unsafe_allow_html=True)
                if st.button("Validar IP", key=unique_key):
                    validate_ip(ip)
                st.markdown("</div>", unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
        loop.run_until_complete(asyncio.sleep(1))

def validate_ip(ip):
    add_ip_to_csv(ip)
    st.session_state.valid_ips.add(ip)
    st.session_state.alerts.append(f"IP validada y añadida al CSV: {ip}")

def main():
    st.title("NetalanScan - Escáner de Red LAN")

    ip_range = get_local_ip_range()
    st.write(f"Rango de IP local detectado: {ip_range}")

    global progress_bar, ip_count_placeholder, ip_list_placeholder
    progress_bar = st.progress(0)
    ip_count_placeholder = st.empty()
    ip_list_placeholder = st.empty()

    if st.button("Iniciar Escaneo"):
        if st.session_state.scan_task is None:
            st.session_state.scan_task = True
            start_scan()
            st.success("Escaneo iniciado.")
            send_gotify_notification("NetalanScan", f"Iniciando escaneo!! DateTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    if st.button("Detener Escaneo"):
        if st.session_state.scan_task:
            st.session_state.scan_task = None
            st.session_state.progress = 0
            st.session_state.ip_count = 0
            st.success("Escaneo detenido.")
            send_gotify_notification("NetalanScan", f"Escaneo finalizado!! DateTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if st.session_state.scan_task:
        st.write("Estado: Escaneando...")
    else:
        st.write("Estado: Detenido")

    # Mostrar alertas
    for alert in st.session_state.alerts:
        st.warning(alert)

if __name__ == "__main__":
    main()
