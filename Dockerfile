# Usa una imagen base de Python
FROM python:3.9-slim

# Establece el directorio de trabajo en el contenedor
WORKDIR /app

# Instala las dependencias del sistema necesarias para Scapy
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copia los archivos de requerimientos
COPY requirements.txt .

RUN pip install --upgrade pip

# Instala las dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copia el resto del código fuente de la aplicación
COPY . .

# Expone el puerto en el que Streamlit se ejecutará
EXPOSE 8511

# Comando para ejecutar la aplicación
CMD ["streamlit", "run", "network_scanner.py", "--server.address=0.0.0.0"]