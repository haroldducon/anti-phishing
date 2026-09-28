# Imagen con Node.js + ClamAV (antivirus real) para el servicio anti-phishing
FROM node:20-bookworm-slim

# Instala ClamAV (motor de escaneo) y sus herramientas de actualización de firmas
RUN apt-get update && \
    apt-get install -y --no-install-recommends clamav clamav-freshclam ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instala dependencias de Node primero (aprovecha la caché de capas de Docker)
COPY package.json package-lock.json* ./
RUN npm install --omit=dev

# Copia el resto del código
COPY . .

# Script que actualiza las firmas de virus y luego arranca el servidor
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 3000

ENTRYPOINT ["/app/entrypoint.sh"]
