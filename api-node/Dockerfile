# Imagen liviana con Node.js — sin ClamAV por ahora (requiere más RAM que el plan free).
# Cuando quieras activar el escaneo de malware real, revisa Dockerfile.with-clamav
# (o pide que te lo regenere) y súbelo a un plan con más memoria.
FROM node:20-bookworm-slim

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev

COPY . .

EXPOSE 3000

CMD ["node", "server.js"]
