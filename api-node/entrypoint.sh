#!/bin/sh
set -e

echo "Actualizando base de firmas de ClamAV (esto puede tardar uno o dos minutos la primera vez)..."
# --quiet evita ruido en logs; si falla (ej. sin red temporalmente) no detiene el arranque,
# clamscan igual intentará usar la base de datos que ya tenga disponible.
freshclam --quiet || echo "Aviso: no se pudo actualizar freshclam ahora mismo, se continúa con la base actual."

echo "Iniciando servidor Node.js..."
exec node server.js
