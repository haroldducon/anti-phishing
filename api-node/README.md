# API Anti-Phishing

Servicio que recibe una URL y devuelve un veredicto: `seguro`, `sospechoso`, `peligroso` o `invalida`, junto con un puntaje de riesgo (0-100) y las razones de la decisión.

## Cómo funciona

Combina dos capas de detección:

1. **Listas** (`WHITELIST` / `BLACKLIST` en `phishingDetector.js`): dominios de confianza y dominios ya reportados como maliciosos.
2. **Reglas heurísticas**: IP en vez de dominio, uso de `@`, acortadores de enlaces, muchos subdominios, guiones excesivos, TLDs de riesgo (.xyz, .top, etc.), palabras clave sospechosas ("login", "verificar-cuenta", nombres de marcas + urgencia), ausencia de HTTPS, y similitud tipo *typosquatting* con dominios de confianza (distancia de Levenshtein).

Cada señal suma puntos de riesgo; el total decide el veredicto:
- `0–24` → seguro
- `25–59` → sospechoso
- `60–100` → peligroso

## Instalación y uso

```bash
npm install
npm start
```

Esto levanta el servicio en `http://localhost:3000`, con una interfaz de prueba en esa misma dirección.

## Uso del API

```bash
curl -X POST http://localhost:3000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypa1-secure-login.xyz/verificar-cuenta"}'
```

Respuesta:
```json
{
  "url": "http://paypa1-secure-login.xyz/verificar-cuenta",
  "domain": "paypa1-secure-login.xyz",
  "verdict": "peligroso",
  "score": 90,
  "reasons": [
    "El dominio contiene múltiples guiones, típico de dominios falsificados.",
    "Extensión de dominio (.xyz) frecuentemente usada en phishing.",
    "Contiene palabras clave sospechosas: login, secure, verificar-cuenta.",
    "No utiliza conexión segura HTTPS."
  ]
}
```

También existe `/api/analyze-batch` para analizar varias URLs a la vez (útil para revisar todos los enlaces de un correo de golpe).

## Validación de adjuntos (fotos, videos, documentos, etc.)

`POST /api/analyze-attachment` (multipart/form-data, campo `file`) analiza un archivo en dos capas:

1. **Validaciones estructurales** (`attachmentValidator.js`, instantáneas, sin dependencias externas):
   - Extensiones de alto riesgo (.exe, .scr, .js, .apk, etc.)
   - Truco de doble extensión (`foto.jpg.exe`)
   - Documentos de Office con macros (.docm, .xlsm, etc.)
   - Discrepancia entre la extensión declarada y el contenido real del archivo (verificado por "magic bytes", no por el nombre)
   - Tamaño anómalo

2. **Escaneo con ClamAV** (`malwareScanner.js`, motor antivirus real y gratuito):
   - Detecta virus, troyanos y otro malware conocido dentro del archivo, sin importar si el archivo "parece" una imagen legítima.
   - Requiere instalar ClamAV en el servidor (instrucciones dentro de `malwareScanner.js`). Si no está instalado, el sistema sigue funcionando solo con las validaciones estructurales y te avisa de que el escaneo de firmas no se realizó.

```bash
curl -X POST http://localhost:3000/api/analyze-attachment \
  -F "file=@/ruta/a/la/foto.jpg"
```

### Por qué dos capas y no solo una

Las validaciones estructurales detectan *trucos* (un ejecutable disfrazado de foto), pero no saben si un archivo genuinamente `.jpg` tiene un exploit incrustado o si un PDF legítimo contiene un virus conocido — eso solo lo detecta un motor con base de firmas actualizada como ClamAV. Usar ambas capas juntas cubre tanto los trucos de disfraz como el malware real.

## Cómo conectarlo a correo / WhatsApp

Este servicio no lee correos ni mensajes de WhatsApp por sí mismo — es el "cerebro" que decide si un enlace es peligroso. Para bloquear enlaces de verdad necesitas conectarlo a una fuente de mensajes, por ejemplo:

- **Correo**: un filtro/regla en Gmail (Apps Script) o Outlook (Power Automate) que extraiga los enlaces de cada correo entrante y llame a `/api/analyze`; si el veredicto es `peligroso`, mueve el correo a spam o lo marca.
- **WhatsApp**: la API oficial de WhatsApp Business (webhook) que reciba cada mensaje entrante, extraiga URLs y consulte este servicio antes de reenviarlo o notificar al usuario.

Puedo ayudarte a construir cualquiera de esas dos integraciones cuando quieras avanzar por ahí.

## Mejoras recomendadas antes de producción

- Reemplazar la lista negra estática por una fuente en vivo (Google Safe Browsing API, PhishTank, OpenPhish).
- Guardar un registro (log) de URLs analizadas para auditoría.
- Ajustar los pesos de puntaje según resultados reales (falsos positivos/negativos).
