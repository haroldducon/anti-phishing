"""
Analizador Anti-Phishing — app de Streamlit
Puerto en Python de la lógica de detección de enlaces y adjuntos sospechosos,
listo para desplegar en Streamlit Community Cloud y que cualquiera lo pruebe.
"""

import re
from urllib.parse import urlparse
import streamlit as st

# --------------------------------------------------------------------------
# --- Detección de URLs sospechosas -----------------------------------------
# --------------------------------------------------------------------------

WHITELIST = {
    "google.com", "youtube.com", "wikipedia.org", "microsoft.com",
    "apple.com", "amazon.com", "whatsapp.com", "gmail.com",
}

BLACKLIST = set()  # dominios reportados como maliciosos (agrega los tuyos)

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "banco", "paypal", "netflix", "whatsapp", "suspendida", "bloqueada",
    "premio", "ganador", "urgente", "click-aqui", "verificar-cuenta",
]

RISKY_TLDS = {"xyz", "top", "club", "work", "click", "loan", "gq", "tk", "ml", "cf", "ga"}


def get_registrable_domain(hostname: str) -> str:
    parts = hostname.split(".")
    return hostname if len(parts) <= 2 else ".".join(parts[-2:])


def is_ip_address(hostname: str) -> bool:
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname)) or ":" in hostname


def levenshtein(a: str, b: str) -> int:
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        dp[i][0] = i
    for j in range(len(b) + 1):
        dp[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)
    return dp[len(a)][len(b)]


def closest_whitelist_match(domain: str):
    best, best_dist = None, float("inf")
    for known in WHITELIST:
        dist = levenshtein(domain, known)
        if dist < best_dist:
            best, best_dist = known, dist
    return best, best_dist


def analyze_url(raw_url: str) -> dict:
    reasons = []
    score = 0

    candidate = raw_url if re.match(r"^https?://", raw_url, re.I) else f"http://{raw_url}"
    try:
        parsed = urlparse(candidate)
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise ValueError("sin host")
    except Exception:
        return {"url": raw_url, "verdict": "invalida", "score": 0,
                 "reasons": ["No se pudo interpretar la URL proporcionada."]}

    domain = get_registrable_domain(hostname)
    tld = domain.split(".")[-1]

    if domain in WHITELIST:
        return {"url": raw_url, "verdict": "seguro", "score": 0,
                 "reasons": ["Dominio en lista blanca de confianza."]}

    if domain in BLACKLIST:
        return {"url": raw_url, "verdict": "peligroso", "score": 100,
                 "reasons": ["Dominio reportado como malicioso (lista negra)."]}

    if is_ip_address(hostname):
        score += 35
        reasons.append("La URL usa una dirección IP en lugar de un nombre de dominio.")

    if domain in URL_SHORTENERS:
        score += 20
        reasons.append("Usa un acortador de enlaces que oculta el destino real.")

    if "@" in raw_url:
        score += 30
        reasons.append("Contiene el símbolo '@', usado para enmascarar el dominio real.")

    subdomain_count = hostname.count(".") - 1
    if subdomain_count >= 3:
        score += 15
        reasons.append(f"Tiene {subdomain_count} subdominios, un patrón común de ofuscación.")

    hyphen_count = domain.count("-")
    if hyphen_count >= 2:
        score += 10
        reasons.append("El dominio contiene múltiples guiones, típico de dominios falsificados.")

    if tld in RISKY_TLDS:
        score += 15
        reasons.append(f"Extensión de dominio (.{tld}) frecuentemente usada en phishing.")

    lower_url = raw_url.lower()
    matched = [k for k in SUSPICIOUS_KEYWORDS if k in lower_url]
    if matched:
        score += min(25, len(matched) * 8)
        reasons.append(f"Contiene palabras clave sospechosas: {', '.join(matched)}.")

    if parsed.scheme != "https":
        score += 10
        reasons.append("No utiliza conexión segura HTTPS.")

    best, dist = closest_whitelist_match(domain)
    if best and 0 < dist <= 2:
        score += 30
        reasons.append(f'Se parece sospechosamente al dominio confiable "{best}" (posible typosquatting).')

    score = min(100, score)
    verdict = "peligroso" if score >= 60 else "sospechoso" if score >= 25 else "seguro"
    if not reasons:
        reasons.append("No se detectaron señales de riesgo conocidas.")

    return {"url": raw_url, "domain": domain, "verdict": verdict, "score": score, "reasons": reasons}


# --------------------------------------------------------------------------
# --- Validación de adjuntos --------------------------------------------------
# --------------------------------------------------------------------------

DANGEROUS_EXTENSIONS = {
    "exe", "bat", "cmd", "com", "scr", "pif", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "msi", "msp", "ps1", "jar", "apk", "app", "dmg", "sh",
    "hta", "reg", "lnk",
}
MACRO_CAPABLE_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xltm"}
EXPECTED_IMAGE_EXT = {"jpg", "jpeg", "png", "gif", "webp", "bmp", "heic"}
EXPECTED_VIDEO_EXT = {"mp4", "mov", "avi", "mkv", "webm", "3gp"}

MAGIC_SIGNATURES = [
    ("jpg", bytes([0xFF, 0xD8, 0xFF]), 0),
    ("png", bytes([0x89, 0x50, 0x4E, 0x47]), 0),
    ("gif", bytes([0x47, 0x49, 0x46, 0x38]), 0),
    ("webp", bytes([0x52, 0x49, 0x46, 0x46]), 0),
    ("pdf", bytes([0x25, 0x50, 0x44, 0x46]), 0),
    ("zip", bytes([0x50, 0x4B, 0x03, 0x04]), 0),
    ("exe", bytes([0x4D, 0x5A]), 0),
    ("elf", bytes([0x7F, 0x45, 0x4C, 0x46]), 0),
    ("mp4", bytes([0x66, 0x74, 0x79, 0x70]), 4),
    ("rar", bytes([0x52, 0x61, 0x72, 0x21]), 0),
]


def detect_real_type(data: bytes) -> str:
    for ext, sig, offset in MAGIC_SIGNATURES:
        if data[offset:offset + len(sig)] == sig:
            return ext
    return "desconocido"


def has_double_extension_trick(filename: str) -> bool:
    parts = filename.lower().split(".")
    if len(parts) < 3:
        return False
    final_ext, hidden_ext = parts[-1], parts[-2]
    looks_like_media = hidden_ext in EXPECTED_IMAGE_EXT or hidden_ext in EXPECTED_VIDEO_EXT or hidden_ext == "pdf"
    return looks_like_media and final_ext in DANGEROUS_EXTENSIONS


def analyze_attachment(filename: str, data: bytes, max_size_bytes: int = 25 * 1024 * 1024) -> dict:
    reasons = []
    score = 0

    declared_ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    real_type = detect_real_type(data)

    if declared_ext in DANGEROUS_EXTENSIONS:
        score += 70
        reasons.append(f"Extensión de archivo de alto riesgo (.{declared_ext}), típica de ejecutables/scripts.")

    if has_double_extension_trick(filename):
        score += 60
        reasons.append("El nombre del archivo usa doble extensión para disfrazar un ejecutable como imagen/video.")

    if declared_ext in MACRO_CAPABLE_EXTENSIONS:
        score += 35
        reasons.append("Es un documento de Office con macros habilitadas, un vector común de infección.")

    is_media_claim = declared_ext in EXPECTED_IMAGE_EXT or declared_ext in EXPECTED_VIDEO_EXT
    if is_media_claim and real_type in ("exe", "elf"):
        score += 90
        reasons.append(f"El archivo se presenta como {declared_ext.upper()} pero su contenido real es un ejecutable.")
    elif is_media_claim and real_type == "desconocido":
        score += 15
        reasons.append("No se pudo verificar que el contenido coincida con la extensión declarada.")

    if len(data) > max_size_bytes:
        score += 10
        reasons.append(f"El archivo supera el tamaño máximo permitido ({max_size_bytes // 1024 // 1024}MB).")
    if is_media_claim and len(data) < 100:
        score += 25
        reasons.append("El archivo es sospechosamente pequeño para tratarse de una foto/video real.")

    score = min(100, score)
    verdict = "peligroso" if score >= 60 else "sospechoso" if score >= 25 else "seguro"
    if not reasons:
        reasons.append("No se detectaron señales estructurales de riesgo.")

    return {
        "filename": filename, "declared_extension": declared_ext or None,
        "detected_type": real_type, "size_bytes": len(data),
        "verdict": verdict, "score": score, "reasons": reasons,
    }


# --------------------------------------------------------------------------
# --- Interfaz de Streamlit ---------------------------------------------------
# --------------------------------------------------------------------------

st.set_page_config(page_title="Analizador Anti-Phishing", page_icon="🔍")
st.title("🔍 Analizador Anti-Phishing")
st.caption("Verifica enlaces y adjuntos sospechosos recibidos por correo, WhatsApp, etc.")

COLORS = {"seguro": "success", "sospechoso": "warning", "peligroso": "error", "invalida": "info"}


def show_result(result: dict):
    kind = COLORS.get(result["verdict"], "info")
    getattr(st, kind)(f"**Veredicto: {result['verdict'].upper()}**  (riesgo: {result['score']}/100)")
    for reason in result["reasons"]:
        st.write(f"- {reason}")


tab1, tab2 = st.tabs(["🔗 Analizar enlace", "📎 Analizar adjunto"])

with tab1:
    url_input = st.text_input("Pega la URL a verificar", placeholder="https://ejemplo.com")
    if st.button("Analizar enlace") and url_input.strip():
        show_result(analyze_url(url_input.strip()))

with tab2:
    uploaded = st.file_uploader("Sube una foto, video u otro archivo")
    if uploaded is not None and st.button("Analizar adjunto"):
        show_result(analyze_attachment(uploaded.name, uploaded.getvalue()))
    st.caption(
        "Nota: esta versión web hace validaciones estructurales (extensión real vs. declarada, "
        "macros, doble extensión, etc.). El escaneo con motor antivirus (ClamAV) contra firmas de "
        "malware conocidas está disponible en la versión del servicio con API (Node.js)."
    )
