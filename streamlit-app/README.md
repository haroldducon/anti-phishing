# Analizador Anti-Phishing (Streamlit)

Versión en Python de la herramienta, lista para que la pruebe cualquiera desde el navegador.

## Probar en local

```bash
pip install -r requirements.txt
streamlit run streamlit_app.py
```

Esto abre la app en `http://localhost:8501`.

## Publicarla gratis (Streamlit Community Cloud)

1. Sube esta carpeta (`streamlit_app.py` + `requirements.txt`) a un repositorio de GitHub.
2. Entra a [share.streamlit.io](https://share.streamlit.io) con tu cuenta de GitHub.
3. Clic en "New app", elige el repositorio y selecciona `streamlit_app.py` como archivo principal.
4. En unos minutos te da un link público (`https://tuapp.streamlit.app`) que puedes compartir para que la prueben.

## Qué incluye esta versión

- Analizador de enlaces (mismas reglas que la API en Node: listas blanca/negra, IPs, acortadores, typosquatting, palabras clave, TLDs de riesgo, HTTPS).
- Analizador de adjuntos con validaciones estructurales (extensión real vs. declarada mediante "magic bytes", doble extensión, macros, tamaño).

## Qué NO incluye (por ahora)

El escaneo de malware con ClamAV (firmas reales de virus) requiere un servidor con ClamAV instalado, algo que Streamlit Community Cloud no permite. Esa parte queda en la versión Node.js con API (`/api/analyze-attachment`) que puedes correr en tu propio servidor. Si más adelante quieres, puedo ayudarte a conectar esta app de Streamlit con esa API en vez de duplicar la lógica.
