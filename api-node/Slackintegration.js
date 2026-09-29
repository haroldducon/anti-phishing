/**
 * slackIntegration.js
 * Recibe eventos de Slack (mensajes nuevos), analiza los enlaces y adjuntos
 * que contengan, y si algo es sospechoso/peligroso, responde en el hilo y
 * agrega una reacción al mensaje original.
 *
 * Requiere dos variables de entorno (se configuran en Render):
 *   SLACK_BOT_TOKEN      -> token que empieza con xoxb-...
 *   SLACK_SIGNING_SECRET -> para verificar que la petición viene de Slack de verdad
 */

const crypto = require("crypto");
const { analyzeUrl } = require("./phishingDetector");
const { analyzeAttachment } = require("./attachmentValidator");

const SLACK_BOT_TOKEN = process.env.SLACK_BOT_TOKEN;
const SLACK_SIGNING_SECRET = process.env.SLACK_SIGNING_SECRET;

// Evita procesar el mismo mensaje dos veces si Slack reintenta la entrega
const eventosYaVistos = new Set();

// ------------------------------------------------------------------
// Verificación de firma (seguridad: confirma que el request es de Slack)
// ------------------------------------------------------------------
function verificarFirmaSlack(req) {
  if (!SLACK_SIGNING_SECRET) return false;

  const timestamp = req.headers["x-slack-request-timestamp"];
  const firmaRecibida = req.headers["x-slack-signature"];
  if (!timestamp || !firmaRecibida) return false;

  // Evita ataques de "replay" (peticiones viejas reenviadas)
  const cincoMinutos = 60 * 5;
  if (Math.abs(Date.now() / 1000 - timestamp) > cincoMinutos) return false;

  const baseString = `v0:${timestamp}:${req.rawBody}`;
  const firmaCalculada =
    "v0=" + crypto.createHmac("sha256", SLACK_SIGNING_SECRET).update(baseString).digest("hex");

  return crypto.timingSafeEqual(Buffer.from(firmaCalculada), Buffer.from(firmaRecibida));
}

// ------------------------------------------------------------------
// Maneja el POST que llega a /slack/events
// ------------------------------------------------------------------
async function manejarEventoSlack(req, res) {
  // 1. Verificación inicial que pide Slack al configurar la URL por primera vez
  if (req.body.type === "url_verification") {
    return res.json({ challenge: req.body.challenge });
  }

  // 2. Verifica que el request sea realmente de Slack
  if (!verificarFirmaSlack(req)) {
    return res.status(401).send("Firma inválida");
  }

  // 3. Responde rápido a Slack (si no, reintenta la entrega) y procesa después
  res.status(200).send();

  const evento = req.body.event;
  if (!evento) return;

  // Evita procesar el mismo evento dos veces
  const idEvento = req.body.event_id;
  if (idEvento) {
    if (eventosYaVistos.has(idEvento)) return;
    eventosYaVistos.add(idEvento);
    // Limpieza simple para no crecer infinito en memoria
    if (eventosYaVistos.size > 1000) eventosYaVistos.clear();
  }

  // Ignora mensajes de bots (incluido el propio) para no entrar en loop
  if (evento.bot_id || evento.subtype === "bot_message") return;
  if (evento.type !== "message") return;

  try {
    await procesarMensaje(evento);
  } catch (error) {
    console.error("Error procesando mensaje de Slack:", error);
  }
}

// ------------------------------------------------------------------
// Analiza un mensaje: enlaces en el texto + archivos adjuntos
// ------------------------------------------------------------------
async function procesarMensaje(evento) {
  const hallazgos = [];

  // Enlaces: en Slack vienen envueltos en <https://ejemplo.com|texto> o <https://ejemplo.com>
  const regexEnlaces = /<(https?:\/\/[^|>]+)(\|[^>]+)?>/g;
  const texto = evento.text || "";
  let coincidencia;
  while ((coincidencia = regexEnlaces.exec(texto)) !== null) {
    const url = coincidencia[1];
    const resultado = analyzeUrl(url);
    if (resultado.verdict === "sospechoso" || resultado.verdict === "peligroso") {
      hallazgos.push(`🔗 *${url}*\n   → ${resultado.verdict.toUpperCase()} (${resultado.score}/100): ${resultado.reasons.join(" ")}`);
    }
  }

  // Adjuntos: hay que descargarlos usando el bot token (son privados)
  const archivos = evento.files || [];
  for (const archivo of archivos) {
    const buffer = await descargarArchivoSlack(archivo.url_private);
    if (!buffer) continue;
    const resultado = analyzeAttachment(archivo.name, buffer);
    if (resultado.verdict === "sospechoso" || resultado.verdict === "peligroso") {
      hallazgos.push(`📎 *${archivo.name}*\n   → ${resultado.verdict.toUpperCase()} (${resultado.score}/100): ${resultado.reasons.join(" ")}`);
    }
  }

  if (hallazgos.length === 0) return; // todo limpio, no hace falta avisar

  const peorEsPeligroso = hallazgos.some((h) => h.includes("PELIGROSO"));

  // Reacciona al mensaje original
  await llamarSlackApi("reactions.add", {
    channel: evento.channel,
    timestamp: evento.ts,
    name: peorEsPeligroso ? "rotating_light" : "warning",
  });

  // Responde en el hilo con el detalle
  await llamarSlackApi("chat.postMessage", {
    channel: evento.channel,
    thread_ts: evento.ts,
    text: `⚠️ Este mensaje tiene contenido potencialmente riesgoso:\n\n${hallazgos.join("\n\n")}`,
  });
}

// ------------------------------------------------------------------
// Descarga un archivo privado de Slack usando el bot token
// ------------------------------------------------------------------
async function descargarArchivoSlack(urlPrivada) {
  try {
    const respuesta = await fetch(urlPrivada, {
      headers: { Authorization: `Bearer ${SLACK_BOT_TOKEN}` },
    });
    const arrayBuffer = await respuesta.arrayBuffer();
    return Buffer.from(arrayBuffer);
  } catch (error) {
    console.error("Error descargando archivo de Slack:", error);
    return null;
  }
}

// ------------------------------------------------------------------
// Llama a cualquier método del API de Slack (chat.postMessage, reactions.add, etc.)
// ------------------------------------------------------------------
async function llamarSlackApi(metodo, payload) {
  try {
    const respuesta = await fetch(`https://slack.com/api/${metodo}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        Authorization: `Bearer ${SLACK_BOT_TOKEN}`,
      },
      body: JSON.stringify(payload),
    });
    const data = await respuesta.json();
    if (!data.ok) {
      console.error(`Error en Slack API (${metodo}):`, data.error);
    }
    return data;
  } catch (error) {
    console.error(`Error llamando a Slack API (${metodo}):`, error);
    return null;
  }
}

module.exports = { manejarEventoSlack };
