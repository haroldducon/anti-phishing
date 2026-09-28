/**
 * server.js
 * API REST para analizar URLs y adjuntos, y detectar posible phishing/malware.
 *
 * Endpoints:
 *   POST /api/analyze              { "url": "..." }            -> analiza una URL
 *   POST /api/analyze-batch        { "urls": ["...", "..."] }   -> analiza varias URLs
 *   POST /api/analyze-attachment   multipart/form-data, campo "file" -> analiza un adjunto
 *   GET  /api/health                                             -> estado del servicio
 *
 * Para usarlo desde correo/WhatsApp/etc.: cada vez que llegue un mensaje con
 * un enlace o un adjunto, tu bot/integración hace un POST al endpoint
 * correspondiente y decide si bloquear, avisar o dejar pasar según el
 * "verdict" recibido.
 */

const express = require("express");
const multer = require("multer");
const { analyzeUrl } = require("./phishingDetector");
const { analyzeAttachment } = require("./attachmentValidator");
const { scanBuffer } = require("./malwareScanner");

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

const app = express();
app.use(express.json());
app.use(express.static("public"));

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.post("/api/analyze", (req, res) => {
  const { url } = req.body || {};
  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "Debes enviar un campo 'url' (string)." });
  }
  const result = analyzeUrl(url.trim());
  res.json(result);
});

app.post("/api/analyze-batch", (req, res) => {
  const { urls } = req.body || {};
  if (!Array.isArray(urls) || urls.length === 0) {
    return res.status(400).json({ error: "Debes enviar un campo 'urls' (array de strings)." });
  }
  const results = urls.map((u) => analyzeUrl(String(u).trim()));
  res.json({ results });
});

app.post("/api/analyze-attachment", upload.single("file"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "Debes enviar un archivo en el campo 'file'." });
  }

  // 1. Validaciones estructurales propias (instantáneas)
  const structural = analyzeAttachment(req.file.originalname, req.file.buffer);

  // 2. Escaneo con ClamAV (firmas de malware reales)
  const scan = await scanBuffer(req.file.buffer, req.file.originalname);

  // Combina ambos resultados en un veredicto final
  let verdict = structural.verdict;
  let score = structural.score;
  const reasons = [...structural.reasons];

  if (scan.available && scan.infected) {
    verdict = "peligroso";
    score = 100;
    reasons.push(`ClamAV detectó malware conocido: ${scan.signature}.`);
  } else if (!scan.available) {
    reasons.push("Aviso: ClamAV no está disponible en este servidor; solo se aplicaron validaciones estructurales.");
  }

  res.json({
    filename: structural.filename,
    verdict,
    score,
    reasons,
    detail: { structural, malwareScan: scan },
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servicio anti-phishing escuchando en http://localhost:${PORT}`);
});
