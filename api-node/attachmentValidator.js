/**
 * attachmentValidator.js
 * Analiza archivos adjuntos (fotos, videos, documentos, etc.) buscando señales
 * de riesgo ANTES de pasarlos a un antivirus real (ver malwareScanner.js).
 *
 * Enfoque: un antivirus completo necesita bases de firmas que se actualizan
 * a diario (eso lo hace ClamAV en malwareScanner.js). Este módulo cubre lo
 * que sí podemos verificar nosotros mismos de forma confiable: que el
 * archivo sea realmente lo que dice ser, y patrones estructurales típicos
 * de archivos maliciosos.
 */

const path = require("path");

// Extensiones que casi nunca deberían llegar como "foto" o "video" adjunto
const DANGEROUS_EXTENSIONS = new Set([
  "exe", "bat", "cmd", "com", "scr", "pif", "vbs", "vbe", "js", "jse",
  "wsf", "wsh", "msi", "msp", "ps1", "jar", "apk", "app", "dmg", "sh",
  "hta", "reg", "lnk",
]);

// Extensiones "de documento/oficina" que pueden llevar macros maliciosas
const MACRO_CAPABLE_EXTENSIONS = new Set(["docm", "xlsm", "pptm", "dotm", "xltm"]);

// Extensiones esperadas para tipos de archivo comunes que el usuario mencionó
const EXPECTED_IMAGE_EXT = new Set(["jpg", "jpeg", "png", "gif", "webp", "bmp", "heic"]);
const EXPECTED_VIDEO_EXT = new Set(["mp4", "mov", "avi", "mkv", "webm", "3gp"]);

// "Magic bytes": primeros bytes de un archivo que identifican su tipo REAL,
// independientemente de cómo se llame o qué extensión tenga.
const MAGIC_SIGNATURES = [
  { ext: "jpg", bytes: [0xff, 0xd8, 0xff] },
  { ext: "png", bytes: [0x89, 0x50, 0x4e, 0x47] },
  { ext: "gif", bytes: [0x47, 0x49, 0x46, 0x38] },
  { ext: "webp", bytes: [0x52, 0x49, 0x46, 0x46] }, // + "WEBP" en offset 8
  { ext: "pdf", bytes: [0x25, 0x50, 0x44, 0x46] },
  { ext: "zip", bytes: [0x50, 0x4b, 0x03, 0x04] }, // también docx/xlsx/pptx/apk/jar
  { ext: "exe", bytes: [0x4d, 0x5a] }, // ejecutables Windows (MZ header)
  { ext: "elf", bytes: [0x7f, 0x45, 0x4c, 0x46] }, // ejecutables Linux
  { ext: "mp4", bytes: [0x66, 0x74, 0x79, 0x70], offset: 4 }, // "ftyp" en offset 4
  { ext: "rar", bytes: [0x52, 0x61, 0x72, 0x21] },
];

function detectRealType(buffer) {
  for (const sig of MAGIC_SIGNATURES) {
    const offset = sig.offset || 0;
    const slice = buffer.subarray(offset, offset + sig.bytes.length);
    if (slice.length === sig.bytes.length && sig.bytes.every((b, i) => slice[i] === b)) {
      return sig.ext;
    }
  }
  return "desconocido";
}

function getExtension(filename) {
  return path.extname(filename).replace(".", "").toLowerCase();
}

// Detecta patrones de doble extensión: "foto.jpg.exe", "video.mp4.scr"
function hasDoubleExtensionTrick(filename) {
  const parts = filename.toLowerCase().split(".");
  if (parts.length < 3) return false;
  const finalExt = parts[parts.length - 1];
  const hiddenExt = parts[parts.length - 2];
  const looksLikeMedia = EXPECTED_IMAGE_EXT.has(hiddenExt) || EXPECTED_VIDEO_EXT.has(hiddenExt) || hiddenExt === "pdf";
  return looksLikeMedia && DANGEROUS_EXTENSIONS.has(finalExt);
}

/**
 * Analiza un adjunto.
 * @param {string} filename - nombre original del archivo
 * @param {Buffer} buffer - contenido del archivo
 * @param {number} maxSizeBytes - tamaño máximo permitido (por defecto 25MB)
 */
function analyzeAttachment(filename, buffer, maxSizeBytes = 25 * 1024 * 1024) {
  const reasons = [];
  let score = 0;

  const declaredExt = getExtension(filename);
  const realType = detectRealType(buffer);

  // 1. Extensión peligrosa directa
  if (DANGEROUS_EXTENSIONS.has(declaredExt)) {
    score += 70;
    reasons.push(`Extensión de archivo de alto riesgo (.${declaredExt}), típica de ejecutables/scripts.`);
  }

  // 2. Truco de doble extensión ("foto.jpg.exe")
  if (hasDoubleExtensionTrick(filename)) {
    score += 60;
    reasons.push("El nombre del archivo usa doble extensión para disfrazar un ejecutable como imagen/video.");
  }

  // 3. Documentos con macros
  if (MACRO_CAPABLE_EXTENSIONS.has(declaredExt)) {
    score += 35;
    reasons.push("Es un documento de Office con macros habilitadas, un vector común de infección.");
  }

  // 4. Discrepancia entre lo que dice ser y lo que realmente es
  const isMediaClaim = EXPECTED_IMAGE_EXT.has(declaredExt) || EXPECTED_VIDEO_EXT.has(declaredExt);
  if (isMediaClaim && (realType === "exe" || realType === "elf")) {
    score += 90;
    reasons.push(`El archivo se presenta como ${declaredExt.toUpperCase()} pero su contenido real es un ejecutable.`);
  } else if (isMediaClaim && realType === "desconocido") {
    score += 15;
    reasons.push("No se pudo verificar que el contenido coincida con la extensión declarada.");
  }

  // 5. Tamaño anómalo (archivo "vacío" salvo por payload, o excesivamente grande)
  if (buffer.length > maxSizeBytes) {
    score += 10;
    reasons.push(`El archivo supera el tamaño máximo permitido (${Math.round(maxSizeBytes / 1024 / 1024)}MB).`);
  }
  if (isMediaClaim && buffer.length < 100) {
    score += 25;
    reasons.push("El archivo es sospechosamente pequeño para tratarse de una foto/video real.");
  }

  score = Math.min(100, score);

  let verdict = "seguro";
  if (score >= 60) verdict = "peligroso";
  else if (score >= 25) verdict = "sospechoso";

  if (reasons.length === 0) {
    reasons.push("No se detectaron señales estructurales de riesgo.");
  }

  return {
    filename,
    declaredExtension: declaredExt || null,
    detectedType: realType,
    sizeBytes: buffer.length,
    verdict,
    score,
    reasons,
  };
}

module.exports = { analyzeAttachment, DANGEROUS_EXTENSIONS, MACRO_CAPABLE_EXTENSIONS };
