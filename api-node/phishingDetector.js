/**
 * phishingDetector.js
 * Analiza una URL y devuelve un veredicto de riesgo (seguro / sospechoso / peligroso)
 * basado en reglas heurísticas + listas negras/blancas de dominios.
 */

// --- Listas configurables -------------------------------------------------

// Dominios conocidos y confiables (ejemplo, amplía según necesites)
const WHITELIST = new Set([
  "google.com", "youtube.com", "wikipedia.org", "microsoft.com",
  "apple.com", "amazon.com", "whatsapp.com", "gmail.com",
]);

// Dominios reportados como maliciosos (ejemplo, en producción esto vendría
// de una fuente actualizada como PhishTank, OpenPhish, Google Safe Browsing, etc.)
const BLACKLIST = new Set([
  // "paypa1-secure-login.com",
]);

// Acortadores de URL comunes (no son maliciosos per se, pero ocultan el destino real)
const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
  "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
]);

// Palabras clave frecuentes en phishing (marcas suplantadas + urgencia)
const SUSPICIOUS_KEYWORDS = [
  "login", "verify", "secure", "account", "update", "confirm",
  "banco", "paypal", "netflix", "whatsapp", "suspendida", "bloqueada",
  "premio", "ganador", "urgente", "click-aqui", "verificar-cuenta",
];

// TLDs frecuentemente usados en campañas de phishing (gratuitos / baratos)
const RISKY_TLDS = new Set([
  "xyz", "top", "club", "work", "click", "loan", "gq", "tk", "ml", "cf", "ga",
]);

// --- Utilidades -------------------------------------------------------------

function parseUrl(raw) {
  try {
    // Añade protocolo si falta, para poder parsear igual
    const withProtocol = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
    return new URL(withProtocol);
  } catch {
    return null;
  }
}

function getRegistrableDomain(hostname) {
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  return parts.slice(-2).join(".");
}

function isIpAddress(hostname) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(":");
}

// Detección simple de homoglifos / typosquatting contra la whitelist
// (distancia de Levenshtein sobre el dominio registrable)
function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) =>
    Array(b.length + 1).fill(0).map((_, j) => (i === 0 ? j : 0))
  );
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[a.length][b.length];
}

function findClosestWhitelistMatch(domain) {
  let best = null;
  let bestDist = Infinity;
  for (const known of WHITELIST) {
    const dist = levenshtein(domain, known);
    if (dist < bestDist) {
      bestDist = dist;
      best = known;
    }
  }
  return { best, bestDist };
}

// --- Motor de reglas ---------------------------------------------------------

function analyzeUrl(rawUrl) {
  const reasons = [];
  let score = 0; // 0-100, más alto = más riesgo

  const url = parseUrl(rawUrl);
  if (!url) {
    return {
      url: rawUrl,
      verdict: "invalida",
      score: 0,
      reasons: ["No se pudo interpretar la URL proporcionada."],
    };
  }

  const hostname = url.hostname.toLowerCase();
  const domain = getRegistrableDomain(hostname);
  const tld = domain.split(".").pop();

  // 1. Lista blanca -> corta el análisis, se considera segura
  if (WHITELIST.has(domain)) {
    return { url: rawUrl, verdict: "seguro", score: 0, reasons: ["Dominio en lista blanca de confianza."] };
  }

  // 2. Lista negra -> máximo riesgo
  if (BLACKLIST.has(domain)) {
    return { url: rawUrl, verdict: "peligroso", score: 100, reasons: ["Dominio reportado como malicioso (lista negra)."] };
  }

  // 3. IP en vez de dominio
  if (isIpAddress(hostname)) {
    score += 35;
    reasons.push("La URL usa una dirección IP en lugar de un nombre de dominio.");
  }

  // 4. Acortador de enlaces
  if (URL_SHORTENERS.has(domain)) {
    score += 20;
    reasons.push("Usa un acortador de enlaces que oculta el destino real.");
  }

  // 5. Símbolo @ en la URL (técnica clásica de phishing)
  if (rawUrl.includes("@")) {
    score += 30;
    reasons.push("Contiene el símbolo '@', usado para enmascarar el dominio real.");
  }

  // 6. Muchos subdominios
  const subdomainCount = hostname.split(".").length - 2;
  if (subdomainCount >= 3) {
    score += 15;
    reasons.push(`Tiene ${subdomainCount} subdominios, un patrón común de ofuscación.`);
  }

  // 7. Guiones excesivos en el dominio
  const hyphenCount = (domain.match(/-/g) || []).length;
  if (hyphenCount >= 2) {
    score += 10;
    reasons.push("El dominio contiene múltiples guiones, típico de dominios falsificados.");
  }

  // 8. TLD de riesgo
  if (RISKY_TLDS.has(tld)) {
    score += 15;
    reasons.push(`Extensión de dominio (.${tld}) frecuentemente usada en phishing.`);
  }

  // 9. Palabras clave sospechosas en la URL completa
  const lowerUrl = rawUrl.toLowerCase();
  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter((k) => lowerUrl.includes(k));
  if (matchedKeywords.length > 0) {
    score += Math.min(25, matchedKeywords.length * 8);
    reasons.push(`Contiene palabras clave sospechosas: ${matchedKeywords.join(", ")}.`);
  }

  // 10. No usa HTTPS
  if (url.protocol !== "https:") {
    score += 10;
    reasons.push("No utiliza conexión segura HTTPS.");
  }

  // 11. Similar a un dominio de confianza (posible typosquatting)
  const { best, bestDist } = findClosestWhitelistMatch(domain);
  if (best && bestDist > 0 && bestDist <= 2) {
    score += 30;
    reasons.push(`Se parece sospechosamente al dominio confiable "${best}" (posible typosquatting).`);
  }

  score = Math.min(100, score);

  let verdict = "seguro";
  if (score >= 60) verdict = "peligroso";
  else if (score >= 25) verdict = "sospechoso";

  if (reasons.length === 0) {
    reasons.push("No se detectaron señales de riesgo conocidas.");
  }

  return { url: rawUrl, domain, verdict, score, reasons };
}

module.exports = { analyzeUrl, WHITELIST, BLACKLIST, URL_SHORTENERS };
