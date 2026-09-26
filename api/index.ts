import { VercelRequest, VercelResponse } from "@vercel/node";

// ── Interfaces ──────────────────────────────────────────────────────────────

interface Indicator {
  type: string;
  description: string;
  weight: number;
}

interface ScoreBreakdown {
  source: string;
  weight: number;
}

interface ProviderResult {
  provider: string;
  known: boolean;
  malicious: boolean;
  detections: number;
  total_engines: number;
  confidence: number;
  evidence: string[];
  status: string;
}

interface ScanResult {
  score: number;
  level: "low" | "medium" | "critical";
  threat_type: string;
  indicators: Indicator[];
  recommendations: string[];
  urls: string[];
  confidence: number;
  score_breakdown: ScoreBreakdown[];
  threat_intelligence: ProviderResult[];
  source: string;
}

interface ScanRecord extends ScanResult {
  id: number;
  content: string;
  created_at: string;
  telegram_chat_id?: number | null;
  telegram_user_id?: number | null;
  telegram_message_id?: number | null;
  media_type?: string | null;
}

// ── Règles d'analyse ────────────────────────────────────────────────────────

const RULES: [string, string, number, RegExp][] = [
  ["sensitive_data", "Demande d'OTP ou de code secret", 30, /\b(otp|code secret|mot de passe|password|pin|identifiant)\b/i],
  ["urgency", "Pression temporelle", 20, /\b(urgent|immédiatement|maintenant|suspendu|bloqué|dernière chance)\b/i],
  ["finance", "Référence à un service financier ou Mobile Money", 15, /\b(mobile money|tmoney|flooz|fcfa|paiement|transfert|argent)\b/i],
  ["impersonation", "Usurpation possible d'un service officiel", 10, /\b(banque|service client|support|administrateur|agent)\b/i],
  ["social_engineering", "Promesse ou sollicitation sociale", 10, /\b(félicitations|gagné|cadeau|concours|emploi|recrutement)\b/i],
];

const SHORTENERS = new Set(["bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd"]);
const SUSPICIOUS_TERMS = ["verify", "verification", "secure", "login", "update", "wallet", "claim"];

// ── Fonctions utilitaires ────────────────────────────────────────────────────

function analyzeUrls(content: string): { urls: string[]; findings: { url: string; indicators: [string, string, number][] }[] } {
  const urlPattern = /https?:\/\/[^\s<>]+/gi;
  const rawUrls = content.match(urlPattern) || [];
  const urls = rawUrls.map(u => u.replace(/[.,!?;:)]+$/, ""));
  const findings: { url: string; indicators: [string, string, number][] }[] = [];

  for (const url of urls) {
    try {
      const parsed = new URL(url);
      const domain = parsed.hostname.toLowerCase();
      const indicators: [string, string, number][] = [];

      if (parsed.protocol !== "https:") {
        indicators.push(["url", "Lien HTTP non sécurisé", 15]);
      }
      if (SHORTENERS.has(domain)) {
        indicators.push(["url", "Raccourcisseur d'URL", 15]);
      }
      const combined = (parsed.pathname + domain).toLowerCase();
      if (SUSPICIOUS_TERMS.some(term => combined.includes(term))) {
        indicators.push(["url", "Domaine ou chemin imitant un service de connexion", 20]);
      }
      const hyphenCount = (domain.match(/-/g) || []).length;
      const dotCount = domain.split(".").length - 1;
      if (hyphenCount >= 2 || dotCount >= 3) {
        indicators.push(["url", "Domaine inhabituel", 15]);
      }
      findings.push({ url, indicators });
    } catch {
      findings.push({ url, indicators: [["url", "URL malformée", 10]] });
    }
  }

  return { urls, findings };
}

function assessRisk(content: string, source: string = "web"): ScanResult {
  const indicators: Indicator[] = [];
  const breakdown: ScoreBreakdown[] = [];
  const intelligence: ProviderResult[] = [];
  let score = 0;

  for (const [type, description, weight, regex] of RULES) {
    if (regex.test(content)) {
      indicators.push({ type, description, weight });
      score += weight;
      breakdown.push({ source: "Local analysis", weight });
    }
  }

  const { urls, findings } = analyzeUrls(content);
  for (const finding of findings) {
    for (const [type, description, weight] of finding.indicators) {
      indicators.push({ type, description, weight });
      score += weight;
    }
    const vtResult: ProviderResult = {
      provider: "VirusTotal",
      known: false,
      malicious: false,
      detections: 0,
      total_engines: 0,
      confidence: 0,
      evidence: [],
      status: process.env.VIRUSTOTAL_API_KEY ? "available" : "not_configured"
    };
    const urlhausResult: ProviderResult = {
      provider: "URLhaus",
      known: false,
      malicious: false,
      detections: 0,
      total_engines: 0,
      confidence: 0,
      evidence: [],
      status: process.env.URLHAUS_API_KEY ? "available" : "not_configured"
    };
    intelligence.push(vtResult, urlhausResult);
  }

  if (urls.length > 0) {
    indicators.push({ type: "url", description: "Présence d'un lien externe", weight: 10 });
    score += 10;
    breakdown.push({ source: "Local URL analysis", weight: 10 });
  }

  score = Math.min(score, 100);
  const level: "low" | "medium" | "critical" = score >= 70 ? "critical" : score >= 40 ? "medium" : "low";
  const isPhishing = indicators.some(item => ["sensitive_data", "impersonation", "url", "reputation"].includes(item.type));
  const threat_type = isPhishing ? "phishing" : indicators.length > 0 ? "suspicious" : "low risk";
  const recommendations = indicators.length > 0
    ? [
        "Ne cliquez pas sur les liens suspects.",
        "Ne communiquez jamais votre OTP, PIN ou mot de passe.",
        "Vérifiez directement auprès du service officiel."
      ]
    : ["Aucun indicateur majeur détecté. Restez néanmoins vigilant."];
  const confidence = indicators.length > 0 ? Math.min(0.99, 0.45 + Math.min(indicators.length, 5) * 0.1) : 0.25;

  return {
    score,
    level,
    threat_type,
    indicators,
    recommendations,
    urls,
    confidence,
    score_breakdown: breakdown,
    threat_intelligence: intelligence,
    source
  };
}

// ── Store en mémoire (non-persistant entre les invocations serverless) ──────

let nextId = 1;
const scanRecords: ScanRecord[] = [];

function persistScan(result: ScanResult, content: string, extra: Partial<ScanRecord> = {}): ScanRecord {
  const record: ScanRecord = {
    ...result,
    id: nextId++,
    content,
    created_at: new Date().toISOString(),
    ...extra
  };
  scanRecords.unshift(record);
  return record;
}

// Seeds
const seedExamples = [
  {
    content: "URGENT : Votre compte Flooz a été suspendu. Envoyez votre code secret immédiatement sur http://flooz-verification-login.com pour débloquer votre solde.",
    source: "telegram"
  },
  {
    content: "Félicitations ! Vous avez gagné 500 000 FCFA au concours TMoney Togo. Cliquez ici pour réclamer : http://bit.ly/gain-tmoney",
    source: "web"
  },
  {
    content: "Bonjour chers clients, veuillez noter que nos agences bancaires seront fermées ce lundi férié.",
    source: "web"
  }
];

for (const seed of seedExamples) {
  const result = assessRisk(seed.content, seed.source);
  persistScan(result, seed.content, { source: seed.source });
}

// ── Helper pour parser l'URL ─────────────────────────────────────────────────

function parseUrl(requestUrl: string): { pathname: string; query: Record<string, string> } {
  const [pathname, queryStr] = requestUrl.split("?");
  const query: Record<string, string> = {};
  if (queryStr) {
    for (const param of queryStr.split("&")) {
      const [key, val] = param.split("=");
      if (key) query[key] = val || "";
    }
  }
  return { pathname, query };
}

// ── Handler Vercel ──────────────────────────────────────────────────────────

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const url = parseUrl(req.url);

  // Health
  if (url.pathname === "/health" && req.method === "GET") {
    return res.json({ status: "ok", service: "TOGO-SHIELD" });
  }

  // POST /api/scans
  if (url.pathname === "/api/scans" && req.method === "POST") {
    const { content, source = "web" } = req.body || {};
    if (!content || typeof content !== "string" || !content.trim()) {
      return res.status(422).json({ detail: "Content is required" });
    }
    const result = assessRisk(content, source);
    persistScan(result, content, { source });
    return res.json(result);
  }

  // GET /api/scans
  if (url.pathname === "/api/scans" && req.method === "GET") {
    const limit = Math.min(Math.max(parseInt(url.query.limit || "50") || 50, 1), 100);
    return res.json(scanRecords.slice(0, limit));
  }

  // GET /api/scans/:id
  if (url.pathname.startsWith("/api/scans/") && req.method === "GET") {
    const id = parseInt(url.pathname.split("/").pop() || "0");
    const found = scanRecords.find(r => r.id === id);
    if (!found) return res.status(404).json({ detail: "Scan not found" });
    return res.json(found);
  }

  // GET /api/dashboard/summary
  if (url.pathname === "/api/dashboard/summary" && req.method === "GET") {
    const total = scanRecords.length;
    const levels = {
      low: scanRecords.filter(r => r.level === "low").length,
      medium: scanRecords.filter(r => r.level === "medium").length,
      critical: scanRecords.filter(r => r.level === "critical").length,
    };
    const telegram = scanRecords.filter(r => r.source === "telegram").length;
    const urlsCount = scanRecords.filter(r => r.content.includes("http")).length;
    const categories = {
      phishing: scanRecords.filter(r => r.threat_type === "phishing").length,
      suspicious: scanRecords.filter(r => r.threat_type === "suspicious").length,
      "low risk": scanRecords.filter(r => r.threat_type === "low risk").length,
    };
    const latest = scanRecords[0]?.created_at || null;

    return res.json({
      total_scans: total,
      critical_threats: levels.critical,
      medium_risk: levels.medium,
      low_risk: levels.low,
      urls_analyzed: urlsCount,
      threats_detected: total - levels.low,
      telegram_scans: telegram,
      last_activity: latest,
      threat_categories: categories,
      risk_distribution: levels,
    });
  }

  // GET /api/telegram/status
  if (url.pathname === "/api/telegram/status" && req.method === "GET") {
    const configured = Boolean(process.env.TELEGRAM_BOT_TOKEN);
    const enabled = process.env.TELEGRAM_ENABLED === "true";
    return res.json({
      status: configured && enabled ? "connected" : "not_configured",
      bot_username: "@TOGOShieldBot",
      configured,
      webhook_url: process.env.TELEGRAM_WEBHOOK_URL || null,
    });
  }

  // POST /api/telegram/webhook
  if (url.pathname === "/api/telegram/webhook" && req.method === "POST") {
    const secret = (req.headers["x-telegram-bot-api-secret-token"] as string) || "";
    if (process.env.TELEGRAM_WEBHOOK_SECRET && secret !== process.env.TELEGRAM_WEBHOOK_SECRET) {
      return res.status(401).json({ detail: "Invalid Telegram webhook secret" });
    }
    const update = req.body;
    const message = update?.message || {};
    const text = message.text || message.caption;
    const chat = message.chat || {};
    if (!text || !chat.id) return res.json({ status: "ignored" });

    const messageId = message.message_id;
    if (messageId && scanRecords.some(r => r.telegram_message_id === messageId)) {
      return res.json({ status: "duplicate" });
    }
    const result = assessRisk(text, "telegram");
    persistScan(result, text, {
      source: "telegram",
      telegram_chat_id: Number(chat.id),
      telegram_user_id: Number(message.from?.id || 0),
      telegram_message_id: messageId ? Number(messageId) : null,
    });
    return res.json({ status: "processed" });
  }

  // POST /api/scans/image
  if (url.pathname === "/api/scans/image" && req.method === "POST") {
    return res.status(501).json({ error: "OCR image scan not available in this environment. Please paste extracted text." });
  }

  // Serveur statique frontend en production
  if (process.env.NODE_ENV === "production" || process.env.VERCEL) {
    try {
      const { readFileSync, existsSync } = await import("fs");
      const { join, extname } = await import("path");
      const distPath = join(process.cwd(), "dist");
      const requestedPath = url.pathname === "/" ? "index.html" : url.pathname;

      const filePath = join(distPath, requestedPath);
      if (existsSync(filePath)) {
        const ext = extname(filePath);
        const contentType = ext === ".html" ? "text/html" :
                           ext === ".css" ? "text/css" :
                           ext === ".js" ? "application/javascript" :
                           ext === ".png" ? "image/png" :
                           ext === ".jpg" || ext === ".jpeg" ? "image/jpeg" :
                           ext === ".svg" ? "image/svg+xml" :
                           ext === ".ico" ? "image/x-icon" :
                           "application/octet-stream";
        res.setHeader("Content-Type", contentType);
        return res.send(readFileSync(filePath));
      }

      // SPA fallback
      if (!url.pathname.startsWith("/api")) {
        res.setHeader("Content-Type", "text/html");
        const indexHtml = readFileSync(join(distPath, "index.html"));
        return res.send(indexHtml);
      }
    } catch {
      // Fallback si le dossier dist n'existe pas
    }
  }

  return res.status(404).json({ detail: "Not found" });
}
