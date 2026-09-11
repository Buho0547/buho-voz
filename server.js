import express from "express";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const app = express();
app.set("trust proxy", 1); // Render va detrás de un proxy: necesario para leer la IP real
app.disable("x-powered-by");
app.use(express.urlencoded({ extended: false, limit: "1mb" }));
// El cuerpo crudo hace falta para verificar la firma del webhook de ElevenLabs:
// si se vuelve a serializar el JSON, los bytes cambian y la firma nunca cuadra.
app.use(express.json({ limit: "2mb", verify: (req, _res, buf) => { req.rawBody = buf; } }));

const {
  ELEVENLABS_API_KEY,
  ELEVENLABS_AGENT_ID,
  ADMIN_PASSWORD,
  BUHO_PRINT_TOKEN,
  BUHO_RESERVATION_TOKEN,
  RESERVATION_PICKUP_DAYS = "10",
  ADMIN_USERNAME = "admin",
  SESSION_SECRET,
  ELEVENLABS_WEBHOOK_SECRET,
  AVISO_EMAIL_TO = "info@buhodelasuerte.es",
  AVISO_EMAIL_FROM,
  SMTP_HOST,
  SMTP_PORT = "587",
  SMTP_USER,
  SMTP_PASS,
  PUBLIC_URL = "https://buho-panel.onrender.com",
  BUHO_DATA_DIR,
  PORT = "10000",
} = process.env;

for (const key of ["ELEVENLABS_API_KEY", "ELEVENLABS_AGENT_ID", "ADMIN_PASSWORD"]) {
  if (!process.env[key]) {
    console.error(`Falta la variable de entorno ${key}`);
    process.exit(1);
  }
}
if (ADMIN_PASSWORD.length < 12) {
  console.warn("AVISO: ADMIN_PASSWORD tiene menos de 12 caracteres. Este panel es público en internet.");
}

const API = "https://api.elevenlabs.io/v1";
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 h
const COOKIE = "__Host-buho_auth";

// Secreto de sesión. Si no se define SESSION_SECRET, se deriva de la contraseña:
// cambiar ADMIN_PASSWORD o SESSION_SECRET invalida todas las sesiones abiertas.
const sessionSecret = SESSION_SECRET
  ? Buffer.from(SESSION_SECRET)
  : crypto.createHmac("sha256", ADMIN_PASSWORD).update("buho-panel:session-key").digest();

const hmac = (message) => crypto.createHmac("sha256", sessionSecret).update(message).digest("hex");

function issueSession() {
  const expires = Date.now() + SESSION_TTL_MS;
  return `${expires}.${hmac(`session:${expires}`)}`;
}
function readSession(token) {
  const [expiresRaw, signature] = String(token).split(".");
  const expires = Number(expiresRaw);
  if (!Number.isFinite(expires) || !signature) return null;
  const expected = hmac(`session:${expires}`);
  if (signature.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  if (Date.now() > expires) return null;
  return `${expires}.${signature}`;
}
const csrfFor = (session) => hmac(`csrf:${session}`);

function parseCookies(req) {
  const cookies = {};
  for (const part of String(req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) cookies[decodeURIComponent(part.slice(0, i).trim())] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return cookies;
}
function requireAuth(req, res, next) {
  const session = readSession(parseCookies(req)[COOKIE] || "");
  if (!session) return res.redirect("/login");
  req.session = session;
  req.csrf = csrfFor(session);
  next();
}
function verifyCsrf(req, res, next) {
  const sent = String(req.body?._csrf || "");
  const expected = req.csrf;
  if (sent.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(expected))) {
    return res.status(403).send("Solicitud no válida. Vuelve a cargar la página.");
  }
  next();
}

// Comparación en tiempo constante para el login
function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// Límite de intentos de login por IP: 8 fallos en 15 minutos
const MAX_ATTEMPTS = 8;
const WINDOW_MS = 15 * 60 * 1000;
const attempts = new Map();
function loginBlocked(ip) {
  const entry = attempts.get(ip);
  if (!entry) return false;
  if (Date.now() - entry.first > WINDOW_MS) { attempts.delete(ip); return false; }
  return entry.count >= MAX_ATTEMPTS;
}
function noteFailure(ip) {
  const entry = attempts.get(ip);
  if (!entry || Date.now() - entry.first > WINDOW_MS) attempts.set(ip, { count: 1, first: Date.now() });
  else entry.count += 1;
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of attempts) if (now - entry.first > WINDOW_MS) attempts.delete(ip);
}, WINDOW_MS).unref();

app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  res.setHeader("Strict-Transport-Security", "max-age=15552000; includeSubDomains");
  next();
});

const esc = (value = "") => String(value)
  .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;").replaceAll("'", "&#039;");

async function eleven(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      "xi-api-key": ELEVENLABS_API_KEY,
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {}),
    },
  });
  const text = await response.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  if (!response.ok) {
    const detail = data?.detail;
    const message = (typeof detail === "string" ? detail : detail?.message) || data?.message || `ElevenLabs devolvió HTTP ${response.status}`;
    const err = new Error(message); err.status = response.status; err.data = data; throw err;
  }
  return data;
}

function formatDate(unix) {
  if (!unix) return "—";
  return new Intl.DateTimeFormat("es-ES", { timeZone: "Europe/Madrid", dateStyle: "short", timeStyle: "short" }).format(new Date(unix * 1000));
}
function duration(secs) {
  if (!Number.isFinite(Number(secs))) return "—";
  const s = Number(secs), m = Math.floor(s / 60), r = Math.round(s % 60);
  return m ? `${m} min ${r} s` : `${r} s`;
}
function statusText(value) {
  const map = { success: "Resuelta", failure: "No resuelta", unknown: "Sin evaluar", error: "Error", done: "Finalizada", failed: "Fallida", processing: "Procesando", initiated: "Iniciada", "in-progress": "En curso" };
  return map[value] || value || "—";
}

// Historial de versiones del prompt guardadas desde este panel (se pierde al reiniciar Render).
// La copia de seguridad de verdad es el botón "Descargar copia".
const history = [];
const MAX_HISTORY = 20;

const CALL_STATES = new Set(["nueva", "pendiente", "atendida", "cerrada"]);
const PANEL_DATA_DIR = BUHO_DATA_DIR || path.join("/tmp", "buho-panel");
const PANEL_STATE_FILE = path.join(PANEL_DATA_DIR, "panel-state.json");
const PANEL_STORAGE_PERSISTENT = Boolean(BUHO_DATA_DIR);

function emptyPanelState() {
  return { calls: {}, reprints: [], reservations: {}, reservation_prints: [] };
}

function loadPanelState() {
  try {
    fs.mkdirSync(PANEL_DATA_DIR, { recursive: true });
    if (!fs.existsSync(PANEL_STATE_FILE)) return emptyPanelState();
    const parsed = JSON.parse(fs.readFileSync(PANEL_STATE_FILE, "utf8"));
    return {
      calls: parsed?.calls && typeof parsed.calls === "object" && !Array.isArray(parsed.calls) ? parsed.calls : {},
      reprints: Array.isArray(parsed?.reprints) ? parsed.reprints : [],
      reservations: parsed?.reservations && typeof parsed.reservations === "object" && !Array.isArray(parsed.reservations) ? parsed.reservations : {},
      reservation_prints: Array.isArray(parsed?.reservation_prints) ? parsed.reservation_prints : [],
    };
  } catch (error) {
    console.error("No se pudo leer el estado del panel:", error.message);
    return emptyPanelState();
  }
}

function savePanelState(state) {
  fs.mkdirSync(PANEL_DATA_DIR, { recursive: true });
  const clean = {
    calls: state?.calls && typeof state.calls === "object" ? state.calls : {},
    reprints: Array.isArray(state?.reprints) ? state.reprints.slice(-300) : [],
    reservations: state?.reservations && typeof state.reservations === "object" ? state.reservations : {},
    reservation_prints: Array.isArray(state?.reservation_prints) ? state.reservation_prints.slice(-500) : [],
  };
  const tmp = `${PANEL_STATE_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(clean, null, 2), "utf8");
  fs.renameSync(tmp, PANEL_STATE_FILE);
}

function managedCallRecord(panelState, id) {
  return panelState?.calls?.[id] && typeof panelState.calls[id] === "object"
    ? panelState.calls[id]
    : {};
}

function safeReturnPath(value, fallback = "/calls") {
  const v = String(value || "").trim();
  return v.startsWith("/") && !v.startsWith("//") ? v : fallback;
}


const RESERVATION_STATES = new Set(["pendiente", "recogida", "cancelada"]);
const RESERVATION_DAYS = Math.max(1, Math.min(60, Number(RESERVATION_PICKUP_DAYS) || 10));
let reservationWriteChain = Promise.resolve();

function withReservationLock(worker) {
  const run = reservationWriteChain.then(worker, worker);
  reservationWriteChain = run.catch(() => {});
  return run;
}

function addCalendarDaysToKey(dayKey, days) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(dayKey || ""));
  if (!m) return "";
  const d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]) + Number(days || 0)));
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,"0")}-${String(d.getUTCDate()).padStart(2,"0")}`;
}

function formatDayKeyEs(dayKey) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(dayKey || ""));
  return m ? `${m[3]}/${m[2]}/${m[1]}` : String(dayKey || "—");
}

function reservationEffectiveStatus(reservation, today = todayMadridKey()) {
  const stored = String(reservation?.status || "pendiente").toLowerCase();
  if (stored === "recogida" || stored === "cancelada") return stored;
  if (reservation?.expires_date && String(reservation.expires_date) < String(today)) return "caducada";
  return "pendiente";
}

function reservationStatusLabel(status) {
  return ({ pendiente: "Pendiente de recoger", recogida: "Recogida", cancelada: "Cancelada", caducada: "Caducada" })[status] || status || "Pendiente";
}

function activeReservationQuantity(state, number, excludeId = "") {
  return Object.values(state?.reservations || {}).reduce((sum, r) => {
    if (!r || r.id === excludeId || r.number !== number) return sum;
    if (reservationEffectiveStatus(r) !== "pendiente") return sum;
    return sum + Math.max(0, Number(r.quantity || 0));
  }, 0);
}

function cleanPhone(value) {
  return String(value || "").trim().replace(/\s+/g, " ").slice(0, 40);
}

function reservationId(state) {
  const day = todayMadridKey().replaceAll("-", "").slice(2);
  for (let i = 0; i < 30; i++) {
    const suffix = String(Math.floor(1000 + Math.random() * 9000));
    const id = `R-${day}-${suffix}`;
    if (!state?.reservations?.[id]) return id;
  }
  return `R-${day}-${crypto.randomUUID().slice(0, 6).toUpperCase()}`;
}

function queueReservationPrint(state, reservation, reason = "new") {
  state.reservation_prints = Array.isArray(state.reservation_prints) ? state.reservation_prints : [];
  const existing = reason === "new" && state.reservation_prints.find((p) => p.reservation_id === reservation.id && p.reason === "new" && !p.acked_at);
  if (existing) return existing.queue_id;
  const queue_id = crypto.randomUUID();
  state.reservation_prints.push({ queue_id, reservation_id: reservation.id, created_at: Date.now(), acked_at: null, reason });
  return queue_id;
}

async function consultarNumeroReservable(number, state = null) {
  const real = await consultarNumeroReal(number);
  const panelState = state || loadPanelState();
  const reserved = activeReservationQuantity(panelState, number);
  const quantity = Math.max(0, Number(real.quantity || 0) - reserved);
  return { ...real, source_quantity: Number(real.quantity || 0), reserved, quantity, available: real.available && quantity > 0 };
}

async function createReservationRecord(input) {
  if (!PANEL_STORAGE_PERSISTENT) {
    const err = new Error("Las reservas están bloqueadas hasta activar el almacenamiento persistente de Render.");
    err.code = "PERSISTENCE_REQUIRED";
    throw err;
  }

  const number = String(input?.number || "").trim();
  const quantity = Number(input?.quantity);
  const customer_name = String(input?.customer_name || "").trim().replace(/\s+/g, " ").slice(0, 120);
  const customer_phone = cleanPhone(input?.customer_phone);
  const conversation_id = String(input?.conversation_id || "").trim().slice(0, 200);

  if (!/^\d{5}$/.test(number)) throw new Error("El número debe contener exactamente cinco cifras.");
  if (!Number.isInteger(quantity) || quantity < 1 || quantity > 100) throw new Error("La cantidad debe ser un número entero entre 1 y 100.");
  if (customer_name.length < 2) throw new Error("Falta el nombre del cliente.");
  if (customer_phone.replace(/\D/g, "").length < 6) throw new Error("Falta un teléfono válido del cliente.");

  const state = loadPanelState();

  // Idempotencia: si ElevenLabs reintenta el mismo tool call, no duplica la reserva.
  if (conversation_id) {
    const existing = Object.values(state.reservations || {}).find((r) =>
      r && r.conversation_id === conversation_id && r.number === number &&
      Number(r.quantity) === quantity && r.customer_name === customer_name &&
      cleanPhone(r.customer_phone) === customer_phone &&
      reservationEffectiveStatus(r) === "pendiente"
    );
    if (existing) return { reservation: existing, already_exists: true, availability: await consultarNumeroReservable(number, state) };
  }

  const availability = await consultarNumeroReservable(number, state);
  if (quantity > availability.quantity) {
    const err = new Error(availability.quantity > 0
      ? `Solo quedan ${availability.quantity} décimo(s) disponibles para reservar.`
      : "Ahora mismo no quedan décimos disponibles para reservar.");
    err.code = "INSUFFICIENT_STOCK";
    err.available_quantity = availability.quantity;
    throw err;
  }

  const createdDate = todayMadridKey();
  const reservation = {
    id: reservationId(state),
    number,
    quantity,
    customer_name,
    customer_phone,
    conversation_id,
    created_at: Date.now(),
    created_date: createdDate,
    expires_date: addCalendarDaysToKey(createdDate, RESERVATION_DAYS),
    status: "pendiente",
    payment: "Pago al recoger",
    notes: "",
    created_by: input?.created_by === "panel" ? "panel" : "agent",
    updated_at: Date.now(),
  };

  state.reservations[reservation.id] = reservation;
  queueReservationPrint(state, reservation, "new");
  savePanelState(state);
  return { reservation, already_exists: false, availability };
}

function boolValue(entry) {
  if (entry === null || entry === undefined) return false;
  const value = typeof entry === "object" ? (entry.value ?? entry.result) : entry;
  if (typeof value === "boolean") return value;
  return ["true", "1", "yes", "si", "sí"].includes(String(value ?? "").trim().toLowerCase());
}

function sentimentText(value) {
  const s = String(value || "").toLowerCase();
  if (s === "positive") return "Positivo";
  if (s === "negative") return "Negativo";
  if (s === "neutral") return "Neutro";
  return value || "";
}

function workflowLabel(value) {
  return ({ nueva: "Nueva", pendiente: "Pendiente", atendida: "Atendida", cerrada: "Cerrada" })[value] || "Nueva";
}

function defaultWorkflow(call) {
  if ((call.reservations || []).some((r) => reservationEffectiveStatus(r) === "pendiente")) return "pendiente";
  if (call.devolver_llamada || call.pidio_borja || call.intencion_compra || call.empresa_asociacion) return "pendiente";
  return "nueva";
}

function tag(label, kind = "") {
  return `<span class="call-tag ${kind ? `tag-${kind}` : ""}">${esc(label)}</span>`;
}

async function buildCallCard(call) {
  const id = call.conversation_id;
  if (!id) return null;
  const detail = await eleven(`/convai/conversations/${encodeURIComponent(id)}`);
  const collected = detail.analysis?.data_collection_results || {};
  const meta = detail.metadata || {};
  const analysis = detail.analysis || {};

  return {
    id,
    at: meta.start_time_unix_secs || call.start_time_unix_secs || 0,
    duracion: meta.call_duration_secs || call.call_duration_secs || 0,
    telefono:
      detail.user_id ||
      meta.phone_call?.external_number ||
      meta.phone_call?.caller_id ||
      "Número no disponible",
    titulo: call.call_summary_title || analysis.call_summary_title || "Llamada",
    resumen: analysis.transcript_summary || call.transcript_summary || "Sin resumen",
    motivo: pickValue(collected.motivo_llamada),
    numeros: pickValue(collected.numeros_consultados),
    disponibilidad: pickValue(collected.resultado_disponibilidad),
    cantidad: pickValue(collected.cantidad_solicitada),
    intencion_compra: boolValue(collected.intencion_compra),
    pidio_borja: boolValue(collected.pidio_borja),
    empresa_asociacion: pickValue(collected.empresa_asociacion),
    aviso_nombre: pickValue(collected.aviso_nombre),
    aviso_telefono: pickValue(collected.aviso_telefono),
    aviso_peticion: pickValue(collected.aviso_peticion),
    devolver_llamada:
      boolValue(collected.devolver_llamada) ||
      Boolean(pickValue(collected.aviso_nombre) || pickValue(collected.aviso_telefono)),
    transferida:
      Array.isArray(call.tool_names) &&
      call.tool_names.some((tool) => String(tool).toLowerCase().includes("transfer")),
    sentimiento:
      detail.sentiment_analysis?.overall_label ||
      call.sentiment_analysis?.overall_label ||
      "",
    sentimiento_score:
      detail.sentiment_analysis?.overall_sentiment_score ??
      call.sentiment_analysis?.overall_sentiment_score ??
      null,
    frustracion:
      detail.sentiment_analysis?.overall_frustration_score ??
      call.sentiment_analysis?.overall_frustration_score ??
      null,
    resultado: call.call_successful || analysis.call_successful || detail.status || call.status || "",
  };
}

const CALL_CACHE_TTL_MS = 45 * 1000;
const recentCallCache = new Map();

async function loadRecentCallCards(limit = 50) {
  const safeLimit = [30, 50, 100].includes(Number(limit)) ? Number(limit) : 50;
  const cached = recentCallCache.get(safeLimit);
  if (cached && Date.now() - cached.at < CALL_CACHE_TTL_MS) return cached.calls;

  const qs = new URLSearchParams({
    agent_id: ELEVENLABS_AGENT_ID,
    page_size: String(safeLimit),
    summary_mode: "include",
    sort_direction: "desc",
  });
  const data = await eleven(`/convai/conversations?${qs}`);
  const baseCalls = data.conversations || [];
  const detailed = await mapLimit(baseCalls, 8, buildCallCard);
  const calls = detailed.filter(Boolean);
  recentCallCache.set(safeLimit, { at: Date.now(), calls });
  return calls;
}

function clearRecentCallCache() {
  recentCallCache.clear();
}

function applyWorkflow(calls, panelState) {
  const reservations = Object.values(panelState?.reservations || {});
  for (const call of calls) {
    const record = managedCallRecord(panelState, call.id);
    call.reservations = reservations.filter((r) => r?.conversation_id === call.id);
    call.workflow = CALL_STATES.has(record.state) ? record.state : defaultWorkflow(call);
    call.notes = String(record.notes || "");
    call.managed_at = Number(record.updated_at || 0);
  }
  return calls;
}

function phoneDigits(phone) {
  let digits = String(phone || "").replace(/\D/g, "");
  if (!digits || String(phone).toLowerCase().includes("no disponible")) return "";
  if (digits.startsWith("00")) digits = digits.slice(2);
  if (digits.length === 9) digits = `34${digits}`;
  return digits;
}

function phoneActions(phone) {
  const digits = phoneDigits(phone);
  if (!digits) return "";
  const tel = String(phone).trim();
  return `<a class="btn tiny secondary" href="tel:${esc(tel)}">Llamar</a><a class="btn tiny whatsapp" href="https://wa.me/${esc(digits)}" target="_blank" rel="noopener noreferrer">WhatsApp</a>`;
}

function madridDayKey(unix) {
  if (!unix) return "";
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Europe/Madrid", year: "numeric", month: "2-digit", day: "2-digit"
  }).formatToParts(new Date(Number(unix) * 1000));
  const get = (type) => parts.find((p) => p.type === type)?.value || "";
  return `${get("year")}-${get("month")}-${get("day")}`;
}

function todayMadridKey() {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Europe/Madrid", year: "numeric", month: "2-digit", day: "2-digit"
  }).formatToParts(new Date());
  const get = (type) => parts.find((p) => p.type === type)?.value || "";
  return `${get("year")}-${get("month")}-${get("day")}`;
}

function isIncident(call) {
  return String(call.motivo || "").toLowerCase().includes("incidencia") ||
    ["failure", "failed", "error"].includes(String(call.resultado || "").toLowerCase());
}

function splitLotteryNumbers(value) {
  return String(value || "").match(/\b\d{5}\b/g) || [];
}

function countTop(values, max = 8) {
  const counts = new Map();
  for (const value of values.filter(Boolean)) counts.set(value, (counts.get(value) || 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, max);
}


function isResolved(call) {
  return String(call?.resultado || "").toLowerCase() === "success";
}

function isUnresolved(call) {
  return ["failure", "failed", "error"].includes(String(call?.resultado || "").toLowerCase());
}

function madridHour(unix) {
  if (!unix) return null;
  const value = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Europe/Madrid",
    hour: "2-digit",
    hourCycle: "h23",
  }).format(new Date(Number(unix) * 1000));
  const hour = Number(value);
  return Number.isFinite(hour) ? hour : null;
}

function madridDateKeys(days) {
  const [year, month, day] = todayMadridKey().split("-").map(Number);
  const base = Date.UTC(year, month - 1, day, 12, 0, 0);
  return Array.from({ length: days }, (_, index) => {
    const date = new Date(base - (days - 1 - index) * 86400000);
    return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, "0")}-${String(date.getUTCDate()).padStart(2, "0")}`;
  });
}

function shortMadridDayLabel(key, compact = false) {
  const [year, month, day] = String(key).split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day, 12, 0, 0));
  return new Intl.DateTimeFormat("es-ES", compact
    ? { day: "numeric", month: "short", timeZone: "UTC" }
    : { weekday: "short", day: "numeric", month: "short", timeZone: "UTC" }
  ).format(date).replaceAll(".", "");
}

function renderGroupedChart(title, subtitle, rows, series) {
  const values = rows.flatMap((row) => series.map((item) => Number(row[item.key] || 0)));
  const maxValue = Math.max(1, ...values);
  const minWidth = Math.max(660, rows.length * Math.max(36, series.length * 14 + 19));
  const legend = series.map((item, index) => `<span class="chart-legend-item"><span class="chart-swatch chart-s${index + 1}"></span>${esc(item.label)}</span>`).join("");
  const columns = rows.map((row) => {
    const bars = series.map((item, index) => {
      const value = Number(row[item.key] || 0);
      const pct = value > 0 ? Math.max(5, Math.round((value / maxValue) * 100)) : 0;
      return `<div class="chart-bar-slot" title="${esc(item.label)}: ${value}"><span class="chart-bar-value">${value || ""}</span><div class="chart-bar chart-s${index + 1}" style="height:${pct}%"></div></div>`;
    }).join("");
    return `<div class="chart-column"><div class="chart-bars-group">${bars}</div><div class="chart-axis-label">${esc(row.label)}</div></div>`;
  }).join("");
  return `<section class="panel chart-panel"><div class="chart-head"><div><h2>${esc(title)}</h2><div class="small">${esc(subtitle)}</div></div><div class="chart-legend">${legend}</div></div><div class="chart-scroll"><div class="chart-grid" style="grid-template-columns:repeat(${rows.length},minmax(28px,1fr));min-width:${minWidth}px">${columns}</div></div></section>`;
}

function renderHorizontalChart(title, subtitle, rows) {
  const maxValue = Math.max(1, ...rows.map((row) => Number(row.value || 0)));
  const body = rows.map((row) => {
    const value = Number(row.value || 0);
    const pct = value > 0 ? Math.max(2, Math.round((value / maxValue) * 100)) : 0;
    return `<div class="hbar-row"><div class="hbar-label">${esc(row.label)}</div><div class="hbar-track"><div class="hbar-fill" style="width:${pct}%"></div></div><strong>${value}</strong></div>`;
  }).join("");
  return `<section class="panel chart-panel"><div class="chart-head"><div><h2>${esc(title)}</h2><div class="small">${esc(subtitle)}</div></div></div><div class="hbar-list">${body}</div></section>`;
}

function metricPercent(value, total) {
  const n = Number(value || 0), d = Number(total || 0);
  if (!d) return 0;
  return Math.round((n / d) * 1000) / 10;
}

function relativeChange(current, previous) {
  const now = Number(current || 0), before = Number(previous || 0);
  if (before === 0) {
    if (now === 0) return { text: "Sin cambio", cls: "flat" };
    return { text: "Nuevo en el periodo", cls: "up" };
  }
  const pct = Math.round(((now - before) / before) * 100);
  if (pct === 0) return { text: "Sin cambio", cls: "flat" };
  return { text: `${pct > 0 ? "+" : ""}${pct}% vs. periodo anterior`, cls: pct > 0 ? "up" : "down" };
}

function pointChange(current, previous) {
  const delta = Math.round((Number(current || 0) - Number(previous || 0)) * 10) / 10;
  if (delta === 0) return { text: "Sin cambio", cls: "flat" };
  return { text: `${delta > 0 ? "+" : ""}${delta} p.p. vs. periodo anterior`, cls: delta > 0 ? "up" : "down" };
}

function trendHtml(trend) {
  const symbol = trend.cls === "up" ? "▲" : trend.cls === "down" ? "▼" : "•";
  return `<div class="metric-trend ${trend.cls}">${symbol} ${esc(trend.text)}</div>`;
}

function renderRankBars(title, subtitle, rows) {
  const safeRows = rows.length ? rows : [{ label: "Sin datos", value: 0 }];
  const maxValue = Math.max(1, ...safeRows.map((row) => Number(row.value || 0)));
  const body = safeRows.map((row, index) => {
    const value = Number(row.value || 0);
    const pct = value > 0 ? Math.max(3, Math.round((value / maxValue) * 100)) : 0;
    return `<div class="rankbar-row"><div class="rankbar-pos">${index + 1}</div><div class="rankbar-main"><div class="rankbar-top"><strong>${esc(row.label)}</strong><span>${value}</span></div><div class="rankbar-track"><div class="rankbar-fill" style="width:${pct}%"></div></div></div></div>`;
  }).join("");
  return `<section class="panel chart-panel"><div class="chart-head"><div><h2>${esc(title)}</h2><div class="small">${esc(subtitle)}</div></div></div><div class="rankbar-list">${body}</div></section>`;
}



const LOGO_DATA_URI = "data:image/jpeg;base64,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";

const CSS = `
:root{
  --bg:#f5f1ea;--panel:#fffdf9;--panel2:#faf6f0;--ink:#24191d;--muted:#75686d;--line:#e5ddd8;
  --brand:#811833;--brand-dark:#5d0e23;--brand-deep:#400919;--brand-soft:#f7e9ee;
  --accent:#c7a15a;--accent-soft:#f7eedb;--danger:#9a2d38;--danger-soft:#fae8ea;
  --ok:#2f6b4c;--ok-soft:#e9f3ed;--blue:#3c5f7d;--blue-soft:#eaf0f6;
  --purple:#6a466f;--purple-soft:#f0e7f2;--shadow:0 12px 32px rgba(73,30,43,.07)
}
*{box-sizing:border-box}
html{background:var(--bg)}
body{margin:0;background:var(--bg);color:var(--ink);font:500 15px/1.5 "Segoe UI",Arial,sans-serif;-webkit-font-smoothing:antialiased}
a{color:inherit}
.shell{display:grid;grid-template-columns:248px minmax(0,1fr);min-height:100vh}
nav{background:linear-gradient(180deg,var(--brand-dark),var(--brand-deep));color:white;padding:22px 16px 20px;position:sticky;top:0;height:100vh;display:flex;flex-direction:column;box-shadow:8px 0 30px rgba(61,9,24,.08);z-index:2}
.brand-box{background:#fff;border-radius:15px;padding:14px 13px 12px;margin-bottom:23px;box-shadow:0 8px 24px rgba(0,0,0,.12)}
.brand-logo{display:block;width:100%;max-width:180px;height:auto;margin:0 auto 9px}
.brand-caption{color:#72535d;text-align:center;font-size:10px;font-weight:800;letter-spacing:1.35px;text-transform:uppercase;line-height:1.3}
.nav-section{font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:rgba(255,255,255,.48);font-weight:800;margin:10px 10px 7px}
nav a{display:flex;align-items:center;gap:9px;text-decoration:none;padding:10px 12px;border-radius:10px;margin:3px 0;color:#f8eef1;font-weight:800;border:1px solid transparent;transition:.15s ease}
nav a:hover{background:rgba(255,255,255,.08);border-color:rgba(255,255,255,.08)}
nav a.active{background:#fff;color:var(--brand);font-weight:900;box-shadow:0 5px 16px rgba(0,0,0,.13)}
nav form{margin-top:auto;padding-top:18px;border-top:1px solid rgba(255,255,255,.14)}
nav button{width:100%;border:1px solid rgba(255,255,255,.18);border-radius:9px;background:rgba(255,255,255,.06);color:#f7e9ee;padding:9px 11px;cursor:pointer;text-align:left;font:inherit;font-weight:800}
main{padding:0 34px 42px;max-width:1520px;width:100%;min-width:0}
.corporate-header{margin:0 -34px 24px;padding:16px 34px 15px;background:rgba(255,253,249,.97);border-bottom:1px solid var(--line);box-shadow:0 5px 22px rgba(73,30,43,.04);position:sticky;top:0;z-index:1}
.corporate-header-inner{display:flex;justify-content:space-between;gap:24px;align-items:center;max-width:1452px}
.corporate-kicker{font-size:10px;font-weight:850;letter-spacing:1.6px;text-transform:uppercase;color:var(--brand);margin-bottom:3px}
.corporate-title{font-family:"Arial Black","Segoe UI",Arial,sans-serif;font-size:27px;line-height:1.06;font-weight:900;color:var(--brand-dark);letter-spacing:-.75px}
.corporate-sub{font-size:12px;color:var(--muted);margin-top:4px}
.agent-chip{display:inline-flex;align-items:center;gap:8px;border:1px solid #ead9df;background:var(--brand-soft);color:var(--brand-dark);border-radius:999px;padding:7px 11px;font-size:12px;font-weight:800;white-space:nowrap}
.agent-dot{width:8px;height:8px;border-radius:50%;background:#3f8b61;box-shadow:0 0 0 4px rgba(63,139,97,.12)}
h1{font-family:"Arial Black","Segoe UI",Arial,sans-serif;font-size:30px;line-height:1.06;margin:0 0 7px;color:#281a1f;font-weight:900;letter-spacing:-.8px}
h2{font-size:18px;margin:0 0 16px;color:#3b252d;font-weight:900;letter-spacing:-.2px}h3{font-size:15px;margin:0 0 8px;font-weight:900}.sub{color:var(--muted);margin-bottom:24px}.small{font-size:12px;color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:18px 0 28px}
.card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px;box-shadow:0 7px 22px rgba(73,30,43,.035)}
.card{position:relative;overflow:hidden}.card:before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent)}
.metric{font-family:"Arial Black","Segoe UI",Arial,sans-serif;font-size:37px;line-height:.95;font-weight:900;color:var(--brand-dark);letter-spacing:-1px}.label{color:var(--muted);font-size:12px;letter-spacing:.15px;font-weight:700}
table{width:100%;border-collapse:collapse;background:var(--panel)}th,td{text-align:left;padding:12px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--brand);font-weight:850}td.summary{max-width:480px}.badge{display:inline-block;border:1px solid #dfd2d6;border-radius:999px;padding:4px 8px;font-size:11px;font-weight:750;white-space:nowrap;background:#fff}
.btn{display:inline-block;border:0;border-radius:9px;background:var(--brand);color:white;padding:9px 13px;text-decoration:none;cursor:pointer;font:inherit;font-weight:850;box-shadow:0 3px 10px rgba(93,14,35,.09);transition:.15s ease}.btn:hover{background:var(--brand-dark);transform:translateY(-1px)}.btn.secondary{background:#eee8e1;color:var(--ink);box-shadow:none}.btn.secondary:hover{background:#e5ddd5}.btn.danger{background:var(--danger)}.btn.whatsapp{background:#e6f4eb;color:#205b3a;box-shadow:none}.btn.tiny{padding:7px 9px;font-size:12px;border-radius:8px}.btn.outline{background:#fff;color:var(--brand);border:1px solid #cfaeb8;box-shadow:none}.btn.outline:hover{background:var(--brand-soft)}
textarea,input,select{width:100%;border:1px solid #d8cfcb;border-radius:10px;background:#fff;padding:11px;font:inherit;color:var(--ink);outline:none;transition:.15s ease}textarea:focus,input:focus,select:focus{border-color:#b77688;box-shadow:0 0 0 3px rgba(129,24,51,.08)}textarea{min-height:430px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px;line-height:1.45}.note-input{min-height:64px;font-family:inherit;font-size:13px}.field{margin:0 0 18px}.field label{display:block;font-weight:750;margin-bottom:6px;color:#4b333b}.actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.notice{border-left:4px solid var(--accent);background:#fff8ea;padding:12px 14px;border-radius:9px;margin:16px 0}.error{border-left-color:var(--danger);background:var(--danger-soft)}.ok{border-left-color:var(--ok);background:var(--ok-soft)}.info{border-left-color:var(--blue);background:var(--blue-soft)}
.login-shell{min-height:100vh;display:grid;place-items:center;padding:24px;background:linear-gradient(135deg,#f7f1ec 0%,#f1e3e8 55%,#eee1d3 100%)}.login{width:min(440px,100%);margin:0;background:rgba(255,253,249,.98);border:1px solid #e1d4d8;border-radius:22px;padding:32px;box-shadow:0 24px 70px rgba(77,15,36,.16)}.login-logo{display:block;width:220px;max-width:78%;height:auto;margin:0 auto 22px}.login h1{text-align:center;font-size:25px;color:var(--brand-dark);margin-bottom:7px}.login .sub{text-align:center;margin-bottom:24px}.login .field{margin-top:16px}.login-foot{text-align:center;border-top:1px solid var(--line);margin-top:22px;padding-top:15px;color:var(--muted);font-size:11px;letter-spacing:.25px}
code{background:#f0e8e5;padding:2px 5px;border-radius:5px}pre{white-space:pre-wrap;background:#f7f2ed;border:1px solid var(--line);padding:14px;border-radius:10px}.transcript{display:grid;gap:10px;margin-top:14px}.msg{padding:11px 13px;border-radius:11px;background:#f4efe9;border:1px solid #eee4de}.msg.agent{margin-left:40px;background:var(--brand-soft);border-color:#eed6de}.msg.user{margin-right:40px}
.quick{display:grid;grid-template-columns:minmax(180px,1fr) auto;gap:9px;max-width:540px}.quick-result{margin-top:14px;padding:14px;border-radius:12px;background:#faf5ef}.quick-result.good{border-left:5px solid var(--ok);background:var(--ok-soft)}.quick-result.bad{border-left:5px solid var(--danger);background:var(--danger-soft)}.quick-number{font-family:"Arial Black","Segoe UI",Arial,sans-serif;font-size:28px;font-weight:900;letter-spacing:1px;color:var(--brand-dark)}.dashboard-grid{display:grid;grid-template-columns:1.15fr .85fr;gap:16px;margin:18px 0}.pending-list{display:grid;gap:8px}.pending-item{display:flex;justify-content:space-between;gap:12px;padding:10px 0;border-bottom:1px solid var(--line)}
.call-toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:18px 0}.call-search{display:flex;gap:8px;flex:1;min-width:260px}.call-search input{min-width:180px}.call-search .btn{flex:0 0 auto}.limit-form{display:flex;gap:7px;align-items:center}.limit-form select{width:auto;padding:8px}.filters{display:flex;gap:7px;flex-wrap:wrap;margin:0 0 20px;padding:10px;background:rgba(255,253,249,.72);border:1px solid var(--line);border-radius:14px;box-shadow:0 4px 14px rgba(73,30,43,.025)}.filter{display:inline-block;text-decoration:none;border:1px solid #dfd2d6;background:var(--panel);border-radius:999px;padding:7px 11px;font-size:12px;font-weight:900;color:#51343d;transition:.15s ease}.filter:hover{border-color:#caa7b2;background:var(--brand-soft)}.filter.active{background:var(--brand);border-color:var(--brand);color:white;box-shadow:0 4px 13px rgba(93,14,35,.13)}
.call-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.call-card{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:19px;box-shadow:var(--shadow);position:relative;overflow:hidden}.call-card:after{content:"";position:absolute;left:0;top:0;bottom:0;width:5px;background:#d8c5cb}.call-card.priority:after{background:var(--accent)}.call-card.negative:after{background:var(--danger)}.call-head{display:flex;justify-content:space-between;gap:14px;align-items:flex-start}.call-time{font-size:11px;color:var(--muted);margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px}.call-phone{font-family:"Arial Black","Segoe UI",Arial,sans-serif;font-size:21px;font-weight:900;line-height:1.1;color:var(--brand-dark);letter-spacing:-.35px}.call-duration{font-size:12px;color:var(--muted);margin-top:4px}.workflow-badge{border:1px solid rgba(0,0,0,.05);border-radius:999px;padding:5px 9px;font-size:11px;font-weight:900;white-space:nowrap}.workflow-nueva{background:#eeeae6;color:#5f5551}.workflow-pendiente{background:var(--accent-soft);color:#765215}.workflow-atendida{background:var(--ok-soft);color:#28583f}.workflow-cerrada{background:#e8e6e0;color:#5d625f}.call-tags{display:flex;flex-wrap:wrap;gap:6px;margin:13px 0}.call-tag{display:inline-block;border-radius:999px;padding:4px 8px;background:#efebe7;font-size:10px;font-weight:900;letter-spacing:.25px;text-transform:uppercase}.tag-buy{background:var(--ok-soft);color:#245039}.tag-company{background:var(--purple-soft);color:#633e69}.tag-borja{background:var(--blue-soft);color:#334f72}.tag-alert{background:var(--danger-soft);color:#842934}.tag-transfer{background:#e9eef6;color:#31506e}.tag-number{background:var(--accent-soft);color:#755616}.call-motive{font-family:"Arial Black","Segoe UI",Arial,sans-serif;font-size:16px;font-weight:900;margin:8px 0 3px;color:#3b242c;letter-spacing:-.25px}.call-summary{color:#5e5054;margin:7px 0 12px;font-size:14px;line-height:1.45}.call-data{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin:12px 0}.call-data>div{background:var(--panel2);border:1px solid #f0e7e1;border-radius:11px;padding:9px 10px}.call-data .value{font-weight:900;margin-top:2px;color:#37262c}.call-footer{display:flex;gap:9px;justify-content:space-between;align-items:flex-end;border-top:1px solid var(--line);padding-top:13px;margin-top:13px;flex-wrap:wrap}.call-actions{display:flex;gap:6px;flex-wrap:wrap}.manage-form{display:grid;grid-template-columns:145px minmax(190px,1fr) auto;gap:7px;align-items:end;flex:1}.manage-form select{padding:8px}.empty{padding:36px;text-align:center;color:var(--muted)}.countline{font-size:13px;color:var(--muted);margin-left:auto}.notes-preview{background:#fbf5e9;border:1px solid #efe0c3;border-radius:10px;padding:9px 10px;margin-top:10px}.notes-preview strong{font-size:11px;text-transform:uppercase;color:#7b6240;letter-spacing:.55px}
.today-strip{display:flex;gap:10px;align-items:center;flex-wrap:wrap;background:linear-gradient(90deg,var(--brand-dark),var(--brand));color:#fff;border-radius:14px;padding:11px 14px;margin:0 0 18px;box-shadow:0 7px 20px rgba(93,14,35,.13)}.today-strip strong{font-family:"Arial Black","Segoe UI",Arial,sans-serif;font-weight:900;letter-spacing:-.2px}.today-strip span{opacity:.9}.today-dot{opacity:.45}
.stat-lists{display:grid;grid-template-columns:1fr 1fr;gap:16px}.rank{counter-reset:item;list-style:none;padding:0;margin:0}.rank li{display:flex;justify-content:space-between;gap:10px;padding:9px 0;border-bottom:1px solid var(--line)}.customer-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.customer-card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:17px;box-shadow:0 7px 22px rgba(73,30,43,.04)}.customer-phone{font-family:"Arial Black","Segoe UI",Arial,sans-serif;font-size:19px;font-weight:900;color:var(--brand-dark);letter-spacing:-.3px}.storage-warning{font-size:12px;color:var(--muted);margin-top:16px}

.summary-toolbar{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;margin:0 0 18px}.period-tabs{display:flex;gap:7px;flex-wrap:wrap;background:rgba(255,253,249,.75);border:1px solid var(--line);border-radius:14px;padding:6px}.period-tab{display:inline-block;text-decoration:none;border-radius:9px;padding:8px 12px;font-size:12px;font-weight:900;color:#5d3e48}.period-tab:hover{background:var(--brand-soft)}.period-tab.active{background:var(--brand);color:#fff;box-shadow:0 4px 12px rgba(93,14,35,.13)}
.summary-metrics{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:11px;margin:15px 0 22px}.summary-metric{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px 15px;box-shadow:0 6px 18px rgba(73,30,43,.035);position:relative;overflow:hidden}.summary-metric:before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent)}.summary-metric .metric{font-size:29px}.summary-metric .label{margin-top:4px}.summary-metric.brand:before{background:var(--brand)}.summary-metric.ok:before{background:var(--ok)}.summary-metric.danger:before{background:var(--danger)}.summary-metric.blue:before{background:var(--blue)}
.charts-two{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:16px 0}.chart-panel{padding:18px 18px 14px;min-width:0}.chart-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:14px}.chart-head h2{margin-bottom:2px}.chart-legend{display:flex;gap:10px 12px;align-items:center;justify-content:flex-end;flex-wrap:wrap}.chart-legend-item{display:inline-flex;align-items:center;gap:5px;font-size:11px;font-weight:800;color:#68565d;white-space:nowrap}.chart-swatch{width:10px;height:10px;border-radius:3px;display:inline-block}.chart-scroll{overflow-x:auto;padding:8px 2px 2px}.chart-grid{height:245px;display:grid;align-items:stretch;gap:7px;border-bottom:1px solid #dfd4d0;background:repeating-linear-gradient(to top,transparent 0,transparent 60px,rgba(129,24,51,.055) 61px,transparent 62px)}.chart-column{display:grid;grid-template-rows:1fr 30px;min-width:0}.chart-bars-group{display:flex;align-items:flex-end;justify-content:center;gap:3px;height:100%;padding:20px 1px 0}.chart-bar-slot{height:100%;flex:1;max-width:18px;min-width:5px;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;position:relative}.chart-bar{width:100%;min-height:0;border-radius:5px 5px 2px 2px;box-shadow:inset 0 1px rgba(255,255,255,.25)}.chart-bar-value{font-size:9px;font-weight:900;color:#69565d;min-height:14px;line-height:12px}.chart-axis-label{text-align:center;font-size:9px;font-weight:800;color:#796b70;line-height:1.08;padding-top:6px;white-space:normal}.chart-s1{background:var(--brand)}.chart-s2{background:var(--ok)}.chart-s3{background:var(--accent)}.chart-s4{background:var(--blue)}.chart-s5{background:#8a718e}.chart-s6{background:var(--danger)}
.hbar-list{display:grid;gap:8px;margin-top:12px}.hbar-row{display:grid;grid-template-columns:48px 1fr 34px;gap:9px;align-items:center}.hbar-label{font-size:11px;font-weight:900;color:#604650;text-align:right}.hbar-track{height:13px;background:#f1e9e6;border-radius:999px;overflow:hidden}.hbar-fill{height:100%;background:linear-gradient(90deg,var(--brand-dark),var(--brand));border-radius:999px}.hbar-row strong{font-size:11px;color:#523942}.chart-note{font-size:11px;color:var(--muted);margin:10px 0 0}.metric-definition{margin-top:14px;padding:12px 14px;border-radius:11px;background:#faf5ef;border:1px solid #eee2da;font-size:12px;color:#6d5a61}.metric-definition strong{color:var(--brand-dark)}

.summary-metric .metric-share{font-size:11px;font-weight:850;color:#67565c;margin-top:6px}.metric-trend{display:inline-flex;align-items:center;gap:4px;margin-top:7px;padding:3px 7px;border-radius:999px;font-size:10px;font-weight:900;line-height:1.2}.metric-trend.up{background:#edf5ef;color:#2b6848}.metric-trend.down{background:#f8e9ec;color:#8a2a39}.metric-trend.flat{background:#f0ece8;color:#74666a}
.compare-panel{margin:16px 0}.compare-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.compare-item{background:var(--panel2);border:1px solid #eee4de;border-radius:12px;padding:12px}.compare-title{font-size:11px;font-weight:900;text-transform:uppercase;letter-spacing:.45px;color:#795864}.compare-values{display:flex;align-items:flex-end;justify-content:space-between;gap:8px;margin-top:7px}.compare-current{font-family:"Arial Black","Segoe UI",Arial,sans-serif;font-size:23px;line-height:1;color:var(--brand-dark)}.compare-prev{font-size:11px;color:var(--muted);text-align:right}.compare-note{margin-top:10px;font-size:11px;color:var(--muted)}
.rankbar-list{display:grid;gap:11px;margin-top:12px}.rankbar-row{display:grid;grid-template-columns:24px 1fr;gap:9px;align-items:center}.rankbar-pos{width:24px;height:24px;display:grid;place-items:center;border-radius:50%;background:var(--brand-soft);color:var(--brand);font-size:10px;font-weight:900}.rankbar-main{min-width:0}.rankbar-top{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:4px;font-size:12px}.rankbar-top strong{font-family:"Arial Black","Segoe UI",Arial,sans-serif;color:#4a2c35;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.rankbar-top span{font-weight:900;color:var(--brand)}.rankbar-track{height:8px;background:#f1e8e5;border-radius:999px;overflow:hidden}.rankbar-fill{height:100%;background:linear-gradient(90deg,var(--brand-dark),var(--brand));border-radius:999px}
.peak-chip{display:inline-flex;gap:7px;align-items:center;background:var(--accent-soft);color:#6f4f17;border:1px solid #ead9b6;border-radius:999px;padding:6px 9px;font-size:11px;font-weight:900}


.reservation-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.reservation-card{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:19px;box-shadow:var(--shadow);position:relative;overflow:hidden}.reservation-card:before{content:"";position:absolute;left:0;top:0;bottom:0;width:5px;background:var(--accent)}.reservation-card.done:before{background:var(--ok)}.reservation-card.cancelled:before,.reservation-card.expired:before{background:#aaa}.reservation-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}.reservation-id{font-size:11px;font-weight:900;letter-spacing:.6px;color:var(--muted)}.reservation-number{font-family:"Arial Black","Segoe UI",Arial,sans-serif;font-size:31px;line-height:1;color:var(--brand-dark);letter-spacing:1px;margin-top:4px}.reservation-name{font-family:"Arial Black","Segoe UI",Arial,sans-serif;font-size:17px;color:#3b252d;margin-top:12px}.reservation-deadline{background:var(--accent-soft);border:1px solid #ead9b6;border-radius:11px;padding:10px 12px;margin:12px 0;font-weight:850;color:#6f4f17}.reservation-status{display:inline-block;border-radius:999px;padding:5px 9px;font-size:11px;font-weight:900}.reservation-status.pendiente{background:var(--accent-soft);color:#765215}.reservation-status.recogida{background:var(--ok-soft);color:#28583f}.reservation-status.cancelada,.reservation-status.caducada{background:#ece9e6;color:#666}.reservation-form{display:grid;grid-template-columns:1fr 110px 1fr 1fr auto;gap:9px;align-items:end}.reservation-form .field{margin:0}.reservation-toolbar{display:flex;gap:9px;flex-wrap:wrap;align-items:center;margin-bottom:18px}.reservation-toolbar form{display:flex;gap:8px;flex:1}.reservation-toolbar input{min-width:220px}.stock-line{font-size:12px;color:var(--muted);margin-top:6px}.reservation-note{font-size:12px;color:var(--muted);margin-top:10px}.reservation-actions{display:flex;gap:7px;flex-wrap:wrap;margin-top:12px}.tag-reservation{background:#f3e4b9;color:#6d4b0c}

@media(max-width:1050px){.call-grid,.reservation-grid{grid-template-columns:1fr}.customer-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.dashboard-grid{grid-template-columns:1fr}.summary-metrics{grid-template-columns:repeat(3,minmax(0,1fr))}.compare-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.charts-two{grid-template-columns:1fr}}
@media(max-width:900px){.reservation-form{grid-template-columns:1fr 1fr}.reservation-form .wide{grid-column:1/-1}.shell{grid-template-columns:1fr}nav{height:auto;position:relative;display:flex;align-items:center;gap:5px;padding:9px 12px;overflow:auto}.brand-box{margin:0 8px 0 0;padding:7px 9px;min-width:105px}.brand-logo{width:92px;margin:0}.brand-caption,.nav-section{display:none}nav a{white-space:nowrap;padding:8px 10px}nav form{margin:0 0 0 auto;padding:0;border:0;min-width:94px}nav button{text-align:center;padding:8px 9px}main{padding:0 20px 32px}.corporate-header{margin:0 -20px 20px;padding:14px 20px;position:relative}.corporate-title{font-size:23px}.corporate-sub{display:none}.cards{grid-template-columns:repeat(2,1fr)}.manage-form{grid-template-columns:1fr}}
@media(max-width:620px){.reservation-form{grid-template-columns:1fr}.reservation-form .wide{grid-column:auto}.agent-chip{display:none}.corporate-title{font-size:21px}.cards{grid-template-columns:1fr}.summary-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.compare-grid{grid-template-columns:1fr}.chart-head{display:block}.chart-legend{justify-content:flex-start;margin-top:9px}.summary-toolbar{display:block}.period-tabs{margin-top:10px;width:max-content;max-width:100%}.customer-grid,.stat-lists{grid-template-columns:1fr}.quick{grid-template-columns:1fr}.call-search{display:grid;grid-template-columns:1fr auto}.call-phone{font-size:18px}.msg.agent{margin-left:18px}.msg.user{margin-right:18px}th:nth-child(4),td:nth-child(4){display:none}}
`;

function layout(title, body, active = "", csrf = "") {
  const link = (href, label, key) => `<a class="${active === key ? "active" : ""}" href="${href}">${label}</a>`;
  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · El Búho de la Suerte</title><style>${CSS}</style></head><body><div class="shell"><nav><div class="brand-box"><img class="brand-logo" src="${LOGO_DATA_URI}" alt="El Búho de la Suerte"><div class="brand-caption">Administración Nº 5 · Gijón</div></div><div class="nav-section">Operativa</div>${link("/", "Inicio", "home")}${link("/calls", "Llamadas", "calls")}${link("/reservas", "Reservas", "reservas")}${link("/clientes", "Clientes", "clientes")}${link("/resumen", "Resumen", "resumen")}<div class="nav-section">Gestión</div>${link("/avisos", "Avisos", "avisos")}${link("/knowledge", "Conocimiento", "knowledge")}${link("/history", "Versiones", "history")}${link("/settings", "Estado", "settings")}<form method="post" action="/logout"><input type="hidden" name="_csrf" value="${esc(csrf)}"><button type="submit">Cerrar sesión</button></form></nav><main><header class="corporate-header"><div class="corporate-header-inner"><div><div class="corporate-kicker">El Búho de la Suerte · Gijón</div><div class="corporate-title">Control de llamadas de El Búho de la Suerte</div><div class="corporate-sub">Seguimiento de clientes, consultas, avisos e incidencias del agente de voz</div></div><div class="agent-chip"><span class="agent-dot"></span>Búho Voz operativo</div></div></header>${body}</main></div></body></html>`;
}

app.get("/health", (_req, res) => res.json({ ok: true, service: "buho-panel" }));

app.get("/login", (req, res) => {
  if (readSession(parseCookies(req)[COOKIE] || "")) return res.redirect("/");
  const error = req.query.error ? '<div class="notice error">Usuario o contraseña incorrectos.</div>' : "";
  const blocked = req.query.blocked ? '<div class="notice error">Demasiados intentos fallidos. Espera 15 minutos.</div>' : "";
  res.send(`<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Acceso · El Búho de la Suerte</title><style>${CSS}</style></head><body><div class="login-shell"><div class="login"><img class="login-logo" src="${LOGO_DATA_URI}" alt="El Búho de la Suerte"><h1>Control de llamadas</h1><p class="sub">Acceso privado al panel de El Búho de la Suerte.</p>${blocked}${error}<form method="post" action="/login"><div class="field"><label>Usuario</label><input name="username" autocomplete="username" required></div><div class="field"><label>Contraseña</label><input name="password" type="password" autocomplete="current-password" required></div><div class="field"><button class="btn" type="submit" style="width:100%">Entrar al panel</button></div></form><div class="login-foot">Administración de Lotería Nº 5 · Palacio Valdés, 9 · Gijón</div></div></div></body></html>`);
});

app.post("/login", (req, res) => {
  const ip = req.ip || "desconocida";
  if (loginBlocked(ip)) return res.redirect("/login?blocked=1");
  const okUser = safeEqual(req.body.username || "", ADMIN_USERNAME);
  const okPass = safeEqual(req.body.password || "", ADMIN_PASSWORD);
  if (!okUser || !okPass) {
    noteFailure(ip);
    console.warn(`Login fallido desde ${ip}`);
    return res.redirect("/login?error=1");
  }
  attempts.delete(ip);
  res.setHeader("Set-Cookie", `${COOKIE}=${encodeURIComponent(issueSession())}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_MS / 1000}`);
  res.redirect("/");
});

app.post("/logout", requireAuth, verifyCsrf, (_req, res) => {
  res.setHeader("Set-Cookie", `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
  res.redirect("/login");
});

app.get("/", requireAuth, async (req, res) => {
  let quick = "";
  const numero = String(req.query.numero || "").trim();
  if (numero) {
    if (!/^\d{5}$/.test(numero)) {
      quick = `<div class="quick-result bad"><strong>Número no válido.</strong><br>Introduce exactamente cinco cifras, por ejemplo 00042.</div>`;
    } else {
      try {
        const result = await consultarNumeroReservable(numero);
        quick = result.available
          ? `<div class="quick-result good"><div class="quick-number">${esc(numero)}</div><strong>DISPONIBLE</strong><br>${esc(result.quantity)} décimo(s) disponibles para venta/reserva.${result.reserved ? ` <span class="stock-line">(${esc(result.reserved)} reservado(s) pendientes sobre ${esc(result.source_quantity)} en stock)</span>` : ""}</div>`
          : `<div class="quick-result bad"><div class="quick-number">${esc(numero)}</div><strong>NO DISPONIBLE</strong><br>Ahora mismo no consta disponibilidad.</div>`;
      } catch (error) {
        quick = `<div class="quick-result bad"><strong>No se pudo consultar.</strong><br>${esc(error.message)}</div>`;
      }
    }
  }

  try {
    const panelState = loadPanelState();
    const calls = applyWorkflow(await loadRecentCallCards(50), panelState);
    const today = todayMadridKey();
    const todayCalls = calls.filter((c) => madridDayKey(c.at) === today);
    const pending = calls.filter((c) => c.workflow === "pendiente");
    const callbacks = pending.filter((c) => c.devolver_llamada);
    const purchases = todayCalls.filter((c) => c.intencion_compra);
    const incidents = todayCalls.filter(isIncident);
    const activeReservations = Object.values(panelState.reservations || {}).filter((r) => reservationEffectiveStatus(r) === "pendiente");

    const pendingRows = pending.slice(0, 6).map((c) => `<div class="pending-item"><div><strong>${esc(c.telefono)}</strong><div class="small">${esc(c.motivo || c.titulo || "Llamada")} · ${esc(formatDate(c.at))}</div></div><a href="/calls/${encodeURIComponent(c.id)}">Abrir</a></div>`).join("");

    res.send(layout("Inicio", `
      <h1>Panel de Búho</h1>
      <div class="sub">Centro operativo de llamadas, clientes y consultas de lotería.</div>
      <div class="today-strip"><strong>HOY</strong><span>${todayCalls.length} llamadas</span><span class="today-dot">•</span><span>${purchases.length} compras</span><span class="today-dot">•</span><span>${pending.length} pendientes</span><span class="today-dot">•</span><span>${incidents.length} incidencias</span><span class="today-dot">•</span><span>${activeReservations.length} reservas pendientes</span></div>

      <div class="panel">
        <h2>Consulta rápida de Lotería de Navidad</h2>
        <form class="quick" method="get" action="/">
          <input name="numero" inputmode="numeric" maxlength="5" pattern="[0-9]{5}" value="${esc(numero)}" placeholder="00042" required>
          <button class="btn" type="submit">Consultar</button>
        </form>
        ${quick}
      </div>

      <div class="cards">
        <div class="card"><div class="metric">${todayCalls.length}</div><div class="label">Llamadas de hoy</div></div>
        <div class="card"><div class="metric">${pending.length}</div><div class="label">Pendientes de gestión</div></div>
        <div class="card"><div class="metric">${callbacks.length}</div><div class="label">Devolver llamada</div></div>
        <div class="card"><div class="metric">${purchases.length}</div><div class="label">Intenciones de compra hoy</div></div>
        <div class="card"><div class="metric">${activeReservations.length}</div><div class="label">Reservas pendientes de recoger</div></div>
      </div>

      <div class="dashboard-grid">
        <div class="panel"><h2>Pendientes prioritarios</h2>${pendingRows || '<div class="small">No hay gestiones pendientes entre las últimas 50 llamadas.</div>'}<p style="margin:14px 0 0"><a class="btn secondary" href="/calls?f=pendientes">Ver todos los pendientes</a></p></div>
        <div class="panel"><h2>Hoy</h2><div class="pending-list"><div class="pending-item"><span>Incidencias</span><strong>${incidents.length}</strong></div><div class="pending-item"><span>Transferidas</span><strong>${todayCalls.filter((c) => c.transferida).length}</strong></div><div class="pending-item"><span>Empresas / asociaciones</span><strong>${todayCalls.filter((c) => Boolean(c.empresa_asociacion)).length}</strong></div><div class="pending-item"><span>Peticiones de Borja</span><strong>${todayCalls.filter((c) => c.pidio_borja).length}</strong></div></div><p style="margin:14px 0 0"><a class="btn secondary" href="/resumen">Abrir resumen completo</a></p></div>
      </div>

      <div class="storage-warning">${PANEL_STORAGE_PERSISTENT ? "Estados y notas: almacenamiento compartido configurado." : "Estados y notas se comparten entre los equipos mientras el servicio está activo. Para conservarlos también tras reinicios/despliegues de Render, configuraremos un disco persistente mediante BUHO_DATA_DIR."}</div>
    `, "home", req.csrf));
  } catch (error) {
    res.status(502).send(layout("Error", `<h1>No se pudo cargar ElevenLabs</h1><div class="notice error">${esc(error.message)}</div>`, "home", req.csrf));
  }
});

app.get("/calls", requireAuth, async (req, res) => {
  try {
    const requestedLimit = Number(req.query.limit || 50);
    const limit = [30, 50, 100].includes(requestedLimit) ? requestedLimit : 50;
    const panelState = loadPanelState();
    const calls = applyWorkflow(await loadRecentCallCards(limit), panelState);

    const q = String(req.query.q || "").trim().toLowerCase();
    const filter = String(req.query.f || "todas").trim().toLowerCase();

    const matchesSearch = (call) => {
      if (!q) return true;
      return [
        formatDate(call.at), call.telefono, call.titulo, call.resumen, call.motivo,
        call.numeros, call.disponibilidad, call.empresa_asociacion,
        call.aviso_nombre, call.aviso_telefono, call.aviso_peticion, call.notes,
      ].some((v) => String(v || "").toLowerCase().includes(q));
    };

    const matchesFilter = (call) => {
      switch (filter) {
        case "pendientes": return call.workflow === "pendiente";
        case "compras": return call.intencion_compra;
        case "empresas": return Boolean(call.empresa_asociacion);
        case "borja": return call.pidio_borja;
        case "avisos": return call.devolver_llamada;
        case "incidencias": return isIncident(call);
        case "negativas": return String(call.sentimiento).toLowerCase() === "negative" || Number(call.frustracion) >= 0.30;
        case "transferidas": return call.transferida;
        case "cerradas": return call.workflow === "cerrada";
        default: return true;
      }
    };

    const visible = calls.filter((call) => matchesSearch(call) && matchesFilter(call));
    const counts = {
      todas: calls.length,
      pendientes: calls.filter((c) => c.workflow === "pendiente").length,
      compras: calls.filter((c) => c.intencion_compra).length,
      empresas: calls.filter((c) => Boolean(c.empresa_asociacion)).length,
      borja: calls.filter((c) => c.pidio_borja).length,
      avisos: calls.filter((c) => c.devolver_llamada).length,
      incidencias: calls.filter(isIncident).length,
      negativas: calls.filter((c) => String(c.sentimiento).toLowerCase() === "negative" || Number(c.frustracion) >= 0.30).length,
      transferidas: calls.filter((c) => c.transferida).length,
      cerradas: calls.filter((c) => c.workflow === "cerrada").length,
    };

    const filterLink = (key, label) => {
      const params = new URLSearchParams();
      if (key !== "todas") params.set("f", key);
      if (q) params.set("q", q);
      if (limit !== 50) params.set("limit", String(limit));
      const href = params.toString() ? `/calls?${params}` : "/calls";
      return `<a class="filter ${filter === key ? "active" : ""}" href="${href}">${esc(label)} · ${esc(counts[key] ?? 0)}</a>`;
    };

    const currentPath = `/calls?${new URLSearchParams(Object.fromEntries(Object.entries({ f: filter !== "todas" ? filter : "", q: String(req.query.q || ""), limit: String(limit) }).filter(([,v]) => v))).toString()}`.replace(/\?$/, "");

    const cards = visible.map((call) => {
      const tags = [];
      if (call.numeros) tags.push(tag(call.numeros, "number"));
      if ((call.reservations || []).some((r) => reservationEffectiveStatus(r) === "pendiente")) tags.push(tag("RESERVA ACTIVA", "reservation"));
      if (call.intencion_compra) tags.push(tag("INTENCIÓN DE COMPRA", "buy"));
      if (call.empresa_asociacion) tags.push(tag("EMPRESA / ASOCIACIÓN", "company"));
      if (call.pidio_borja) tags.push(tag("PIDE BORJA", "borja"));
      if (call.devolver_llamada) tags.push(tag("DEVOLVER LLAMADA", "alert"));
      if (call.transferida) tags.push(tag("TRANSFERIDA", "transfer"));

      const sentiment = sentimentText(call.sentimiento);
      const frustration = Number(call.frustracion);
      const negative = String(call.sentimiento).toLowerCase() === "negative" || (Number.isFinite(frustration) && frustration >= 0.60);
      const priority = call.workflow === "pendiente" || call.devolver_llamada || call.intencion_compra || call.pidio_borja || call.empresa_asociacion;

      const dataCells = [
        call.disponibilidad ? `<div><div class="label">Disponibilidad</div><div class="value">${esc(call.disponibilidad)}</div></div>` : "",
        call.cantidad ? `<div><div class="label">Cantidad solicitada</div><div class="value">${esc(call.cantidad)} décimo(s)</div></div>` : "",
        call.empresa_asociacion ? `<div><div class="label">Entidad</div><div class="value">${esc(call.empresa_asociacion)}</div></div>` : "",
        sentiment ? `<div><div class="label">Sentimiento estimado</div><div class="value">${esc(sentiment)}${Number.isFinite(frustration) ? ` · frustración ${esc(Math.round(frustration * 100))}%` : ""}</div></div>` : "",
      ].filter(Boolean).join("");

      const notice = call.devolver_llamada
        ? `<div class="notice" style="margin:12px 0 0"><strong>Devolver llamada</strong>${call.aviso_nombre ? ` · ${esc(call.aviso_nombre)}` : ""}${call.aviso_telefono ? ` · ${esc(call.aviso_telefono)}` : ""}${call.aviso_peticion ? `<br>${esc(call.aviso_peticion)}` : ""}</div>`
        : "";

      const history = phoneDigits(call.telefono) ? `<a class="btn tiny outline" href="/clientes/${encodeURIComponent(phoneDigits(call.telefono))}">Historial</a>` : "";

      return `<article class="call-card ${negative ? "negative" : priority ? "priority" : ""}">
        <div class="call-head"><div><div class="call-time">${esc(formatDate(call.at))}</div><div class="call-phone">${esc(call.telefono)}</div><div class="call-duration">${esc(duration(call.duracion))}</div></div><span class="workflow-badge workflow-${esc(call.workflow)}">${esc(workflowLabel(call.workflow))}</span></div>
        <div class="call-tags">${tags.join("")}</div>
        <div class="call-motive">${esc(call.motivo || call.titulo || "Llamada")}</div>
        <div class="call-summary">${esc(call.resumen || "Sin resumen")}</div>
        ${dataCells ? `<div class="call-data">${dataCells}</div>` : ""}
        ${notice}
        ${call.notes ? `<div class="notes-preview"><strong>Nota interna</strong><br>${esc(call.notes)}</div>` : ""}

        <div class="call-footer">
          <div class="call-actions"><a class="btn tiny secondary" href="/calls/${encodeURIComponent(call.id)}">Abrir</a>${phoneActions(call.telefono)}${history}<form method="post" action="/calls/${encodeURIComponent(call.id)}/reprint" style="display:inline"><input type="hidden" name="_csrf" value="${esc(req.csrf)}"><input type="hidden" name="return_to" value="${esc(currentPath)}"><button class="btn tiny outline" type="submit">Reimprimir</button></form></div>
          <form class="manage-form" method="post" action="/calls/${encodeURIComponent(call.id)}/manage">
            <input type="hidden" name="_csrf" value="${esc(req.csrf)}"><input type="hidden" name="return_to" value="${esc(currentPath)}">
            <div><div class="small">Estado</div><select name="state" aria-label="Estado de gestión">${["nueva","pendiente","atendida","cerrada"].map((st) => `<option value="${st}" ${call.workflow === st ? "selected" : ""}>${esc(workflowLabel(st))}</option>`).join("")}</select></div>
            <div><div class="small">Nota interna</div><textarea class="note-input" name="notes" maxlength="2000" placeholder="Ej.: Llamado a las 13:20; vuelve por la tarde">${esc(call.notes)}</textarea></div>
            <button class="btn" type="submit">Guardar</button>
          </form>
        </div>
      </article>`;
    }).join("");

    const queryValue = esc(String(req.query.q || ""));
    const filters = [
      filterLink("todas", "Todas"), filterLink("pendientes", "Pendientes"), filterLink("compras", "Compras"),
      filterLink("empresas", "Empresas"), filterLink("borja", "Borja"), filterLink("avisos", "Avisos"),
      filterLink("incidencias", "Incidencias"), filterLink("negativas", "Negativas"), filterLink("transferidas", "Transferidas"), filterLink("cerradas", "Cerradas"),
    ].join("");

    const flash = req.query.reprint ? '<div class="notice ok">Reimpresión enviada a la cola de Búho Print.</div>' : req.query.saved ? '<div class="notice ok">Estado y nota guardados.</div>' : "";

    res.send(layout("Llamadas", `
      <h1>Fichas de llamadas</h1>
      <div class="sub">Hasta ${limit} conversaciones recientes. Puedes mostrar 30, 50 o 100.</div>
      ${flash}
      <div class="call-toolbar">
        <form class="call-search" method="get" action="/calls">${filter !== "todas" ? `<input type="hidden" name="f" value="${esc(filter)}">` : ""}<input type="hidden" name="limit" value="${limit}"><input name="q" value="${queryValue}" placeholder="Buscar teléfono, fecha, número, empresa, nombre, nota o texto…"><button class="btn" type="submit">Buscar</button>${q ? '<a class="btn secondary" href="/calls">Limpiar</a>' : ""}</form>
        <form class="limit-form" method="get" action="/calls">${filter !== "todas" ? `<input type="hidden" name="f" value="${esc(filter)}">` : ""}${q ? `<input type="hidden" name="q" value="${queryValue}">` : ""}<span class="small">Mostrar</span><select name="limit">${[30,50,100].map((n) => `<option value="${n}" ${n === limit ? "selected" : ""}>${n}</option>`).join("")}</select><button class="btn tiny secondary" type="submit">Aplicar</button></form>
        <span class="countline">${visible.length} ficha(s) visibles</span>
      </div>
      <div class="filters">${filters}</div>
      <div class="call-grid">${cards || '<div class="panel empty">No hay llamadas que coincidan con este filtro o búsqueda.</div>'}</div>
      <div class="storage-warning">${PANEL_STORAGE_PERSISTENT ? "Estados y notas compartidos mediante BUHO_DATA_DIR." : "Los estados y notas ya se guardan en el servidor y se ven desde otros equipos. Falta añadir un disco persistente de Render para garantizar que sobrevivan a reinicios y nuevos despliegues."}</div>
    `, "calls", req.csrf));
  } catch (error) {
    res.status(502).send(layout("Llamadas", `<h1>Fichas de llamadas</h1><div class="notice error">${esc(error.message)}</div>`, "calls", req.csrf));
  }
});

app.post("/calls/:id/manage", requireAuth, verifyCsrf, (req, res) => {
  const id = String(req.params.id || "").trim();
  const state = String(req.body.state || "").trim().toLowerCase();
  const notes = String(req.body.notes || "").trim().slice(0, 2000);
  if (!id || !CALL_STATES.has(state)) return res.status(400).send("Estado no válido.");

  const panelState = loadPanelState();
  panelState.calls[id] = { state, notes, updated_at: Date.now() };
  savePanelState(panelState);
  res.redirect(`${safeReturnPath(req.body.return_to, "/calls")}${safeReturnPath(req.body.return_to, "/calls").includes("?") ? "&" : "?"}saved=1`);
});

// Compatibilidad con la primera versión de las fichas.
app.post("/calls/:id/state", requireAuth, verifyCsrf, (req, res) => {
  const id = String(req.params.id || "").trim();
  const state = String(req.body.state || "").trim().toLowerCase();
  if (!id || !CALL_STATES.has(state)) return res.status(400).send("Estado no válido.");
  const panelState = loadPanelState();
  const previous = managedCallRecord(panelState, id);
  panelState.calls[id] = { state, notes: String(previous.notes || ""), updated_at: Date.now() };
  savePanelState(panelState);
  res.redirect("/calls?saved=1");
});

app.post("/calls/:id/reprint", requireAuth, verifyCsrf, (req, res) => {
  const id = String(req.params.id || "").trim();
  if (!id) return res.status(400).send("Llamada no válida.");
  const panelState = loadPanelState();
  const now = Date.now();
  panelState.reprints = panelState.reprints.filter((r) => !r.acked_at && now - Number(r.created_at || 0) < 7 * 86400000);
  panelState.reprints.push({ queue_id: crypto.randomUUID(), conversation_id: id, created_at: now, acked_at: null });
  savePanelState(panelState);
  const back = safeReturnPath(req.body.return_to, "/calls");
  res.redirect(`${back}${back.includes("?") ? "&" : "?"}reprint=1`);
});

app.get("/calls/:id", requireAuth, async (req, res) => {
  try {
    const rawId = String(req.params.id || "");
    const id = encodeURIComponent(rawId);
    const [summary, detail] = await Promise.all([
      eleven(`/convai/conversations/${id}/summary?max_messages=100`),
      eleven(`/convai/conversations/${id}`),
    ]);
    let messages = Array.isArray(summary.messages) && summary.messages.length && !summary.messages_omitted ? summary.messages : null;
    if (!messages && Array.isArray(detail.transcript)) messages = detail.transcript.map((m) => ({ role: m.role, message: m.message || m.text || "" }));
    const transcript = (messages || []).map((m) => `<div class="msg ${m.role === "agent" ? "agent" : "user"}"><div class="small">${m.role === "agent" ? "Búho" : "Cliente"}</div>${esc(m.message || "")}</div>`).join("");
    const meta = detail.metadata || {};
    const analysis = detail.analysis || {};
    const collected = analysis.data_collection_results || {};
    const title = summary.call_summary_title || analysis.call_summary_title || "Detalle de llamada";
    const text = summary.transcript_summary || analysis.transcript_summary || "Todavía no hay resumen disponible.";
    const stateEval = summary.call_successful || analysis.call_successful || detail.status;
    const cost = meta.cost_fiat ?? meta.cost ?? "—";
    const phone = detail.user_id || meta.phone_call?.external_number || meta.phone_call?.caller_id || "Número no disponible";
    const panelState = loadPanelState();
    const record = managedCallRecord(panelState, rawId);
    const workflow = CALL_STATES.has(record.state) ? record.state : defaultWorkflow({
      devolver_llamada: boolValue(collected.devolver_llamada) || Boolean(pickValue(collected.aviso_nombre) || pickValue(collected.aviso_telefono)),
      pidio_borja: boolValue(collected.pidio_borja), intencion_compra: boolValue(collected.intencion_compra), empresa_asociacion: pickValue(collected.empresa_asociacion),
    });
    const notes = String(record.notes || "");
    const historyButton = phoneDigits(phone) ? `<a class="btn secondary" href="/clientes/${encodeURIComponent(phoneDigits(phone))}">Historial del cliente</a>` : "";

    res.send(layout("Detalle de llamada", `
      <p><a href="/calls">← Volver a llamadas</a></p><h1>${esc(title)}</h1><div class="sub">${esc(formatDate(meta.start_time_unix_secs))} · ${esc(duration(meta.call_duration_secs))} · ${esc(phone)}</div>
      <div class="actions" style="margin-bottom:18px">${phoneActions(phone)}${historyButton}<form method="post" action="/calls/${id}/reprint"><input type="hidden" name="_csrf" value="${esc(req.csrf)}"><input type="hidden" name="return_to" value="/calls/${esc(rawId)}"><button class="btn outline" type="submit">Reimprimir ticket</button></form></div>
      <div class="cards"><div class="card"><div class="label">Gestión</div><strong>${esc(workflowLabel(workflow))}</strong></div><div class="card"><div class="label">Evaluación</div><strong>${esc(statusText(stateEval))}</strong></div><div class="card"><div class="label">Mensajes</div><strong>${esc(summary.message_count ?? "—")}</strong></div><div class="card"><div class="label">Coste reportado</div><strong>${esc(cost)}</strong></div></div>
      <div class="panel"><h2>Gestión interna</h2><form method="post" action="/calls/${id}/manage"><input type="hidden" name="_csrf" value="${esc(req.csrf)}"><input type="hidden" name="return_to" value="/calls/${esc(rawId)}"><div class="field"><label>Estado</label><select name="state">${["nueva","pendiente","atendida","cerrada"].map((st) => `<option value="${st}" ${workflow === st ? "selected" : ""}>${esc(workflowLabel(st))}</option>`).join("")}</select></div><div class="field"><label>Nota interna</label><textarea class="note-input" name="notes" maxlength="2000" placeholder="Anotaciones de seguimiento">${esc(notes)}</textarea></div><button class="btn" type="submit">Guardar gestión</button></form></div>
      <div class="panel" style="margin-top:16px"><h2>Resumen</h2><p>${esc(text)}</p></div>
      <div class="panel" style="margin-top:16px"><h2>Conversación</h2><div class="transcript">${transcript || "<p>No hay transcripción disponible.</p>"}</div></div>
    `, "calls", req.csrf));
  } catch (error) {
    res.status(502).send(layout("Detalle", `<h1>No se pudo abrir la conversación</h1><div class="notice error">${esc(error.message)}</div>`, "calls", req.csrf));
  }
});


// --------------------------------------------------------------------------
// RESERVAS: gestión de reservas de décimos para recogida en administración.
// --------------------------------------------------------------------------
app.get("/reservas", requireAuth, async (req, res) => {
  const state = loadPanelState();
  const q = String(req.query.q || "").trim().toLowerCase();
  const filter = String(req.query.f || "pendientes").trim().toLowerCase();
  const all = Object.values(state.reservations || {}).filter(Boolean).sort((a,b) => Number(b.created_at || 0) - Number(a.created_at || 0));
  const enriched = all.map((r) => ({ ...r, effective_status: reservationEffectiveStatus(r) }));
  const visible = enriched.filter((r) => {
    if (filter !== "todas" && filter !== r.effective_status && !(filter === "pendientes" && r.effective_status === "pendiente")) return false;
    if (!q) return true;
    return [r.id, r.number, r.customer_name, r.customer_phone, r.notes].some((v) => String(v || "").toLowerCase().includes(q));
  });

  const counts = { pendiente:0, recogida:0, cancelada:0, caducada:0 };
  for (const r of enriched) counts[r.effective_status] = (counts[r.effective_status] || 0) + 1;
  const flash = req.query.created ? '<div class="notice ok">Reserva creada y vale enviado a la cola de impresión.</div>'
    : req.query.saved ? '<div class="notice ok">Reserva actualizada.</div>'
    : req.query.reprint ? '<div class="notice ok">Reimpresión del vale enviada a Búho Print.</div>' : "";

  const tabs = [
    ["pendientes", `Pendientes (${counts.pendiente})`], ["recogida", `Recogidas (${counts.recogida})`],
    ["caducada", `Caducadas (${counts.caducada})`], ["cancelada", `Canceladas (${counts.cancelada})`], ["todas", `Todas (${enriched.length})`]
  ].map(([key,label]) => `<a class="filter ${filter === key ? "active" : ""}" href="/reservas?f=${key}${q ? `&q=${encodeURIComponent(q)}` : ""}">${esc(label)}</a>`).join("");

  const cards = visible.map((r) => {
    const status = r.effective_status;
    const canClose = status === "pendiente";
    const phone = phoneActions(r.customer_phone);
    return `<article class="reservation-card ${status === "recogida" ? "done" : status === "cancelada" ? "cancelled" : status === "caducada" ? "expired" : ""}">
      <div class="reservation-head"><div><div class="reservation-id">${esc(r.id)} · ${esc(formatDate(Math.round(Number(r.created_at || 0)/1000)))}</div><div class="reservation-number">${esc(r.number)}</div></div><span class="reservation-status ${esc(status)}">${esc(reservationStatusLabel(status))}</span></div>
      <div class="reservation-name">${esc(r.customer_name)}</div>
      <div class="small">${esc(r.customer_phone)} · ${esc(r.quantity)} décimo(s)</div>
      <div class="reservation-deadline">Recoger antes del cierre del ${esc(formatDayKeyEs(r.expires_date))}</div>
      <div class="call-data"><div><div class="label">Pago</div><div class="value">Al recoger</div></div><div><div class="label">Origen</div><div class="value">${r.created_by === "panel" ? "Panel" : "Búho Voz"}</div></div></div>
      ${r.notes ? `<div class="notes-preview"><strong>Nota interna</strong><br>${esc(r.notes)}</div>` : ""}
      <div class="reservation-actions">${phone}<form method="post" action="/reservas/${encodeURIComponent(r.id)}/reprint"><input type="hidden" name="_csrf" value="${esc(req.csrf)}"><button class="btn tiny outline" type="submit">Reimprimir vale</button></form>${canClose ? `<form method="post" action="/reservas/${encodeURIComponent(r.id)}/status"><input type="hidden" name="_csrf" value="${esc(req.csrf)}"><input type="hidden" name="status" value="recogida"><button class="btn tiny" type="submit">Marcar recogida</button></form><form method="post" action="/reservas/${encodeURIComponent(r.id)}/status"><input type="hidden" name="_csrf" value="${esc(req.csrf)}"><input type="hidden" name="status" value="cancelada"><button class="btn tiny secondary" type="submit">Cancelar</button></form>` : ""}</div>
    </article>`;
  }).join("");

  const persistence = PANEL_STORAGE_PERSISTENT
    ? '<div class="notice ok">Almacenamiento persistente activo: las reservas están habilitadas.</div>'
    : '<div class="notice error"><strong>Reservas todavía bloqueadas.</strong> Antes de usarlas con clientes hay que activar el disco persistente de Render y BUHO_DATA_DIR=/var/data. Así una reserva nunca puede desaparecer por un reinicio o deploy.</div>';

  res.send(layout("Reservas", `<h1>Reservas</h1><div class="sub">Décimos reservados por teléfono o desde el panel para recogida y pago en la administración. Plazo: ${RESERVATION_DAYS} días naturales.</div>${flash}${persistence}
    <div class="panel"><h2>Nueva reserva manual</h2><form class="reservation-form" method="post" action="/reservas/create"><input type="hidden" name="_csrf" value="${esc(req.csrf)}"><div class="field"><label>Número</label><input name="number" maxlength="5" pattern="[0-9]{5}" placeholder="00042" required></div><div class="field"><label>Décimos</label><input name="quantity" type="number" min="1" max="100" value="1" required></div><div class="field"><label>Nombre</label><input name="customer_name" required></div><div class="field"><label>Teléfono</label><input name="customer_phone" required></div><button class="btn" type="submit" ${PANEL_STORAGE_PERSISTENT ? "" : "disabled"}>Crear reserva</button></form><div class="reservation-note">No se cobra nada al crearla. El cliente paga al recogerla. El sistema descuenta las reservas pendientes de la disponibilidad que ve Búho.</div></div>
    <div class="reservation-toolbar"><form method="get" action="/reservas"><input type="hidden" name="f" value="${esc(filter)}"><input name="q" value="${esc(req.query.q || "")}" placeholder="Buscar por reserva, número, nombre o teléfono"><button class="btn" type="submit">Buscar</button></form>${q ? '<a class="btn secondary" href="/reservas">Limpiar</a>' : ""}</div>
    <div class="filters">${tabs}</div><div class="reservation-grid">${cards || '<div class="panel empty">No hay reservas con este filtro.</div>'}</div>`, "reservas", req.csrf));
});

app.post("/reservas/create", requireAuth, verifyCsrf, async (req, res) => {
  try {
    await withReservationLock(() => createReservationRecord({ ...req.body, created_by: "panel" }));
    res.redirect("/reservas?created=1");
  } catch (error) {
    res.status(400).send(layout("Reserva no creada", `<h1>No se pudo crear la reserva</h1><div class="notice error">${esc(error.message)}</div><p><a class="btn secondary" href="/reservas">Volver a reservas</a></p>`, "reservas", req.csrf));
  }
});

app.post("/reservas/:id/status", requireAuth, verifyCsrf, (req, res) => {
  const id = String(req.params.id || "");
  const status = String(req.body.status || "").toLowerCase();
  if (!RESERVATION_STATES.has(status)) return res.status(400).send("Estado de reserva no válido.");
  const state = loadPanelState();
  const r = state.reservations?.[id];
  if (!r) return res.status(404).send("Reserva no encontrada.");
  r.status = status; r.updated_at = Date.now();
  savePanelState(state);
  res.redirect("/reservas?saved=1");
});

app.post("/reservas/:id/reprint", requireAuth, verifyCsrf, (req, res) => {
  const id = String(req.params.id || "");
  const state = loadPanelState();
  const r = state.reservations?.[id];
  if (!r) return res.status(404).send("Reserva no encontrada.");
  queueReservationPrint(state, r, "reprint");
  savePanelState(state);
  res.redirect("/reservas?reprint=1");
});

app.get("/clientes", requireAuth, async (req, res) => {
  try {
    const panelState = loadPanelState();
    const calls = applyWorkflow(await loadRecentCallCards(100), panelState);
    const groups = new Map();
    for (const call of calls) {
      const digits = phoneDigits(call.telefono);
      if (!digits) continue;
      if (!groups.has(digits)) groups.set(digits, { digits, telefono: call.telefono, calls: [] });
      groups.get(digits).calls.push(call);
    }
    const customers = [...groups.values()].sort((a,b) => Number(b.calls[0]?.at || 0) - Number(a.calls[0]?.at || 0));
    const cards = customers.map((c) => {
      const purchases = c.calls.filter((x) => x.intencion_compra).length;
      const pending = c.calls.filter((x) => x.workflow === "pendiente").length;
      return `<div class="customer-card"><div class="customer-phone">${esc(c.telefono)}</div><div class="small">Última: ${esc(formatDate(c.calls[0]?.at))}</div><div class="call-data"><div><div class="label">Llamadas</div><div class="value">${c.calls.length}</div></div><div><div class="label">Compras</div><div class="value">${purchases}</div></div><div><div class="label">Pendientes</div><div class="value">${pending}</div></div></div><div class="actions">${phoneActions(c.telefono)}<a class="btn tiny" href="/clientes/${encodeURIComponent(c.digits)}">Ver historial</a></div></div>`;
    }).join("");
    res.send(layout("Clientes", `<h1>Clientes</h1><div class="sub">Agrupación por teléfono dentro de las 100 llamadas más recientes.</div><div class="customer-grid">${cards || '<div class="panel">No hay teléfonos identificados.</div>'}</div>`, "clientes", req.csrf));
  } catch (error) {
    res.status(502).send(layout("Clientes", `<h1>Clientes</h1><div class="notice error">${esc(error.message)}</div>`, "clientes", req.csrf));
  }
});

app.get("/clientes/:phone", requireAuth, async (req, res) => {
  try {
    const target = phoneDigits(req.params.phone);
    const panelState = loadPanelState();
    const calls = applyWorkflow(await loadRecentCallCards(100), panelState).filter((c) => phoneDigits(c.telefono) === target);
    const displayPhone = calls[0]?.telefono || req.params.phone;
    const rows = calls.map((c) => `<tr><td>${esc(formatDate(c.at))}</td><td>${esc(c.motivo || c.titulo || "Llamada")}</td><td>${esc(c.numeros || "—")}</td><td>${esc(workflowLabel(c.workflow))}</td><td class="summary">${esc(c.resumen)}</td><td><a href="/calls/${encodeURIComponent(c.id)}">Abrir</a></td></tr>`).join("");
    res.send(layout("Historial de cliente", `<p><a href="/clientes">← Volver a clientes</a></p><h1>${esc(displayPhone)}</h1><div class="sub">Historial encontrado dentro de las 100 llamadas más recientes.</div><p class="actions">${phoneActions(displayPhone)}</p><div class="panel" style="overflow:auto"><table><thead><tr><th>Fecha</th><th>Motivo</th><th>Número</th><th>Gestión</th><th>Resumen</th><th></th></tr></thead><tbody>${rows || '<tr><td colspan="6">No hay llamadas recientes para este teléfono.</td></tr>'}</tbody></table></div>`, "clientes", req.csrf));
  } catch (error) {
    res.status(502).send(layout("Historial", `<h1>Historial de cliente</h1><div class="notice error">${esc(error.message)}</div>`, "clientes", req.csrf));
  }
});

app.get("/resumen", requireAuth, async (req, res) => {
  try {
    const requestedDays = Number(req.query.dias || 7);
    const days = [7, 14, 30].includes(requestedDays) ? requestedDays : 7;
    const panelState = loadPanelState();
    const calls = applyWorkflow(await loadRecentCallCards(100), panelState);

    // Dos ventanas consecutivas del mismo tamaño: periodo actual y periodo anterior.
    const allKeys = madridDateKeys(days * 2);
    const previousKeys = allKeys.slice(0, days);
    const keys = allKeys.slice(days);
    const keySet = new Set(keys);
    const previousKeySet = new Set(previousKeys);
    const periodCalls = calls.filter((call) => keySet.has(madridDayKey(call.at)));
    const previousCalls = calls.filter((call) => previousKeySet.has(madridDayKey(call.at)));

    const todayKey = todayMadridKey();
    const today = calls.filter((call) => madridDayKey(call.at) === todayKey);

    const byDay = new Map(keys.map((key) => [key, []]));
    for (const call of periodCalls) {
      const key = madridDayKey(call.at);
      if (byDay.has(key)) byDay.get(key).push(call);
    }

    const daily = keys.map((key) => {
      const dayCalls = byDay.get(key) || [];
      const unresolved = dayCalls.filter(isUnresolved).length;
      const resolved = dayCalls.filter(isResolved).length;
      const evaluated = resolved + unresolved;
      return {
        key,
        label: shortMadridDayLabel(key, days > 14),
        llamadas: dayCalls.length,
        resueltas: resolved,
        no_resueltas: unresolved,
        sin_evaluar: Math.max(0, dayCalls.length - evaluated),
        nuevas: dayCalls.filter((call) => call.workflow === "nueva").length,
        pendientes: dayCalls.filter((call) => call.workflow === "pendiente").length,
        atendidas: dayCalls.filter((call) => call.workflow === "atendida").length,
        cerradas: dayCalls.filter((call) => call.workflow === "cerrada").length,
        compras: dayCalls.filter((call) => call.intencion_compra).length,
        transferidas: dayCalls.filter((call) => call.transferida).length,
        incidencias: dayCalls.filter(isIncident).length,
      };
    });

    // Horas punta: se ordenan por volumen, no por reloj, para que sirvan como ranking operativo.
    const hourly = Array.from({ length: 24 }, (_, hour) => ({ hour, label: `${String(hour).padStart(2, "0")} h`, value: 0 }));
    for (const call of periodCalls) {
      const hour = madridHour(call.at);
      if (hour !== null && hourly[hour]) hourly[hour].value += 1;
    }
    const peakHours = hourly.filter((row) => row.value > 0).sort((a,b) => b.value - a.value || a.hour - b.hour).slice(0, 8);
    const peak = peakHours[0] || null;

    const topNumbers = countTop(periodCalls.flatMap((call) => splitLotteryNumbers(call.numeros)), 10);
    const topMotives = countTop(periodCalls.map((call) => call.motivo || call.titulo || "Otro"), 8);
    const motiveRows = topMotives.map(([n,c]) => `<li><span>${esc(n)}</span><strong>${c}</strong></li>`).join("");

    const resolved = periodCalls.filter(isResolved).length;
    const unresolved = periodCalls.filter(isUnresolved).length;
    const attended = periodCalls.filter((call) => call.workflow === "atendida").length;
    const closed = periodCalls.filter((call) => call.workflow === "cerrada").length;
    const pending = periodCalls.filter((call) => call.workflow === "pendiente").length;
    const purchases = periodCalls.filter((call) => call.intencion_compra).length;
    const transfers = periodCalls.filter((call) => call.transferida).length;
    const incidents = periodCalls.filter(isIncident).length;
    const callbacks = periodCalls.filter((c) => c.devolver_llamada).length;
    const companies = periodCalls.filter((c) => Boolean(c.empresa_asociacion)).length;
    const tense = periodCalls.filter((c) => String(c.sentimiento).toLowerCase() === "negative" || Number(c.frustracion) >= .3).length;
    const evaluated = resolved + unresolved;
    const resolutionRate = evaluated ? metricPercent(resolved, evaluated) : 0;

    const prevResolved = previousCalls.filter(isResolved).length;
    const prevUnresolved = previousCalls.filter(isUnresolved).length;
    const prevEvaluated = prevResolved + prevUnresolved;
    const prevResolutionRate = prevEvaluated ? metricPercent(prevResolved, prevEvaluated) : 0;
    const prevAttended = previousCalls.filter((c) => c.workflow === "atendida").length;
    const prevPending = previousCalls.filter((c) => c.workflow === "pendiente").length;
    const prevPurchases = previousCalls.filter((c) => c.intencion_compra).length;
    const prevIncidents = previousCalls.filter(isIncident).length;

    const callsTrend = relativeChange(periodCalls.length, previousCalls.length);
    const resolutionTrend = pointChange(resolutionRate, prevResolutionRate);
    const attendedTrend = relativeChange(attended, prevAttended);
    const pendingTrend = relativeChange(pending, prevPending);
    const purchasesTrend = relativeChange(purchases, prevPurchases);
    const incidentsTrend = relativeChange(incidents, prevIncidents);

    const oldestAvailableKey = calls.length
      ? madridDayKey(Math.min(...calls.map((c) => Number(c.at || 0)).filter((n) => n > 0)))
      : "";
    const comparisonIncomplete = calls.length >= 100 && oldestAvailableKey && oldestAvailableKey > previousKeys[0];
    const currentIncomplete = calls.length >= 100 && oldestAvailableKey && oldestAvailableKey > keys[0];

    const periodTabs = [7, 14, 30].map((value) => `<a class="period-tab ${days === value ? "active" : ""}" href="/resumen?dias=${value}">${value} días</a>`).join("");

    const callsChart = renderGroupedChart(
      "Llamadas por día",
      `Volumen diario durante los últimos ${days} días`,
      daily,
      [{ key: "llamadas", label: "Llamadas" }]
    );

    const resolutionChart = renderGroupedChart(
      "Resolución de consultas",
      "Evaluación de ElevenLabs: no equivale al estado interno de gestión",
      daily,
      [
        { key: "resueltas", label: "Resueltas" },
        { key: "no_resueltas", label: "No resueltas" },
        { key: "sin_evaluar", label: "Sin evaluar" },
      ]
    );

    const workflowChart = renderGroupedChart(
      "Gestión interna",
      "Estado asignado en Búho Panel",
      daily,
      [
        { key: "nuevas", label: "Nuevas" },
        { key: "pendientes", label: "Pendientes" },
        { key: "atendidas", label: "Atendidas" },
        { key: "cerradas", label: "Cerradas" },
      ]
    );

    const activityChart = renderGroupedChart(
      "Actividad comercial y operativa",
      "Señales detectadas en cada conversación",
      daily,
      [
        { key: "compras", label: "Compra" },
        { key: "transferidas", label: "Transferidas" },
        { key: "incidencias", label: "Incidencias" },
      ]
    );

    const hourChart = renderHorizontalChart(
      "Horas con más llamadas",
      `Top de franjas horarias durante los últimos ${days} días`,
      peakHours.length ? peakHours : [{ label: "Sin datos", value: 0 }]
    );

    const numberChart = renderRankBars(
      "Números más consultados",
      `Ranking de números de cinco cifras · últimos ${days} días`,
      topNumbers.map(([label, value]) => ({ label, value }))
    );

    const limitNotice = currentIncomplete
      ? `<div class="notice info">El periodo seleccionado supera el histórico que cabe en las <strong>100 conversaciones más recientes</strong>. Algunas cifras de los días más antiguos pueden estar incompletas.</div>`
      : "";
    const comparisonNotice = comparisonIncomplete
      ? `<div class="notice info">La comparación con el periodo anterior es orientativa: el histórico disponible de 100 llamadas no cubre por completo los ${days} días anteriores.</div>`
      : "";

    res.send(layout("Resumen", `
      <div class="summary-toolbar"><div><h1>Resumen de actividad</h1><div class="sub" style="margin-bottom:0">Cuadro de mando operativo de Búho Voz.</div></div><div class="actions">${peak ? `<span class="peak-chip">Hora punta: ${esc(peak.label)} · ${peak.value} llamada(s)</span>` : ""}<div class="period-tabs">${periodTabs}</div></div></div>
      ${limitNotice}${comparisonNotice}

      <div class="today-strip"><strong>HOY</strong><span class="today-dot">•</span><span>${today.length} llamadas</span><span class="today-dot">•</span><span>${today.filter(isResolved).length} resueltas</span><span class="today-dot">•</span><span>${today.filter((c) => c.intencion_compra).length} compras</span><span class="today-dot">•</span><span>${today.filter((c) => c.workflow === "pendiente").length} pendientes</span><span class="today-dot">•</span><span>${today.filter(isIncident).length} incidencias</span></div>

      <div class="summary-metrics">
        <div class="summary-metric brand"><div class="metric">${periodCalls.length}</div><div class="label">Llamadas · ${days} días</div><div class="metric-share">Periodo anterior: ${previousCalls.length}</div>${trendHtml(callsTrend)}</div>
        <div class="summary-metric ok"><div class="metric">${resolved}</div><div class="label">Resueltas</div><div class="metric-share">${resolutionRate}% de las evaluadas</div>${trendHtml(resolutionTrend)}</div>
        <div class="summary-metric"><div class="metric">${attended}</div><div class="label">Atendidas</div><div class="metric-share">${metricPercent(attended, periodCalls.length)}% de llamadas</div>${trendHtml(attendedTrend)}</div>
        <div class="summary-metric"><div class="metric">${pending}</div><div class="label">Pendientes</div><div class="metric-share">${metricPercent(pending, periodCalls.length)}% de llamadas</div>${trendHtml(pendingTrend)}</div>
        <div class="summary-metric blue"><div class="metric">${purchases}</div><div class="label">Intenciones de compra</div><div class="metric-share">${metricPercent(purchases, periodCalls.length)}% de llamadas</div>${trendHtml(purchasesTrend)}</div>
        <div class="summary-metric danger"><div class="metric">${incidents}</div><div class="label">Incidencias</div><div class="metric-share">${metricPercent(incidents, periodCalls.length)}% de llamadas</div>${trendHtml(incidentsTrend)}</div>
      </div>

      <section class="panel compare-panel"><div class="chart-head"><div><h2>Comparativa con el periodo anterior</h2><div class="small">Últimos ${days} días frente a los ${days} días inmediatamente anteriores</div></div></div><div class="compare-grid">
        <div class="compare-item"><div class="compare-title">Llamadas</div><div class="compare-values"><div class="compare-current">${periodCalls.length}</div><div class="compare-prev">antes<br><strong>${previousCalls.length}</strong></div></div>${trendHtml(callsTrend)}</div>
        <div class="compare-item"><div class="compare-title">Tasa de resolución</div><div class="compare-values"><div class="compare-current">${resolutionRate}%</div><div class="compare-prev">antes<br><strong>${prevResolutionRate}%</strong></div></div>${trendHtml(resolutionTrend)}</div>
        <div class="compare-item"><div class="compare-title">Compras detectadas</div><div class="compare-values"><div class="compare-current">${purchases}</div><div class="compare-prev">antes<br><strong>${prevPurchases}</strong></div></div>${trendHtml(purchasesTrend)}</div>
        <div class="compare-item"><div class="compare-title">Incidencias</div><div class="compare-values"><div class="compare-current">${incidents}</div><div class="compare-prev">antes<br><strong>${prevIncidents}</strong></div></div>${trendHtml(incidentsTrend)}</div>
      </div><div class="compare-note">Las flechas muestran variación estadística, no una valoración automática. Por ejemplo, que aumenten las llamadas puede ser positivo aunque aparezca como subida.</div></section>

      ${callsChart}
      <div class="charts-two">${resolutionChart}${workflowChart}</div>
      ${activityChart}

      <div class="charts-two">
        ${hourChart}
        ${numberChart}
      </div>

      <div class="charts-two">
        <section class="panel chart-panel"><div class="chart-head"><div><h2>Indicadores del periodo</h2><div class="small">Últimos ${days} días</div></div></div><div class="call-data">
          <div><div class="label">No resueltas</div><div class="value">${unresolved} · ${metricPercent(unresolved, evaluated)}% evaluadas</div></div>
          <div><div class="label">Cerradas</div><div class="value">${closed} · ${metricPercent(closed, periodCalls.length)}%</div></div>
          <div><div class="label">Transferidas</div><div class="value">${transfers} · ${metricPercent(transfers, periodCalls.length)}%</div></div>
          <div><div class="label">Devolver llamada</div><div class="value">${callbacks} · ${metricPercent(callbacks, periodCalls.length)}%</div></div>
          <div><div class="label">Empresas / asociaciones</div><div class="value">${companies} · ${metricPercent(companies, periodCalls.length)}%</div></div>
          <div><div class="label">Conversaciones tensas</div><div class="value">${tense} · ${metricPercent(tense, periodCalls.length)}%</div></div>
        </div><div class="metric-definition"><strong>Resuelta</strong> = ElevenLabs considera resuelta la consulta. <strong>Atendida</strong> = vosotros habéis gestionado la ficha en Búho Panel. Son métricas independientes.</div></section>
        <div class="panel"><h2>Motivos de llamada · ${days} días</h2><ol class="rank">${motiveRows || '<li><span>Sin datos</span></li>'}</ol></div>
      </div>

      <p class="chart-note">Las métricas y comparaciones se calculan con las conversaciones disponibles en Búho Panel. En intervalos largos, el límite actual de 100 conversaciones puede hacer que el periodo anterior sea parcial; el panel lo avisa cuando lo detecta.</p>
    `, "resumen", req.csrf));
  } catch (error) {
    res.status(502).send(layout("Resumen", `<h1>Resumen</h1><div class="notice error">${esc(error.message)}</div>`, "resumen", req.csrf));
  }
});


// --------------------------------------------------------------------------
// Avisos: llamadas que entraron con la administración cerrada y en las que el
// cliente dejó sus datos para que le devuelvan la llamada. Los datos se leen
// de los campos aviso_* que ElevenLabs extrae de cada conversación.
// --------------------------------------------------------------------------
function pickValue(entry) {
  if (entry === null || entry === undefined) return "";
  if (typeof entry === "object") return String(entry.value ?? entry.result ?? "").trim();
  return String(entry).trim();
}

async function mapLimit(items, limit, worker) {
  const results = new Array(items.length);
  let index = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (index < items.length) {
      const current = index++;
      try { results[current] = await worker(items[current]); }
      catch { results[current] = null; }
    }
  }));
  return results;
}

async function fetchAvisos(days) {
  const qs = new URLSearchParams({ agent_id: ELEVENLABS_AGENT_ID, page_size: "100", sort_direction: "desc" });
  const list = await eleven(`/convai/conversations?${qs}`);
  const since = days ? Date.now() / 1000 - days * 86400 : 0;
  const recent = (list.conversations || []).filter((c) => (c.start_time_unix_secs || 0) >= since);
  const detailed = await mapLimit(recent, 4, async (c) => {
    const detail = await eleven(`/convai/conversations/${encodeURIComponent(c.conversation_id)}`);
    const collected = detail.analysis?.data_collection_results || {};
    const aviso = {
      id: c.conversation_id,
      at: c.start_time_unix_secs,
      nombre: pickValue(collected.aviso_nombre),
      telefono: pickValue(collected.aviso_telefono),
      peticion: pickValue(collected.aviso_peticion),
      resumen: detail.analysis?.transcript_summary || c.transcript_summary || "",
    };
    const explicitCallback = boolValue(collected.devolver_llamada);
    return (explicitCallback || aviso.nombre || aviso.telefono) ? aviso : null;
  });
  return detailed.filter(Boolean);
}

app.get("/avisos", requireAuth, async (req, res) => {
  const days = req.query.todos ? 0 : 7;
  try {
    const avisos = await fetchAvisos(days);
    const rows = avisos.map((a) => `<tr><td>${esc(formatDate(a.at))}</td><td><strong>${esc(a.nombre || "Sin nombre")}</strong></td><td>${a.telefono ? `<a href="tel:${esc(a.telefono)}">${esc(a.telefono)}</a>` : "—"}</td><td class="summary">${esc(a.peticion || a.resumen || "—")}</td><td><a href="/calls/${encodeURIComponent(a.id)}">Ver llamada</a></td></tr>`).join("");
    const filtro = days
      ? '<a class="btn secondary" href="/avisos?todos=1">Ver todos</a>'
      : '<a class="btn secondary" href="/avisos">Solo últimos 7 días</a>';
    res.send(layout("Avisos", `<h1>Avisos para devolver</h1><div class="sub">Clientes que llamaron con la administración cerrada y dejaron sus datos para que un compañero les llame.</div><p class="actions">${filtro}<span class="small">${days ? "Mostrando los últimos 7 días" : "Mostrando todas las llamadas recientes"}</span></p><div class="panel" style="overflow:auto"><table><thead><tr><th>Llamada</th><th>Nombre</th><th>Teléfono</th><th>Qué pide</th><th></th></tr></thead><tbody>${rows || '<tr><td colspan="5">No hay avisos pendientes.</td></tr>'}</tbody></table></div><div class="notice">Esta pantalla lee los avisos directamente de ElevenLabs cada vez que la abres, así que no se pierde ninguno aunque Render reinicie. Tarda unos segundos en cargar porque consulta llamada por llamada.</div>`, "avisos", req.csrf));
  } catch (error) {
    res.status(502).send(layout("Avisos", `<h1>Avisos</h1><div class="notice error">${esc(error.message)}</div>`, "avisos", req.csrf));
  }
});

const getAgent = () => eleven(`/convai/agents/${encodeURIComponent(ELEVENLABS_AGENT_ID)}`);

app.get("/knowledge", requireAuth, async (req, res) => {
  try {
    const agent = await getAgent();
    const firstMessage = agent.conversation_config?.agent?.first_message || "";
    const prompt = agent.conversation_config?.agent?.prompt?.prompt || "";
    // Herramientas que este panel conserva al guardar. De built_in_tools se listan
    // solo las entradas con configuración: ElevenLabs devuelve el hueco a null
    // para las integradas que el agente no usa.
    const builtIn = agent.conversation_config?.agent?.prompt?.built_in_tools || {};
    const tools = [
      ...(agent.conversation_config?.agent?.prompt?.tool_ids || []),
      ...Object.entries(builtIn).filter(([, value]) => value).map(([name]) => name),
    ];
    const saved = req.query.saved ? '<div class="notice ok">Cambios guardados en ElevenLabs. Se ha archivado la versión anterior en “Versiones”.</div>' : "";
    res.send(layout("Conocimiento", `<h1>Conocimiento de Búho</h1><div class="sub">Edita la configuración que Búho utiliza en sus conversaciones. Los cambios se envían al agente real.</div>${saved}<div class="notice">Este panel guarda la versión anterior antes de cada cambio, pero ese historial se pierde si Render reinicia. Para un cambio grande, descarga primero una copia.</div><p class="actions"><a class="btn secondary" href="/knowledge/backup">Descargar copia de seguridad</a>${tools.length ? `<span class="small">Herramientas que se conservan al guardar: ${esc(tools.join(", "))}</span>` : '<span class="small">El agente no tiene herramientas configuradas.</span>'}</p><form method="post" action="/knowledge"><input type="hidden" name="_csrf" value="${esc(req.csrf)}"><div class="field"><label>Primer mensaje</label><input name="first_message" value="${esc(firstMessage)}" required><div class="small">No uses variables como <code>{{saludo}}</code> si no están definidas: la llamada falla nada más entrar.</div></div><div class="field"><label>Mensaje del sistema / conocimiento</label><textarea name="prompt" required>${esc(prompt)}</textarea></div><div class="actions"><button class="btn" type="submit">Guardar en ElevenLabs</button><a class="btn secondary" href="/knowledge">Descartar cambios</a></div></form>`, "knowledge", req.csrf));
  } catch (error) {
    res.status(502).send(layout("Conocimiento", `<h1>Conocimiento</h1><div class="notice error">${esc(error.message)}</div>`, "knowledge", req.csrf));
  }
});

app.get("/knowledge/backup", requireAuth, async (req, res) => {
  try {
    const agent = await getAgent();
    const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-");
    const body = `# Copia de seguridad de Buho Voz — ${stamp}\n\n## Primer mensaje\n\n${agent.conversation_config?.agent?.first_message || ""}\n\n## Mensaje del sistema\n\n${agent.conversation_config?.agent?.prompt?.prompt || ""}\n`;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="buho-voz-${stamp}.txt"`);
    res.send(body);
  } catch (error) {
    res.status(502).send(layout("Conocimiento", `<h1>No se pudo descargar la copia</h1><div class="notice error">${esc(error.message)}</div>`, "knowledge", req.csrf));
  }
});

// Guardado seguro: leemos la configuración completa, cambiamos sólo los dos campos
// y devolvemos el objeto entero. Así no dependemos de que el PATCH parcial mezcle
// bien y no se puede perder la herramienta de transferencia ni la voz.
async function saveAgentText(firstMessage, prompt) {
  const agent = await getAgent();
  const config = structuredClone(agent.conversation_config || {});
  config.agent = config.agent || {};
  config.agent.prompt = config.agent.prompt || {};
  const previous = {
    at: Date.now(),
    first_message: config.agent.first_message || "",
    prompt: config.agent.prompt.prompt || "",
  };
  config.agent.first_message = firstMessage;
  config.agent.prompt.prompt = prompt;
  await eleven(`/convai/agents/${encodeURIComponent(ELEVENLABS_AGENT_ID)}`, {
    method: "PATCH",
    body: JSON.stringify({ conversation_config: config }),
  });
  history.unshift(previous);
  if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
}

app.post("/knowledge", requireAuth, verifyCsrf, async (req, res) => {
  const firstMessage = String(req.body.first_message || "").trim();
  const prompt = String(req.body.prompt || "").trim();
  if (!firstMessage || !prompt) {
    return res.status(400).send(layout("Conocimiento", '<h1>Faltan datos</h1><div class="notice error">El primer mensaje y el mensaje del sistema no pueden quedar vacíos.</div><p><a href="/knowledge">Volver</a></p>', "knowledge", req.csrf));
  }
  if (prompt.length > 200000) {
    return res.status(413).send(layout("Conocimiento", '<h1>Texto demasiado largo</h1><div class="notice error">El mensaje del sistema supera los 200.000 caracteres.</div><p><a href="/knowledge">Volver</a></p>', "knowledge", req.csrf));
  }
  try {
    await saveAgentText(firstMessage, prompt);
    res.redirect("/knowledge?saved=1");
  } catch (error) {
    res.status(502).send(layout("Conocimiento", `<h1>No se pudieron guardar los cambios</h1><div class="notice error">${esc(error.message)}</div><p>El agente no se ha modificado.</p><p><a href="/knowledge">Volver</a></p>`, "knowledge", req.csrf));
  }
});

app.get("/history", requireAuth, (req, res) => {
  const rows = history.map((entry, index) => `<tr><td>${esc(formatDate(Math.round(entry.at / 1000)))}</td><td class="summary">${esc(entry.first_message)}</td><td>${esc(entry.prompt.length)} caracteres</td><td><form method="post" action="/history/restore"><input type="hidden" name="_csrf" value="${esc(req.csrf)}"><input type="hidden" name="index" value="${index}"><button class="btn danger" type="submit">Restaurar</button></form></td></tr>`).join("");
  res.send(layout("Versiones", `<h1>Versiones anteriores</h1><div class="sub">Copias guardadas automáticamente justo antes de cada cambio hecho desde este panel.</div><div class="notice">Este historial vive en memoria: si Render reinicia el servicio, se vacía. Para conservar una versión, usa “Descargar copia de seguridad”.</div><div class="panel" style="overflow:auto"><table><thead><tr><th>Guardada</th><th>Primer mensaje</th><th>Tamaño del prompt</th><th></th></tr></thead><tbody>${rows || '<tr><td colspan="4">Todavía no se ha guardado ningún cambio desde este panel.</td></tr>'}</tbody></table></div>`, "history", req.csrf));
});

app.post("/history/restore", requireAuth, verifyCsrf, async (req, res) => {
  const entry = history[Number(req.body.index)];
  if (!entry) return res.status(404).send(layout("Versiones", '<h1>Versión no encontrada</h1><p><a href="/history">Volver</a></p>', "history", req.csrf));
  try {
    await saveAgentText(entry.first_message, entry.prompt);
    res.redirect("/knowledge?saved=1");
  } catch (error) {
    res.status(502).send(layout("Versiones", `<h1>No se pudo restaurar</h1><div class="notice error">${esc(error.message)}</div>`, "history", req.csrf));
  }
});

app.get("/settings", requireAuth, async (req, res) => {
  let agentName = "No comprobado", apiStatus = "No comprobado", voice = "—", llm = "—";
  try {
    const agent = await getAgent();
    agentName = agent.name || "Sin nombre";
    apiStatus = "Conectada";
    voice = agent.conversation_config?.tts?.voice_id || "—";
    llm = agent.conversation_config?.agent?.prompt?.llm || "—";
  } catch (error) {
    apiStatus = `Error: ${error.message}`;
  }
  res.send(layout("Estado", `<h1>Estado</h1><div class="sub">Comprobación de la conexión del panel.</div><div class="panel"><table><tbody><tr><th>ElevenLabs API</th><td>${esc(apiStatus)}</td></tr><tr><th>Agente</th><td>${esc(agentName)}</td></tr><tr><th>Agent ID</th><td><code>${esc(ELEVENLABS_AGENT_ID)}</code></td></tr><tr><th>Voz (voice_id)</th><td><code>${esc(voice)}</code></td></tr><tr><th>Modelo</th><td>${esc(llm)}</td></tr><tr><th>API key</th><td>Configurada y oculta</td></tr><tr><th>Aviso por correo</th><td>${esc(emailListo ? `Configurado, se env\u00eda a ${AVISO_EMAIL_TO}` : "Sin configurar: faltan las variables SMTP en Render")}</td></tr><tr><th>Webhook de ElevenLabs</th><td>${esc(ELEVENLABS_WEBHOOK_SECRET ? "Secreto configurado" : "Sin configurar: falta ELEVENLABS_WEBHOOK_SECRET")}</td></tr><tr><th>Zona horaria</th><td>Europe/Madrid</td></tr><tr><th>Estados y notas</th><td>${esc(PANEL_STORAGE_PERSISTENT ? `Directorio persistente: ${PANEL_DATA_DIR}` : `Servidor compartido en ${PANEL_DATA_DIR}; falta disco persistente`)}</td></tr><tr><th>Reservas</th><td>${esc(PANEL_STORAGE_PERSISTENT && BUHO_RESERVATION_TOKEN ? `Habilitadas · plazo ${RESERVATION_DAYS} días` : !PANEL_STORAGE_PERSISTENT ? "Bloqueadas: falta disco persistente / BUHO_DATA_DIR" : "Preparadas: falta BUHO_RESERVATION_TOKEN")}</td></tr></tbody></table></div>`, "settings", req.csrf));
});

// --------------------------------------------------------------------------
// Saludo según la hora (opcional).
// ElevenLabs puede pedir a este endpoint las variables dinámicas justo antes
// de empezar cada llamada. Se activa poniendo ENABLE_SALUDO_WEBHOOK=1 y
// apuntando aquí el "conversation initiation webhook" del agente.
// AVISO: si el servicio de Render está dormido (plan gratuito), la primera
// llamada del día puede tardar demasiado y la llamada fallará. No lo actives
// hasta tener el servicio siempre despierto.
// --------------------------------------------------------------------------
function saludoDeMadrid(now = new Date()) {
  const hour = Number(new Intl.DateTimeFormat("es-ES", { timeZone: "Europe/Madrid", hour: "2-digit", hour12: false }).format(now));
  if (hour >= 6 && hour < 14) return "Buenos días";
  if (hour >= 14 && hour < 21) return "Buenas tardes";
  return "Buenas noches";
}
if (process.env.ENABLE_SALUDO_WEBHOOK === "1") {
  app.post("/elevenlabs/init", (_req, res) => {
    res.json({ type: "conversation_initiation_client_data", dynamic_variables: { saludo: saludoDeMadrid() } });
  });
  app.get("/elevenlabs/init", (_req, res) => res.json({ saludo: saludoDeMadrid() })); // sólo para comprobar a mano
}


// --------------------------------------------------------------------------
// Aviso por correo al terminar una llamada.
// ElevenLabs manda aquí cada conversación; si trae un aviso para devolver la
// llamada, se envía un correo a la administración.
// --------------------------------------------------------------------------
const emailListo = Boolean(SMTP_HOST && SMTP_USER && SMTP_PASS);
let transporte = null;
async function enviarCorreo(asunto, texto) {
  if (!emailListo) return false;
  if (!transporte) {
    const { default: nodemailer } = await import("nodemailer");
    transporte = nodemailer.createTransport({
      host: SMTP_HOST,
      port: Number(SMTP_PORT),
      secure: Number(SMTP_PORT) === 465,
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    });
  }
  await transporte.sendMail({
    from: AVISO_EMAIL_FROM || SMTP_USER,
    to: AVISO_EMAIL_TO,
    subject: asunto,
    text: texto,
  });
  return true;
}

// ElevenLabs puede reenviar la misma llamada hasta cinco veces; sin esto,
// el dependiente recibiría el mismo aviso repetido.
const yaAvisadas = new Set();
function marcarAvisada(id) {
  yaAvisadas.add(id);
  if (yaAvisadas.size > 500) yaAvisadas.delete(yaAvisadas.values().next().value);
}

function firmaValida(req) {
  const cabecera = String(req.get("ElevenLabs-Signature") || "");
  const partes = Object.fromEntries(cabecera.split(",").map((p) => {
    const i = p.indexOf("=");
    return i > 0 ? [p.slice(0, i).trim(), p.slice(i + 1).trim()] : [p.trim(), ""];
  }));
  const marca = Number(partes.t);
  const recibida = partes.v0;
  if (!Number.isFinite(marca) || !recibida || !req.rawBody) return false;
  // ElevenLabs admite 30 minutos de desfase.
  if (Math.abs(Date.now() / 1000 - marca) > 1800) return false;
  const esperada = crypto.createHmac("sha256", ELEVENLABS_WEBHOOK_SECRET)
    .update(`${marca}.${req.rawBody.toString("utf8")}`).digest("hex");
  if (recibida.length !== esperada.length) return false;
  return crypto.timingSafeEqual(Buffer.from(recibida), Buffer.from(esperada));
}

app.post("/elevenlabs/post-call", async (req, res) => {
  if (!ELEVENLABS_WEBHOOK_SECRET) {
    console.warn("Webhook recibido pero falta ELEVENLABS_WEBHOOK_SECRET");
    return res.status(503).send("Webhook no configurado.");
  }
  if (!firmaValida(req)) {
    console.warn("Webhook con firma no válida");
    return res.status(401).send("Firma no válida.");
  }

  // Contestamos ya: ElevenLabs espera un 200 rápido y reintenta si tardamos.
  res.status(200).send("ok");

  try {
    const evento = req.body || {};
    if (evento.type !== "post_call_transcription") return;
    const datos = evento.data || {};
    if (datos.agent_id && datos.agent_id !== ELEVENLABS_AGENT_ID) return;

    const id = datos.conversation_id || "";
    if (!id || yaAvisadas.has(id)) return;

    const recogido = datos.analysis?.data_collection_results || {};
    const nombre = pickValue(recogido.aviso_nombre);
    const telefono = pickValue(recogido.aviso_telefono);
    const peticion = pickValue(recogido.aviso_peticion);
    if (!nombre && !telefono && !peticion) return;

    marcarAvisada(id);

    const cuando = formatDate(datos.metadata?.start_time_unix_secs);
    const resumen = datos.analysis?.transcript_summary || "";
    const asunto = `Aviso de Búho: ${nombre || "cliente sin nombre"}${telefono ? ` · ${telefono}` : ""}`;
    const texto = [
      "Un cliente ha llamado fuera del horario de la administración y ha dejado un aviso.",
      "",
      `Nombre:   ${nombre || "no lo dijo"}`,
      `Teléfono: ${telefono || "no lo dejó"}`,
      `Pide:     ${peticion || "sin detalle"}`,
      `Llamada:  ${cuando}`,
      "",
      resumen ? `Resumen de la llamada:\n${resumen}` : "",
      "",
      `Escuchar la llamada: ${PUBLIC_URL}/calls/${encodeURIComponent(id)}`,
      `Todos los avisos:    ${PUBLIC_URL}/avisos`,
    ].join("\n");

    try {
      if (await enviarCorreo(asunto, texto)) console.log(`Aviso enviado a ${AVISO_EMAIL_TO} (${id})`);
      else console.warn(`Aviso sin enviar, falta configurar el correo (${id}). Queda visible en /avisos.`);
    } catch (fallo) {
      // Si el correo falla, desmarcamos: si ElevenLabs reenvía la llamada,
      // se vuelve a intentar. Y el aviso sigue estando en /avisos igualmente.
      yaAvisadas.delete(id);
      console.error(`No se pudo enviar el aviso por correo (${id}):`, fallo.message);
    }
  } catch (error) {
    console.error("Error procesando el aviso:", error);
  }
});


// ======================================================
// CONSULTAR DISPONIBILIDAD DE UN NÚMERO DE LOTERÍA
// ======================================================

async function consultarNumeroReal(number) {
  if (!/^\d{5}$/.test(String(number || ""))) throw new Error("El número debe contener exactamente cinco cifras");

  const baseUrl = process.env.LOTTERY_API_BASE_URL;
  const drawId = process.env.LOTTERY_DRAW_ID;
  const pvCode = process.env.LOTTERY_PV_CODE;
  const apiKey = process.env.LOTTERY_API_KEY;
  if (!baseUrl || !drawId || !pvCode || !apiKey) throw new Error("Servicio de consulta no configurado");

  const url = new URL("/consulta", baseUrl);
  url.searchParams.set("number", number);
  url.searchParams.set("id_draw", drawId);
  url.searchParams.set("pv_code", pvCode);
  url.searchParams.set("apikey", apiKey);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 7000);
  let response;
  try {
    response = await fetch(url.toString(), { method: "GET", signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }

  const responseText = await response.text();
  if (!response.ok) {
    console.error("Error servidor lotería:", response.status, responseText);
    throw new Error("No se pudo consultar la disponibilidad");
  }

  let result;
  try { result = JSON.parse(responseText); } catch { result = responseText; }
  const quantity = Number(result?.available ?? 0);
  const found = result?.found === true;
  return { number, available: found && quantity > 0, quantity };
}

app.get("/api/consulta-numero", async (req, res) => {
  const number = String(req.query.number || "").trim();
  if (!/^\d{5}$/.test(number)) return res.status(400).json({ ok: false, error: "El número debe contener exactamente cinco cifras" });
  try {
    const result = await consultarNumeroReservable(number);
    return res.json({ ok: true, ...result });
  } catch (error) {
    console.error("Error consulta número:", error.message);
    return res.status(502).json({ ok: false, number, error: error.message || "Error consultando el número" });
  }
});


// ======================================================
// BUSCAR NÚMEROS POR TERMINACIÓN O AL AZAR
// La API de stock admite asteriscos como comodines y devuelve
// todo el stock coincidente en una sola consulta.
// ======================================================

function wildcardPatternRegex(pattern) {
  return new RegExp(`^${String(pattern).replace(/\*/g, "\\d")}$`);
}

function quantityFromStockItem(item) {
  if (item === null || item === undefined) return 0;
  if (typeof item === "number" || typeof item === "string") {
    const n = Number(item);
    return Number.isFinite(n) ? n : 0;
  }
  if (typeof item !== "object") return 0;
  const keys = ["quantity", "stock", "qty", "cantidad", "units", "decimos", "décimos", "available_quantity", "availableQuantity", "available"];
  for (const key of keys) {
    const raw = item?.[key];
    if (typeof raw === "boolean") continue;
    const n = Number(raw);
    if (raw !== "" && raw !== null && raw !== undefined && Number.isFinite(n)) return n;
  }
  return 0;
}

function numberFromStockItem(item, fallbackKey = "") {
  if (item && typeof item === "object") {
    const keys = ["number", "numero", "número", "num", "lottery_number", "lotteryNumber"];
    for (const key of keys) {
      const value = String(item?.[key] ?? "").trim();
      if (/^\d{5}$/.test(value)) return value;
    }
  }
  return /^\d{5}$/.test(String(fallbackKey || "")) ? String(fallbackKey) : "";
}

function normalizeWildcardStock(payload, pattern) {
  const rows = [];
  let recognized = false;
  const seenObjects = new Set();

  const add = (item, fallbackKey = "") => {
    const number = numberFromStockItem(item, fallbackKey);
    if (!number) return;
    rows.push({ number, source_quantity: Math.max(0, quantityFromStockItem(item)) });
  };

  const walk = (value, depth = 0) => {
    if (depth > 4 || value === null || value === undefined) return;
    if (Array.isArray(value)) {
      recognized = true;
      for (const item of value) walk(item, depth + 1);
      return;
    }
    if (typeof value !== "object") return;
    if (seenObjects.has(value)) return;
    seenObjects.add(value);

    const directNumber = numberFromStockItem(value);
    if (directNumber) add(value);

    const containerKeys = ["results", "data", "stock", "numbers", "items", "matches", "available_numbers", "availableNumbers"];
    for (const key of containerKeys) {
      if (value[key] && typeof value[key] === "object") {
        recognized = true;
        walk(value[key], depth + 1);
      }
    }

    // Algunas APIs devuelven el stock como objeto: { "19993": 4, "00042": { available: 9 } }
    for (const [key, child] of Object.entries(value)) {
      if (/^\d{5}$/.test(key)) {
        recognized = true;
        add(child, key);
      }
    }

    if (value.found === false) recognized = true;
  };

  walk(payload);

  const matcher = wildcardPatternRegex(pattern);
  const byNumber = new Map();
  for (const row of rows) {
    if (!matcher.test(row.number)) continue;
    const previous = byNumber.get(row.number);
    if (!previous || row.source_quantity > previous.source_quantity) byNumber.set(row.number, row);
  }
  return { recognized, rows: [...byNumber.values()] };
}

async function consultarStockPorPatron(pattern) {
  pattern = String(pattern || "").trim();
  if (!/^[0-9*]{5}$/.test(pattern) || !pattern.includes("*")) {
    throw new Error("El patrón debe tener cinco posiciones y contener al menos un asterisco");
  }

  const baseUrl = process.env.LOTTERY_API_BASE_URL;
  const drawId = process.env.LOTTERY_DRAW_ID;
  const pvCode = process.env.LOTTERY_PV_CODE;
  const apiKey = process.env.LOTTERY_API_KEY;
  if (!baseUrl || !drawId || !pvCode || !apiKey) throw new Error("Servicio de consulta no configurado");

  const url = new URL("/consulta", baseUrl);
  url.searchParams.set("number", pattern);
  url.searchParams.set("id_draw", drawId);
  url.searchParams.set("pv_code", pvCode);
  url.searchParams.set("apikey", apiKey);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  let response;
  try {
    response = await fetch(url.toString(), { method: "GET", signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }

  const responseText = await response.text();
  if (!response.ok) {
    console.error("Error servidor lotería (búsqueda parcial):", response.status, responseText.slice(0, 1000));
    throw new Error("No se pudo buscar números disponibles");
  }

  let payload;
  try { payload = JSON.parse(responseText); } catch {
    throw new Error("La búsqueda parcial devolvió una respuesta no válida");
  }

  const normalized = normalizeWildcardStock(payload, pattern);
  if (!normalized.recognized) {
    console.error("Formato no reconocido en búsqueda parcial:", responseText.slice(0, 1500));
    throw new Error("Formato de stock parcial no reconocido");
  }

  const state = loadPanelState();
  const reservedByNumber = new Map();
  for (const r of Object.values(state.reservations || {})) {
    if (!r || reservationEffectiveStatus(r) !== "pendiente" || !/^\d{5}$/.test(String(r.number || ""))) continue;
    reservedByNumber.set(r.number, (reservedByNumber.get(r.number) || 0) + Math.max(0, Number(r.quantity || 0)));
  }

  return normalized.rows.map((row) => {
    const reserved = reservedByNumber.get(row.number) || 0;
    const quantity = Math.max(0, Number(row.source_quantity || 0) - reserved);
    return { number: row.number, quantity, source_quantity: row.source_quantity, reserved, available: quantity > 0 };
  }).filter((row) => row.available);
}

function randomSample(items, limit) {
  const copy = [...items];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy.slice(0, limit);
}

app.get("/api/buscar-numeros", async (req, res) => {
  const type = String(req.query.type || req.query.tipo || "ending").trim().toLowerCase();
  const value = String(req.query.value || req.query.valor || "").trim();
  const requestedLimit = Number(req.query.limit || 3);
  const limit = Number.isFinite(requestedLimit) ? Math.max(1, Math.min(5, Math.floor(requestedLimit))) : 3;

  let pattern;
  let responseLimit = limit;
  if (["random", "azar", "aleatorio"].includes(type)) {
    pattern = "*****";
    responseLimit = 1;
  } else if (["ending", "terminacion", "terminación", "suffix"].includes(type)) {
    if (!/^\d{1,4}$/.test(value)) {
      return res.status(400).json({ ok:false, error:"La terminación debe contener entre una y cuatro cifras" });
    }
    pattern = `${"*".repeat(5 - value.length)}${value}`;
  } else {
    return res.status(400).json({ ok:false, error:"Tipo de búsqueda no válido. Usa ending o random." });
  }

  try {
    const all = await consultarStockPorPatron(pattern);
    const results = randomSample(all, responseLimit).map(({ number, quantity }) => ({ number, quantity }));
    return res.json({
      ok: true,
      type: pattern === "*****" ? "random" : "ending",
      value: pattern === "*****" ? "" : value,
      pattern,
      total_available_numbers: all.length,
      results,
      message: results.length
        ? (pattern === "*****"
          ? `Número disponible al azar: ${results[0].number}. Quedan ${results[0].quantity} décimo(s).`
          : `Se han encontrado ${all.length} número(s) disponibles que terminan en ${value}.`)
        : (pattern === "*****" ? "No se ha encontrado ningún número disponible." : `No hay números disponibles que terminen en ${value}.`)
    });
  } catch (error) {
    console.error("Error búsqueda de números:", error.message);
    return res.status(502).json({ ok:false, error:error.message || "Error buscando números" });
  }
});


// ======================================================
// RESERVAS - API PARA BÚHO VOZ
// ======================================================
function requireReservationToken(req, res, next) {
  if (!PANEL_STORAGE_PERSISTENT) return res.status(503).json({ ok:false, error:"reservas_no_habilitadas", message:"Las reservas requieren almacenamiento persistente." });
  if (!BUHO_RESERVATION_TOKEN) return res.status(503).json({ ok:false, error:"reservas_no_configuradas", message:"Falta BUHO_RESERVATION_TOKEN." });
  const received = String(req.get("X-Buho-Reservation-Token") || "");
  const a = Buffer.from(received), b = Buffer.from(BUHO_RESERVATION_TOKEN);
  if (a.length !== b.length || !crypto.timingSafeEqual(a,b)) return res.status(401).json({ ok:false, error:"no_autorizado" });
  next();
}

app.post("/api/crear-reserva", requireReservationToken, async (req, res) => {
  try {
    const result = await withReservationLock(() => createReservationRecord({
      number: req.body?.number,
      quantity: req.body?.quantity,
      customer_name: req.body?.customer_name,
      customer_phone: req.body?.customer_phone,
      conversation_id: req.body?.conversation_id,
      created_by: "agent",
    }));
    const r = result.reservation;
    return res.json({
      ok: true,
      already_exists: result.already_exists,
      reservation_id: r.id,
      number: r.number,
      quantity: r.quantity,
      customer_name: r.customer_name,
      customer_phone: r.customer_phone,
      payment: "Se paga al recoger en la administración",
      pickup_days: RESERVATION_DAYS,
      pickup_deadline: formatDayKeyEs(r.expires_date),
      pickup_deadline_text: `Recoger antes del cierre del ${formatDayKeyEs(r.expires_date)}`,
      remaining_after_reservation: Math.max(0, Number(result.availability.quantity || 0) - (result.already_exists ? 0 : Number(r.quantity || 0))),
      message: `Reserva ${r.id} confirmada. Se paga al recoger. Recoger antes del cierre del ${formatDayKeyEs(r.expires_date)}.`
    });
  } catch (error) {
    const status = error.code === "INSUFFICIENT_STOCK" ? 409 : error.code === "PERSISTENCE_REQUIRED" ? 503 : 400;
    return res.status(status).json({ ok:false, error:error.code || "reserva_no_creada", message:error.message, available_quantity:error.available_quantity ?? null });
  }
});

// ======================================================
// BÚHO PRINT - LLAMADAS PARA IMPRESIÓN + REIMPRESIONES
// ======================================================

function requirePrintToken(req, res, next) {
  if (!BUHO_PRINT_TOKEN) return res.status(503).json({ ok: false, error: "Búho Print no configurado" });
  const received = String(req.get("X-Buho-Print-Token") || "");
  const a = Buffer.from(received), b = Buffer.from(BUHO_PRINT_TOKEN);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ ok: false, error: "No autorizado" });
  next();
}

function printJobFrom(call, detail, overrides = {}) {
  const collected = detail.analysis?.data_collection_results || {};
  const telefono = detail.user_id || detail.metadata?.phone_call?.external_number || detail.metadata?.phone_call?.caller_id || "Número no disponible";
  const avisoNombre = pickValue(collected.aviso_nombre);
  const avisoTelefono = pickValue(collected.aviso_telefono);
  const explicitCallback = boolValue(collected.devolver_llamada);
  return {
    id: overrides.id || call.conversation_id || detail.conversation_id,
    original_id: overrides.original_id || call.conversation_id || detail.conversation_id,
    reprint_queue_id: overrides.reprint_queue_id || "",
    print_queue_id: overrides.reprint_queue_id || "",
    reprint: Boolean(overrides.reprint_queue_id),
    at: detail.metadata?.start_time_unix_secs || call.start_time_unix_secs || 0,
    telefono,
    duracion: detail.metadata?.call_duration_secs || call.call_duration_secs || 0,
    titulo: call.call_summary_title || detail.analysis?.call_summary_title || "Llamada",
    resumen: detail.analysis?.transcript_summary || call.transcript_summary || "Sin resumen",
    motivo: pickValue(collected.motivo_llamada),
    numeros: pickValue(collected.numeros_consultados),
    disponibilidad: pickValue(collected.resultado_disponibilidad),
    cantidad: pickValue(collected.cantidad_solicitada),
    intencion_compra: boolValue(collected.intencion_compra),
    pidio_borja: boolValue(collected.pidio_borja),
    empresa_asociacion: pickValue(collected.empresa_asociacion),
    devolver_llamada: explicitCallback || Boolean(avisoNombre || avisoTelefono),
    aviso_nombre: avisoNombre,
    aviso_telefono: avisoTelefono,
    aviso_peticion: pickValue(collected.aviso_peticion),
    transferida: Array.isArray(call.tool_names) && call.tool_names.some((tool) => String(tool).toLowerCase().includes("transfer")),
    sentimiento: detail.sentiment_analysis?.overall_label || call.sentiment_analysis?.overall_label || "",
    sentimiento_score: detail.sentiment_analysis?.overall_sentiment_score ?? call.sentiment_analysis?.overall_sentiment_score ?? null,
    frustracion: detail.sentiment_analysis?.overall_frustration_score ?? call.sentiment_analysis?.overall_frustration_score ?? null,
  };
}


function reservationPrintJob(reservation, item) {
  return {
    id: `reservation:${item.queue_id}`,
    job_type: "reservation",
    original_id: reservation.conversation_id || reservation.id,
    reservation_id: reservation.id,
    reservation_print_queue_id: item.queue_id,
    print_queue_id: item.queue_id,
    reprint: item.reason === "reprint",
    at: Math.floor(Number(reservation.created_at || Date.now()) / 1000),
    reservation_created_at: reservation.created_at,
    numero_reserva: reservation.number,
    cantidad_reserva: reservation.quantity,
    nombre_reserva: reservation.customer_name,
    telefono_reserva: reservation.customer_phone,
    fecha_limite_reserva: formatDayKeyEs(reservation.expires_date),
    pago_reserva: "PAGO AL RECOGER",
    estado_reserva: reservationStatusLabel(reservationEffectiveStatus(reservation)),
    conversation_id: reservation.conversation_id || "",
  };
}

app.get("/api/print-jobs", requirePrintToken, async (req, res) => {
  try {
    const defaultAfter = Math.floor(Date.now() / 1000) - 86400;
    const after = Number(req.query.after || defaultAfter);
    if (!Number.isFinite(after)) return res.status(400).json({ ok: false, error: "Fecha no válida" });

    const qs = new URLSearchParams({ agent_id: ELEVENLABS_AGENT_ID, page_size: "100", summary_mode: "include", sort_direction: "desc" });
    const data = await eleven(`/convai/conversations?${qs}`);
    const calls = (data.conversations || []).filter((call) => {
      const inicio = Number(call.start_time_unix_secs || 0);
      const status = String(call.status || "").toLowerCase();
      return inicio > after && !["initiated", "in-progress", "processing"].includes(status);
    });

    const normalJobs = (await mapLimit(calls, 6, async (call) => {
      if (!call.conversation_id) return null;
      const detail = await eleven(`/convai/conversations/${encodeURIComponent(call.conversation_id)}`);
      return printJobFrom(call, detail);
    })).filter(Boolean);

    const panelState = loadPanelState();
    const now = Date.now();
    panelState.reprints = panelState.reprints.filter((r) => !r.acked_at && now - Number(r.created_at || 0) < 7 * 86400000);
    const pendingReprints = panelState.reprints.slice(0, 20);
    savePanelState(panelState);

    const reprintJobs = (await mapLimit(pendingReprints, 4, async (item) => {
      const detail = await eleven(`/convai/conversations/${encodeURIComponent(item.conversation_id)}`);
      const call = { ...detail, conversation_id: item.conversation_id, tool_names: detail.tool_names || [] };
      return printJobFrom(call, detail, {
        id: `reprint:${item.queue_id}`,
        original_id: item.conversation_id,
        reprint_queue_id: item.queue_id,
      });
    })).filter(Boolean);

    // Vales de reserva: solo se entregan a la impresora cuando la llamada ya ha terminado.
    // Así el resumen normal sale primero y el vale independiente justo después.
    panelState.reservation_prints = (panelState.reservation_prints || []).filter((p) => !p.acked_at && now - Number(p.created_at || 0) < 30 * 86400000);
    const pendingReservationPrints = panelState.reservation_prints.slice(0, 30);
    const byConversation = new Map((data.conversations || []).map((c) => [c.conversation_id, c]));
    const reservationJobs = [];
    for (const item of pendingReservationPrints) {
      const reservation = panelState.reservations?.[item.reservation_id];
      if (!reservation) { item.acked_at = Date.now(); continue; }
      const cid = reservation.conversation_id || "";
      if (cid) {
        const call = byConversation.get(cid);
        if (!call) continue;
        const status = String(call.status || "").toLowerCase();
        if (["initiated", "in-progress", "processing"].includes(status)) continue;
      }
      reservationJobs.push(reservationPrintJob(reservation, item));
    }
    savePanelState(panelState);

    const jobs = [...normalJobs, ...reprintJobs, ...reservationJobs].sort((a,b) => {
      const atDiff = Number(a.at || 0) - Number(b.at || 0);
      if (atDiff) return atDiff;
      // Si tienen la misma hora, resumen antes que vale de reserva.
      return (a.job_type === "reservation" ? 1 : 0) - (b.job_type === "reservation" ? 1 : 0);
    });
    return res.json({ ok: true, count: jobs.length, jobs });
  } catch (error) {
    console.error("Error Búho Print:", error);
    return res.status(500).json({ ok: false, error: "No se pudieron obtener las llamadas" });
  }
});

app.post("/api/print-ack", requirePrintToken, (req, res) => {
  const queueId = String(req.body?.queue_id || "").trim();
  if (!queueId) return res.status(400).json({ ok: false, error: "Falta queue_id" });
  const panelState = loadPanelState();
  const item = panelState.reprints.find((r) => r.queue_id === queueId) ||
    (panelState.reservation_prints || []).find((r) => r.queue_id === queueId);
  if (!item) return res.json({ ok: true, already_done: true });
  item.acked_at = Date.now();
  savePanelState(panelState);
  return res.json({ ok: true });
});

app.use((_req, res) => res.status(404).send("No encontrado."));
app.use((err, _req, res, _next) => { console.error(err); res.status(500).send("Error interno."); });
app.listen(Number(PORT), "0.0.0.0", () => console.log(`Búho Panel escuchando en el puerto ${PORT}`));
