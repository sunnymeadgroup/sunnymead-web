// Sunnymead admin API (Cloudflare Pages Function).
// Needs, in the Pages project settings:
//   KV binding   DB              (Settings > Bindings > KV namespace)
//   Secret       ADMIN_PASSWORD  (Settings > Variables and Secrets)
//   Variable     GOOGLE_CLIENT_ID (Google OAuth Web application client ID)
//   Variable     ADMIN_GOOGLE_EMAILS (comma-separated allowed admin emails)

const COLLECTIONS = ["sites", "ledger", "reminders"];
const COOKIE = "sm_admin";
const DAYS_30 = 60 * 60 * 24 * 30;
const sessionSecret = (env) => env.ADMIN_SESSION_SECRET || env.ADMIN_PASSWORD;

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...headers } });

// ---------- login ----------

async function hmac(secret, text) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

const GOOGLE_NONCE_COOKIE = "sm_google_nonce";
const allowedEmails = (env) => String(env.ADMIN_GOOGLE_EMAILS || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
const googleEnabled = (env) => !!env.GOOGLE_CLIENT_ID && allowedEmails(env).length > 0;
const sessionCookie = (token) => `${COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=${DAYS_30}; HttpOnly; Secure; SameSite=Strict`;

function readCookie(request, name) {
  try {
    const item = (request.headers.get("cookie") || "").split(";").map((s) => s.trim()).find((s) => s.startsWith(name + "="));
    return item ? decodeURIComponent(item.slice(name.length + 1)) : "";
  } catch { return ""; }
}

function decodeBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Invalid encoding");
  const raw = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(raw + "=".repeat((4 - raw.length % 4) % 4)), (c) => c.charCodeAt(0));
}
const decodeJson = (value) => JSON.parse(new TextDecoder().decode(decodeBase64Url(value)));
const encodeEmail = (email) => btoa(email).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function loggedIn(request, env) {
  if (!sessionSecret(env)) return false;
  const parts = readCookie(request, COOKIE).split(".");
  if (parts[0] === "google" && parts.length === 4) {
    const [, expires, encodedEmail, sig] = parts;
    if (!/^\d+$/.test(expires) || Date.now() / 1000 >= Number(expires)) return false;
    try {
      const email = new TextDecoder().decode(decodeBase64Url(encodedEmail));
      return googleEnabled(env) && allowedEmails(env).includes(email) &&
        safeEqual(sig, await hmac(sessionSecret(env), `google.${expires}.${encodedEmail}`));
    } catch { return false; }
  }
  return false; // Password sessions are no longer accepted.
}

// Google's rotating public keys are cached for the lifetime advertised by Google.
let googleKeys = { keys: [], expires: 0 };
async function verifyGoogleToken(token, clientId, nonce) {
  if (typeof token !== "string" || token.length > 12000) throw new Error("Invalid token");
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid token");
  const header = decodeJson(parts[0]);
  const claims = decodeJson(parts[1]);
  const now = Math.floor(Date.now() / 1000);
  if (header.alg !== "RS256" || typeof header.kid !== "string" ||
      !["accounts.google.com", "https://accounts.google.com"].includes(claims.iss) ||
      claims.aud !== clientId || (claims.azp && claims.azp !== clientId) ||
      !Number.isFinite(claims.exp) || claims.exp <= now ||
      !Number.isFinite(claims.iat) || claims.iat > now + 60 ||
      typeof claims.sub !== "string" || !claims.sub ||
      claims.email_verified !== true || typeof claims.email !== "string" ||
      claims.nonce !== nonce) throw new Error("Invalid token");
  if (googleKeys.expires <= Date.now() || !googleKeys.keys.some((k) => k.kid === header.kid)) {
    const response = await fetch("https://www.googleapis.com/oauth2/v3/certs", { signal: AbortSignal.timeout(10000) });
    if (!response.ok) throw new Error("Google verification unavailable");
    const data = await response.json();
    if (!Array.isArray(data.keys)) throw new Error("Invalid Google keys");
    const maxAge = Number((response.headers.get("cache-control") || "").match(/max-age=(\d+)/)?.[1] || 300);
    googleKeys = { keys: data.keys, expires: Date.now() + Math.min(maxAge, 86400) * 1000 };
  }
  const jwk = googleKeys.keys.find((k) => k.kid === header.kid && k.kty === "RSA");
  if (!jwk) throw new Error("Unknown Google key");
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, decodeBase64Url(parts[2]), new TextEncoder().encode(parts[0] + "." + parts[1]));
  if (!valid) throw new Error("Invalid signature");
  return claims;
}

// ---------- data ----------

const SEED = () => {
  const today = new Date().toISOString().slice(0, 10);
  return {
    sites: [
      { id: "sunnymead", name: "Sunnymead Web", client: "Sunnymead Group Ltd", url: "https://sunnymeadgroup.co.uk", status: "live", own: true, build: 0, monthly: 0, domain: "sunnymeadgroup.co.uk", registrar: "Cloudflare", domainRenews: "", liveSince: "", depositPaid: false, balancePaid: false, notes: "Our own site. Add the domain renewal date from Cloudflare." },
      { id: "carrs", name: "Carr's Barbers Club", client: "Carr's Barbers Club, Jesmond", url: "https://carrs-barber.sunnymeadgroup.workers.dev", status: "demo", build: 300, monthly: 30, domain: "", registrar: "", domainRenews: "", liveSince: "", depositPaid: false, balancePaid: false, notes: "Booking system, customer app and barber diary." },
      { id: "gemini", name: "Gemini Aesthetics", client: "Lucy, Gemini Aesthetics", url: "https://gemini-aesthetics.sunnymeadgroup.workers.dev", status: "demo", build: 300, monthly: 30, domain: "", registrar: "", domainRenews: "", liveSince: "", depositPaid: false, balancePaid: false, notes: "Booking with deposits, staff logins and apps." },
    ],
    ledger: [],
    reminders: [],
    invoices: [],
    business: { name: "Sunnymead Web", email: "web@sunnymeadgroup.co.uk", payDays: 14, buildTerms: "£150 deposit to start, £150 when you are happy with the website.", nextNumber: 1 },
    created: today,
  };
};

// Existing array order reflects insertion order; do not invent historical dates.
function normaliseProjectJobs(data) {
  data.sites = data.sites || [];
  let changed = false;
  const used = new Set();
  let next = Math.max(1, Number.isSafeInteger(data.nextJobNumber) ? data.nextJobNumber : 1,
    ...data.sites.map((s) => Number.isSafeInteger(s.jobNumber) && s.jobNumber > 0 ? s.jobNumber + 1 : 1));
  for (const site of data.sites) {
    if (!Number.isSafeInteger(site.jobNumber) || site.jobNumber < 1 || used.has(site.jobNumber)) {
      // Initial numbering follows the saved project order.
      const initialMigration = !data.sites.some((s) => Number.isSafeInteger(s.jobNumber) && s.jobNumber > 0);
      if (initialMigration) next = 1;
      site.jobNumber = next++;
      changed = true;
    }
    used.add(site.jobNumber);
    if (!site.createdAt) {
      const creation = (data.audit || []).filter((event) => (event.changes || []).some((change) => change.collection === "sites" && change.id === site.id && !change.before && change.after))
        .map((event) => event.at).filter((at) => Number.isFinite(Date.parse(at))).sort()[0];
      if (creation) { site.createdAt = creation; changed = true; }
    }
  }
  if (data.nextJobNumber !== next) { data.nextJobNumber = next; changed = true; }
  return changed;
}

async function load(env) {
  const data = await env.DB.get("data", "json");
  if (data) {
    data.invoices = data.invoices || [];
    data.audit = data.audit || [];
    data.business = { name: "Sunnymead Web", email: "web@sunnymeadgroup.co.uk", payDays: 14, buildTerms: "£150 deposit to start, £150 when you are happy with the website.", nextNumber: 1, ...(data.business || {}) };
    if (normaliseProjectJobs(data)) await env.DB.put("data", JSON.stringify(data));
    return data;
  }
  const seed = env.VENTURE && env.VENTURE.id !== "sunnymead-web"
    ? { sites: [], ledger: [], reminders: [], invoices: [], business: { name: env.VENTURE.name, email: "", legalName: "Sunnymead Group Ltd", payDays: 14, nextNumber: 1, invoicePrefix: env.VENTURE.prefix, buildTerms: "" }, created: new Date().toISOString().slice(0, 10) }
    : SEED();
  seed.sites.forEach((site) => { site.createdAt = new Date().toISOString(); });
  normaliseProjectJobs(seed);
  await env.DB.put("data", JSON.stringify(seed));
  return seed;
}
async function save(env, data) {
  const before = await env.DB.get("data", "json");
  const audit = data.audit || [];
  const changed = [];
  for (const collection of ["ledger", "invoices", "sites", "reminders"]) {
    const previous = new Map((before?.[collection] || []).map((r) => [r.id, r]));
    for (const row of data[collection] || []) {
      const old = previous.get(row.id);
      if (JSON.stringify(old) !== JSON.stringify(row)) changed.push({ collection, id: row.id, before: old || null, after: row });
      previous.delete(row.id);
    }
    for (const [id, row] of previous) changed.push({ collection, id, before: row, after: null });
  }
  if (JSON.stringify(before?.business) !== JSON.stringify(data.business)) changed.push({ collection: "settings", before: before?.business || null, after: data.business });
  if (changed.length) audit.push({ at: new Date().toISOString(), actor: env.ACTOR || "Admin", changes: changed });
  data.audit = audit;
  await env.DB.put("data", JSON.stringify(data));
}

async function ventureRegistry(env) {
  return await env.DB.get("books_ventures", "json") || {
    company: { name: "Sunnymead Group Ltd", yearStart: "01-01", companyNumber: "", registeredAddress: "" },
    ventures: [{ id: "sunnymead-web", name: "Sunnymead Web", prefix: "SW", status: "active", kind: "web" }]
  };
}
function scopedEnv(env, venture) {
  const storage = env.DB;
  const key = venture.id === "sunnymead-web" ? "data" : "books:" + venture.id;
  return { ...env, VENTURE: venture, DB: {
    get: (_, format) => storage.get(key, format),
    put: (_, value) => storage.put(key, value)
  } };
}


const clean = (v, max = 500) => String(v ?? "").replace(/[\u0000-\u0008\u000b-\u001f]/g, " ").trim().slice(0, max);
const num = (v) => { const n = Math.round(Number(v) * 100) / 100; return Number.isFinite(n) ? n : 0; };
const date = (v) => {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(v || "")) return "";
  const parsed = new Date(v + "T12:00:00Z");
  return Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === v ? v : "";
};

function tidy(collection, item) {
  const id = clean(item.id, 40) || crypto.randomUUID().slice(0, 8);
  if (collection === "sites") {
    return {
      id, name: clean(item.name, 80), client: clean(item.client, 120), url: clean(item.url, 300),
      status: ["demo", "live", "paused", "ended"].includes(item.status) ? item.status : "demo",
      own: !!item.own, build: num(item.build), monthly: num(item.monthly),
      depositPaid: !!item.depositPaid, balancePaid: !!item.balancePaid,
      liveSince: date(item.liveSince), domain: clean(item.domain, 120), registrar: clean(item.registrar, 60),
      domainRenews: date(item.domainRenews), subStart: date(item.subStart), phone: clean(item.phone, 30), email: clean(item.email, 120),
      repo: clean(item.repo, 120), notes: clean(item.notes, 2000),
      lastCheck: item.lastCheck || null,
    };
  }
  if (collection === "ledger") {
    return {
      id, date: date(item.date) || new Date().toISOString().slice(0, 10),
      type: item.type === "out" ? "out" : "in",
      amount: Math.abs(num(item.amount)), category: clean(item.category, 40) || "Other",
      site: clean(item.site, 40), description: clean(item.description, 300),
      paid: !!item.paid, ref: clean(item.ref, 60),
      counterparty: clean(item.counterparty, 120), account: clean(item.account, 80),
      paidDate: date(item.paidDate), due: date(item.due), receipt: clean(item.receipt, 250),
      reconciled: !!item.reconciled,
      treatment: ["trading", "asset", "finance", "transfer"].includes(item.treatment) ? item.treatment : "trading",
      vat: Math.max(0, Math.min(Math.abs(num(item.amount)), num(item.vat))),
    };
  }
  return {
    id, title: clean(item.title, 120), due: date(item.due),
    repeat: ["none", "monthly", "yearly"].includes(item.repeat) ? item.repeat : "none",
    notes: clean(item.notes, 500),
  };
}

function addDays(d, n) { const x = new Date(`${d}T12:00:00Z`); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); }
function addMonths(d, n) { const x = new Date(`${d}T12:00:00Z`); x.setUTCMonth(x.getUTCMonth() + n); return x.toISOString().slice(0, 10); }
const prettyDate = (d) => new Date(`${d}T12:00:00Z`).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });

function addPeriod(d, repeat) {
  const x = new Date(`${d}T12:00:00Z`);
  if (repeat === "monthly") x.setUTCMonth(x.getUTCMonth() + 1);
  if (repeat === "yearly") x.setUTCFullYear(x.getUTCFullYear() + 1);
  return x.toISOString().slice(0, 10);
}

// ---------- handler ----------

export async function onRequest({ request, env, params }) {
  const path = "/" + [].concat(params.path || []).join("/");
  const method = request.method;
  if (!env.DB) return json({ error: "The DB storage is not connected yet. Add a KV binding called DB in Cloudflare." }, 500);
  // Only public presentation fields leave the admin data store.
  if (path === "/projects" && method === "GET") {
    const data = await env.DB.get("data", "json");
    if (!data) return json({ error: "Projects are not available yet" }, 503);
    const projects = (data.sites || []).filter((site) => (site.status === "demo" || (!site.own && site.status === "live")))
      .filter((site) => { try { return ["http:", "https:"].includes(new URL(site.url).protocol); } catch { return false; } })
      .map(({ id, name, url, status }) => ({ id, name, url, status }));
    return json({ projects });
  }
  if (!sessionSecret(env)) return json({ error: "Set ADMIN_SESSION_SECRET in Cloudflare. The existing ADMIN_PASSWORD secret can also sign sessions." }, 500);

  if (path === "/auth-config" && method === "GET") {
    if (!googleEnabled(env)) return json({ googleEnabled: false });
    const expires = Math.floor(Date.now() / 1000) + 600;
    const challenge = `${expires}.${crypto.randomUUID()}`;
    const nonce = `${challenge}.${await hmac(sessionSecret(env), "nonce." + challenge)}`;
    return json({ googleEnabled: true, clientId: env.GOOGLE_CLIENT_ID, nonce }, 200, {
      "set-cookie": `${GOOGLE_NONCE_COOKIE}=${nonce}; Path=/api; Max-Age=600; HttpOnly; Secure; SameSite=Strict`
    });
  }

  if (path === "/google-login" && method === "POST") {
    if (!googleEnabled(env)) return json({ error: "Google sign-in is not configured yet." }, 503);
    if (request.headers.get("origin") !== new URL(request.url).origin ||
        !(request.headers.get("content-type") || "").startsWith("application/json")) {
      return json({ error: "Please sign in from the admin page." }, 403);
    }
    const nonce = readCookie(request, GOOGLE_NONCE_COOKIE);
    const [expires, random, sig] = nonce.split(".");
    if (!/^\d+$/.test(expires || "") || Number(expires) <= Date.now() / 1000 || !random || !sig ||
        !safeEqual(sig, await hmac(sessionSecret(env), `nonce.${expires}.${random}`))) {
      return json({ error: "Sign-in expired. Refresh the page and try again." }, 401);
    }
    const { credential } = await request.json().catch(() => ({}));
    let claims;
    try { claims = await verifyGoogleToken(credential, env.GOOGLE_CLIENT_ID, nonce); }
    catch { return json({ error: "Could not verify Google sign-in. Refresh the page and try again." }, 401); }
    const email = claims.email.trim().toLowerCase();
    if (!allowedEmails(env).includes(email)) return json({ error: "This Google account does not have admin access." }, 403);
    const sessionExpires = Math.floor(Date.now() / 1000) + DAYS_30;
    const payload = `google.${sessionExpires}.${encodeEmail(email)}`;
    const token = `${payload}.${await hmac(sessionSecret(env), payload)}`;
    const headers = new Headers({ "set-cookie": sessionCookie(token) });
    headers.append("set-cookie", `${GOOGLE_NONCE_COOKIE}=; Path=/api; Max-Age=0; HttpOnly; Secure; SameSite=Strict`);
    headers.set("content-type", "application/json");
    headers.set("cache-control", "no-store");
    return new Response(JSON.stringify({ ok: true }), { headers });
  }

  if (path === "/login") return json({ error: "Use Google sign-in. Password login has been removed." }, 410);

  if (path === "/logout") {
    return json({ ok: true }, 200, { "set-cookie": `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict` });
  }

  if (!(await loggedIn(request, env))) return json({ error: "Please log in" }, 401);

  if (method === "POST" && (request.headers.get("origin") !== new URL(request.url).origin || !(request.headers.get("content-type") || "").startsWith("application/json"))) {
    return json({ error: "Submit changes from the books page." }, 403);
  }
  const registry = await ventureRegistry(env);
  if (path === "/ventures" && method === "GET") return json(registry);
  if (path === "/ventures" && method === "POST") {
    const input = await request.json().catch(() => ({}));
    const name = clean(input.name, 100);
    if (!name) return json({ error: "Enter a trading name." }, 400);
    if (registry.ventures.some((v) => v.name.toLowerCase() === name.toLowerCase())) return json({ error: "That trading name already exists." }, 409);
    const prefix = clean(input.prefix, 8).toUpperCase().replace(/[^A-Z0-9]/g, "");
    if (!prefix || registry.ventures.some((v) => v.prefix === prefix)) return json({ error: "Choose a unique invoice prefix, for example MB." }, 400);
    const venture = { id: crypto.randomUUID(), name, prefix, kind: "general", status: input.status === "planned" ? "planned" : "active" };
    registry.ventures.push(venture);
    await env.DB.put("books_ventures", JSON.stringify(registry));
    return json({ ok: true, venture });
  }
  if (path === "/venture-status" && method === "POST") {
    const input = await request.json().catch(() => ({}));
    const selected = registry.ventures.find((v) => v.id === input.id);
    if (!selected || !["active", "planned"].includes(input.status)) return json({ error: "Choose a trading name and status." }, 400);
    selected.status = input.status;
    await env.DB.put("books_ventures", JSON.stringify(registry));
    return json({ ok: true });
  }
  if (path === "/company-settings" && method === "POST") {
    const input = await request.json().catch(() => ({}));
    if (!date("2000-" + input.yearStart)) return json({ error: "Enter a valid year start in MM-DD format." }, 400);
    registry.company = { name: clean(input.name, 120) || "Sunnymead Group Ltd", companyNumber: clean(input.companyNumber, 30), registeredAddress: clean(input.registeredAddress, 300), yearStart: input.yearStart };
    await env.DB.put("books_ventures", JSON.stringify(registry));
    return json({ ok: true });
  }
  if (path === "/company-data" && method === "GET") {
    const books = await Promise.all(registry.ventures.map(async (venture) => ({
      venture, data: await load(scopedEnv(env, venture))
    })));
    return json({ ...registry, books });
  }
  const ventureId = new URL(request.url).searchParams.get("venture") || "sunnymead-web";
  const venture = registry.ventures.find((v) => v.id === ventureId);
  if (!venture) return json({ error: "Trading name not found." }, 404);
  const actorParts = readCookie(request, COOKIE).split(".");
  env = scopedEnv({ ...env, ACTOR: new TextDecoder().decode(decodeBase64Url(actorParts[2])) }, venture);

  if (path === "/data" && method === "GET") {
    const data = await load(env);
    return json({ ...data, venture, company: registry.company });
  }

  if (path === "/invoice-create" && method === "POST") {
    const input = await request.json().catch(() => ({}));
    const customer = clean(input.customer, 120), description = clean(input.description, 500);
    const amount = num(input.amount), issued = date(input.date), due = date(input.due);
    if (!customer || !description || !(amount > 0) || !issued || !due || due < issued) return json({ error: "Add a customer, description, positive amount and valid invoice/due dates." }, 400);
    const data = await load(env);
    const next = Math.max(1, Number(data.business.nextNumber) || 1);
    const number = venture.prefix + String(next).padStart(4, "0");
    if (data.invoices.some((i) => i.number === number)) return json({ error: "This invoice number exists. Update the next number in Settings." }, 409);
    data.business.nextNumber = next + 1;
    const id = crypto.randomUUID(), ledgerId = crypto.randomUUID();
    if (Number(input.vat || 0) < 0 || Number(input.vat || 0) > amount) return json({ error: "VAT included must be between zero and the invoice total." }, 400);
    const vat = Math.max(0, Math.min(amount, num(input.vat)));
    data.invoices.push({ id, number, kind: "general", site: "", customer, customerAddress: clean(input.customerAddress, 300), customerEmail: clean(input.customerEmail, 120), date: issued, due, lines: [{ desc: description, amount }], total: amount, vat, note: clean(input.note, 500), ledgerId,
      issuer: { ...data.business, name: venture.name, legalName: registry.company.name, companyNumber: registry.company.companyNumber, registeredAddress: registry.company.registeredAddress } });
    data.ledger.push(tidy("ledger", { id: ledgerId, date: issued, due, type: "in", amount, vat, counterparty: customer, description: "Invoice " + number + ": " + description, category: "Sales", paid: false, ref: "inv-" + id }));
    await save(env, data);
    return json({ ok: true, id, number });
  }

  if (path === "/save" && method === "POST") {
    const { collection, item } = await request.json().catch(() => ({}));
    if (!COLLECTIONS.includes(collection) || !item) return json({ error: "Bad request" }, 400);
    const data = await load(env);
    if (collection === "ledger" && (!date(item.date) || !(Number(item.amount) > 0))) return json({ error: "Enter a date and an amount greater than zero." }, 400);
    const row = tidy(collection, item);
    if (collection === "ledger" && (row.vat > row.amount || Number(item.vat || 0) < 0 || Number(item.vat || 0) > row.amount)) return json({ error: "VAT included must be between zero and the gross amount." }, 400);
    if (collection === "ledger" && row.reconciled && !row.paid) return json({ error: "Mark the transaction paid before matching it to a statement." }, 400);
    const i = data[collection].findIndex((x) => x.id === row.id);
    if (collection === "sites") {
      if (i >= 0) {
        row.jobNumber = data.sites[i].jobNumber;
        if (data.sites[i].createdAt) row.createdAt = data.sites[i].createdAt;
      } else {
        row.jobNumber = data.nextJobNumber++;
        row.createdAt = new Date().toISOString();
      }
    }
    if (collection === "ledger" && i >= 0 && data.invoices.some((inv) => inv.ledgerId === row.id)) {
      const old = data.ledger[i];
      if (row.amount !== old.amount || row.type !== old.type || row.date !== old.date || row.vat !== (old.vat || 0) || row.treatment !== (old.treatment || "trading")) return json({ error: "Invoice amounts and dates cannot be changed through an entry. Create a replacement invoice instead." }, 409);
    }
    if (i >= 0) data[collection][i] = row; else data[collection].push(row);
    await save(env, data);
    return json({ ok: true, item: row });
  }

  if (path === "/delete" && method === "POST") {
    const { collection, id } = await request.json().catch(() => ({}));
    if (!COLLECTIONS.includes(collection)) return json({ error: "Bad request" }, 400);
    const data = await load(env);
    if (collection === "ledger" && data.invoices.some((inv) => inv.ledgerId === id)) return json({ error: "This entry belongs to an invoice. Keep it with the invoice." }, 409);
    data[collection] = data[collection].filter((x) => x.id !== id);
    await save(env, data);
    return json({ ok: true });
  }

  // Mark a reminder done: repeating ones roll forward, one offs are removed.
  if (path === "/reminder-done" && method === "POST") {
    const { id } = await request.json().catch(() => ({}));
    const data = await load(env);
    const r = data.reminders.find((x) => x.id === id);
    if (!r) return json({ error: "Not found" }, 404);
    if (r.repeat === "none" || !r.due) data.reminders = data.reminders.filter((x) => x.id !== id);
    else r.due = addPeriod(r.due, r.repeat);
    await save(env, data);
    return json({ ok: true });
  }

  if (path === "/monthly-fees") return json({ error: "Create an invoice to record monthly income, so fees are not counted twice." }, 410);

  // ----- invoices -----
  // kind "build": invoice 1, the website build.
  // kind "sub": the next 3 months of the monthly fee (invoice 2 is the first one).
  if (path === "/invoice" && method === "POST") {
    const { site: siteId, kind } = await request.json().catch(() => ({}));
    const data = await load(env);
    const s = data.sites.find((x) => x.id === siteId);
    if (!s) return json({ error: "Project not found" }, 404);
    const today = new Date().toISOString().slice(0, 10);
    const mine = data.invoices.filter((i) => i.site === s.id);
    let lines, periodFrom = "", periodTo = "", note = "";
    if (kind === "build") {
      if (mine.some((i) => i.kind === "build")) return json({ error: "This project already has a build invoice" }, 409);
      if (!(s.build > 0)) return json({ error: "Add a build price to this project first" }, 400);
      lines = [{ desc: `Website design and build: ${s.name}`, amount: s.build }];
      note = data.business.buildTerms || "";
    } else if (kind === "sub") {
      if (!(s.monthly > 0)) return json({ error: "Add a monthly fee to this project first" }, 400);
      const last = mine.filter((i) => i.kind === "sub").sort((a, b) => b.periodTo.localeCompare(a.periodTo))[0];
      periodFrom = last ? addDays(last.periodTo, 1) : (s.subStart || s.liveSince || today);
      periodTo = addDays(addMonths(periodFrom, 3), -1);
      lines = [{ desc: `Website hosting, care and updates: ${s.name}, ${prettyDate(periodFrom)} to ${prettyDate(periodTo)} (3 months at £${s.monthly} a month)`, amount: Math.round(s.monthly * 3 * 100) / 100 }];
    } else return json({ error: "Bad invoice type" }, 400);
    data.business.nextNumber = (data.business.nextNumber || 1);
    const number = `${venture.prefix}${String(data.business.nextNumber).padStart(4, "0")}`;
    if (data.invoices.some((i) => i.number === number)) return json({ error: "This invoice number already exists. Update the next number in Settings." }, 409);
    data.business.nextNumber++;
    const total = lines.reduce((a, l) => a + l.amount, 0);
    const id = crypto.randomUUID().slice(0, 8);
    const ledgerId = crypto.randomUUID().slice(0, 8);
    const due = addDays(today, Number(data.business.payDays || 14));
    data.invoices.push({ id, number, site: s.id, kind, date: today, due, lines, total, periodFrom, periodTo, note, ledgerId, issuer: { ...data.business, name: venture.name, legalName: registry.company.name, companyNumber: registry.company.companyNumber, registeredAddress: registry.company.registeredAddress } });
    data.ledger.push(tidy("ledger", { id: ledgerId, date: today, type: "in", amount: total, category: kind === "build" ? "Build" : "Maintenance", site: s.id, description: `Invoice ${number}: ${kind === "build" ? "website build" : "3 months care"}`, paid: false, ref: `inv-${id}` }));
    await save(env, data);
    return json({ ok: true, id, number });
  }

  if (path === "/invoice-delete" && method === "POST") {
    const { id } = await request.json().catch(() => ({}));
    const data = await load(env);
    const inv = data.invoices.find((i) => i.id === id);
    if (!inv) return json({ error: "Not found" }, 404);
    const payment = data.ledger.find((l) => l.id === inv.ledgerId);
    if (payment && (payment.paid || payment.reconciled)) return json({ error: "A paid or statement-matched invoice cannot be undone. Review its payment record first." }, 409);
    data.invoices = data.invoices.filter((i) => i.id !== id);
    data.ledger = data.ledger.filter((l) => l.id !== inv.ledgerId);
    await save(env, data);
    return json({ ok: true });
  }

  if (path === "/business" && method === "POST") {
    const b = await request.json().catch(() => ({}));
    const data = await load(env);
    const keep = data.business.nextNumber;
    data.business = {
      name: clean(b.name, 100), address: clean(b.address, 300), email: clean(b.email, 120), phone: clean(b.phone, 30),
      bankName: clean(b.bankName, 60), accountName: clean(b.accountName, 80), sortCode: clean(b.sortCode, 12), accountNumber: clean(b.accountNumber, 12),
      payDays: Math.min(90, Math.max(0, parseInt(b.payDays, 10) || 14)), buildTerms: clean(b.buildTerms, 300), footer: clean(b.footer, 300),
      nextNumber: Math.max(1, parseInt(b.nextNumber, 10) || keep || 1),
    };
    await save(env, data);
    return json({ ok: true });
  }

  // Check a site is up.
  if (path === "/check" && method === "POST") {
    const { id } = await request.json().catch(() => ({}));
    const data = await load(env);
    const s = data.sites.find((x) => x.id === id);
    if (!s || !/^https?:\/\//.test(s.url)) return json({ error: "No web address saved for this site" }, 400);
    const t0 = Date.now();
    let result;
    try {
      const res = await fetch(s.url, { method: "GET", redirect: "follow", headers: { "user-agent": "Sunnymead uptime check" }, signal: AbortSignal.timeout(10000) });
      result = { ok: res.ok, status: res.status, ms: Date.now() - t0, at: new Date().toISOString() };
    } catch (e) {
      result = { ok: false, status: 0, ms: Date.now() - t0, at: new Date().toISOString(), error: String(e.message || e).slice(0, 120) };
    }
    s.lastCheck = result;
    await save(env, data);
    return json(result);
  }

  return json({ error: "Not found" }, 404);
}
