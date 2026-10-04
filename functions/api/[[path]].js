// Sunnymead admin API (Cloudflare Pages Function).
// Needs, in the Pages project settings:
//   KV binding   DB              (Settings > Bindings > KV namespace)
//   Secret       ADMIN_PASSWORD  (Settings > Variables and Secrets)
//   Variable     GOOGLE_CLIENT_ID (Google OAuth Web application client ID)
//   Variable     ADMIN_GOOGLE_EMAILS (comma-separated allowed admin emails)

const COLLECTIONS = ["sites", "ledger", "reminders"];
const COOKIE = "sm_admin";
const DAYS_30 = 60 * 60 * 24 * 30;

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
  if (!env.ADMIN_PASSWORD) return false;
  const parts = readCookie(request, COOKIE).split(".");
  if (parts[0] === "google" && parts.length === 4) {
    const [, expires, encodedEmail, sig] = parts;
    if (!/^\d+$/.test(expires) || Date.now() / 1000 >= Number(expires)) return false;
    try {
      const email = new TextDecoder().decode(decodeBase64Url(encodedEmail));
      return googleEnabled(env) && allowedEmails(env).includes(email) &&
        safeEqual(sig, await hmac(env.ADMIN_PASSWORD, `google.${expires}.${encodedEmail}`));
    } catch { return false; }
  }
  const [expires, sig] = parts;
  if (parts.length !== 2 || !/^\d+$/.test(expires) || !sig || Date.now() / 1000 >= Number(expires)) return false;
  return safeEqual(sig, await hmac(env.ADMIN_PASSWORD, `admin.${expires}`));
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

async function load(env) {
  const data = await env.DB.get("data", "json");
  if (data) {
    data.invoices = data.invoices || [];
    data.business = { name: "Sunnymead Web", email: "web@sunnymeadgroup.co.uk", payDays: 14, buildTerms: "£150 deposit to start, £150 when you are happy with the website.", nextNumber: 1, ...(data.business || {}) };
    return data;
  }
  const seed = SEED();
  await env.DB.put("data", JSON.stringify(seed));
  return seed;
}
const save = (env, data) => env.DB.put("data", JSON.stringify(data));

const clean = (v, max = 500) => String(v ?? "").replace(/[\u0000-\u0008\u000b-\u001f]/g, " ").trim().slice(0, max);
const num = (v) => { const n = Math.round(Number(v) * 100) / 100; return Number.isFinite(n) ? n : 0; };
const date = (v) => (/^\d{4}-\d{2}-\d{2}$/.test(v || "") ? v : "");

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
      paid: item.type === "out" ? true : !!item.paid, ref: clean(item.ref, 60),
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
  if (!env.ADMIN_PASSWORD) return json({ error: "Set ADMIN_PASSWORD in Cloudflare first." }, 500);

  if (path === "/auth-config" && method === "GET") {
    if (!googleEnabled(env)) return json({ googleEnabled: false });
    const expires = Math.floor(Date.now() / 1000) + 600;
    const challenge = `${expires}.${crypto.randomUUID()}`;
    const nonce = `${challenge}.${await hmac(env.ADMIN_PASSWORD, "nonce." + challenge)}`;
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
        !safeEqual(sig, await hmac(env.ADMIN_PASSWORD, `nonce.${expires}.${random}`))) {
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
    const token = `${payload}.${await hmac(env.ADMIN_PASSWORD, payload)}`;
    const headers = new Headers({ "set-cookie": sessionCookie(token) });
    headers.append("set-cookie", `${GOOGLE_NONCE_COOKIE}=; Path=/api; Max-Age=0; HttpOnly; Secure; SameSite=Strict`);
    headers.set("content-type", "application/json");
    headers.set("cache-control", "no-store");
    return new Response(JSON.stringify({ ok: true }), { headers });
  }

  if (path === "/login" && method === "POST") {
    const { password } = await request.json().catch(() => ({}));
    if (!safeEqual(String(password || ""), env.ADMIN_PASSWORD)) {
      await new Promise((r) => setTimeout(r, 800)); // slow down guessing
      return json({ error: "Wrong password" }, 401);
    }
    const expires = Math.floor(Date.now() / 1000) + DAYS_30;
    const token = `${expires}.${await hmac(env.ADMIN_PASSWORD, `admin.${expires}`)}`;
    return json({ ok: true }, 200, { "set-cookie": `${COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=${DAYS_30}; HttpOnly; Secure; SameSite=Strict` });
  }

  if (path === "/logout") {
    return json({ ok: true }, 200, { "set-cookie": `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict` });
  }

  if (!(await loggedIn(request, env))) return json({ error: "Please log in" }, 401);

  if (path === "/data" && method === "GET") return json(await load(env));

  if (path === "/save" && method === "POST") {
    const { collection, item } = await request.json().catch(() => ({}));
    if (!COLLECTIONS.includes(collection) || !item) return json({ error: "Bad request" }, 400);
    const data = await load(env);
    const row = tidy(collection, item);
    const i = data[collection].findIndex((x) => x.id === row.id);
    if (i >= 0) data[collection][i] = row; else data[collection].push(row);
    await save(env, data);
    return json({ ok: true, item: row });
  }

  if (path === "/delete" && method === "POST") {
    const { collection, id } = await request.json().catch(() => ({}));
    if (!COLLECTIONS.includes(collection)) return json({ error: "Bad request" }, 400);
    const data = await load(env);
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

  // Add this month's maintenance fees as income (unpaid) for every live client site.
  if (path === "/monthly-fees" && method === "POST") {
    const { month } = await request.json().catch(() => ({}));
    if (!/^\d{4}-\d{2}$/.test(month || "")) return json({ error: "Bad month" }, 400);
    const data = await load(env);
    let added = 0;
    for (const s of data.sites) {
      if (s.status !== "live" || s.own || !(s.monthly > 0)) continue;
      const ref = `fee-${s.id}-${month}`;
      if (data.ledger.some((x) => x.ref === ref)) continue;
      data.ledger.push(tidy("ledger", { date: `${month}-01`, type: "in", amount: s.monthly, category: "Maintenance", site: s.id, description: `${s.name} monthly fee`, paid: false, ref }));
      added++;
    }
    await save(env, data);
    return json({ ok: true, added });
  }

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
    const number = `SW${String(data.business.nextNumber).padStart(4, "0")}`;
    data.business.nextNumber++;
    const total = lines.reduce((a, l) => a + l.amount, 0);
    const id = crypto.randomUUID().slice(0, 8);
    const ledgerId = crypto.randomUUID().slice(0, 8);
    const due = addDays(today, Number(data.business.payDays || 14));
    data.invoices.push({ id, number, site: s.id, kind, date: today, due, lines, total, periodFrom, periodTo, note, ledgerId });
    data.ledger.push(tidy("ledger", { id: ledgerId, date: today, type: "in", amount: total, category: kind === "build" ? "Build" : "Maintenance", site: s.id, description: `Invoice ${number}: ${kind === "build" ? "website build" : "3 months care"}`, paid: false, ref: `inv-${id}` }));
    await save(env, data);
    return json({ ok: true, id, number });
  }

  if (path === "/invoice-delete" && method === "POST") {
    const { id } = await request.json().catch(() => ({}));
    const data = await load(env);
    const inv = data.invoices.find((i) => i.id === id);
    if (!inv) return json({ error: "Not found" }, 404);
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
