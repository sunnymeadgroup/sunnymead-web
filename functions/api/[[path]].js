// Sunnymead admin API (Cloudflare Pages Function).
// Needs, in the Pages project settings:
//   KV binding   DB              (Settings > Bindings > KV namespace)
//   Secret       ADMIN_PASSWORD  (Settings > Variables and Secrets)

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

async function loggedIn(request, env) {
  const m = (request.headers.get("cookie") || "").match(new RegExp(`${COOKIE}=([^;]+)`));
  if (!m || !env.ADMIN_PASSWORD) return false;
  const [expires, sig] = decodeURIComponent(m[1]).split(".");
  if (!expires || !sig || Date.now() / 1000 > Number(expires)) return false;
  return safeEqual(sig, await hmac(env.ADMIN_PASSWORD, `admin.${expires}`));
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
    created: today,
  };
};

async function load(env) {
  const data = await env.DB.get("data", "json");
  if (data) return data;
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
      domainRenews: date(item.domainRenews), phone: clean(item.phone, 30), email: clean(item.email, 120),
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
