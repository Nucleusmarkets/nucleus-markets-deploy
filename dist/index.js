// server/index.ts
import express from "express";
import helmet from "helmet";
import compression from "compression";
import path2 from "node:path";
import fs2 from "node:fs";
import { fileURLToPath } from "node:url";

// server/auth.ts
import { createHash, randomBytes as randomBytes2 } from "node:crypto";
import { Router } from "express";

// server/db.ts
import pg from "pg";
var { Pool } = pg;
var connectionString = process.env.DATABASE_URL ?? "";
var dbConfigured = connectionString.length > 0;
function sslFor(url) {
  const mode = process.env.DATABASE_SSL;
  if (mode === "disable") return void 0;
  if (mode === "require") return { rejectUnauthorized: false };
  if (/localhost|127\.0\.0\.1|\.internal(?:$|[:/])/.test(url)) return void 0;
  return { rejectUnauthorized: false };
}
var max = Number(process.env.DATABASE_POOL_MAX) || 8;
var pool = dbConfigured ? new Pool({
  connectionString,
  ssl: sslFor(connectionString),
  max,
  idleTimeoutMillis: 3e4,
  connectionTimeoutMillis: 1e4
}) : null;
pool?.on("error", (err) => {
  console.error("[db] idle client error:", err.message);
});
function db() {
  if (!pool) throw new Error("DATABASE_URL is not set");
  return pool;
}
async function query(text, params = []) {
  return db().query(text, params);
}
async function withTransaction(fn) {
  const client = await db().connect();
  try {
    await client.query("begin");
    const out = await fn(client);
    await client.query("commit");
    return out;
  } catch (err) {
    await client.query("rollback").catch(() => {
    });
    throw err;
  } finally {
    client.release();
  }
}
async function dbHealthy() {
  if (!pool) return false;
  try {
    await pool.query("select 1");
    return true;
  } catch {
    return false;
  }
}

// server/passwords.ts
import { randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
var scrypt = promisify(scryptCb);
var PARAMS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
var KEYLEN = 64;
async function hashPassword(password) {
  const salt = randomBytes(16);
  const key = await scrypt(password, salt, KEYLEN, PARAMS);
  return ["scrypt", PARAMS.N, PARAMS.r, PARAMS.p, salt.toString("base64"), key.toString("base64")].join("$");
}
async function verifyPassword(password, stored) {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const [, nRaw, rRaw, pRaw, saltB64, keyB64] = parts;
  const N = Number(nRaw);
  const r = Number(rRaw);
  const p = Number(pRaw);
  if (!Number.isFinite(N) || !Number.isFinite(r) || !Number.isFinite(p)) return false;
  let expected;
  try {
    expected = Buffer.from(keyB64, "base64");
  } catch {
    return false;
  }
  const actual = await scrypt(password, Buffer.from(saltB64, "base64"), expected.length, {
    ...PARAMS,
    N,
    r,
    p
  });
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
var DECOY = "scrypt$16384$8$1$MDAwMDAwMDAwMDAwMDAwMA==$" + Buffer.alloc(64).toString("base64");
async function burnTime(password) {
  await verifyPassword(password, DECOY).catch(() => false);
}

// server/migrate.ts
var statements = [
  `create table if not exists users (
     id                bigserial primary key,
     email             text        not null,
     first_name        text        not null,
     last_name         text        not null,
     password_hash     text        not null,
     status            text        not null default 'active',
     email_verified_at timestamptz,
     terms_accepted_at timestamptz not null,
     signup_ip         text,
     created_at        timestamptz not null default now(),
     updated_at        timestamptz not null default now()
   )`,
  // Case-insensitive uniqueness: the registration race is settled by the database,
  // not by a check-then-insert that two concurrent signups can both pass.
  `create unique index if not exists users_email_key on users (lower(email))`,
  `create table if not exists sessions (
     id           bigserial primary key,
     token_hash   text        not null unique,
     user_id      bigint      not null references users (id) on delete cascade,
     created_at   timestamptz not null default now(),
     last_seen_at timestamptz not null default now(),
     expires_at   timestamptz not null,
     ip           text,
     user_agent   text
   )`,
  `create index if not exists sessions_user_id_idx on sessions (user_id)`,
  `create index if not exists sessions_expires_at_idx on sessions (expires_at)`,
  // Audit trail and the source of truth for throttling. Never stores a password.
  `create table if not exists auth_events (
     id         bigserial primary key,
     kind       text        not null,
     email      text,
     ip         text,
     created_at timestamptz not null default now()
   )`,
  `create index if not exists auth_events_ip_idx on auth_events (ip, kind, created_at desc)`,
  `create index if not exists auth_events_email_idx on auth_events (lower(email), kind, created_at desc)`,
  // Added after the first release, so it has to be an alter rather than a column in
  // the create above - existing databases already have the table.
  `alter table users add column if not exists role text not null default 'customer'`,
  // Residency, and the sophisticated-trader declaration that "Other" requires. Both
  // are claims the customer made about themselves, so the timestamp matters as much
  // as the value - it is the record of when they said it.
  `alter table users add column if not exists country text`,
  `alter table users add column if not exists sophisticated_at timestamptz`,
  `create index if not exists users_role_idx on users (role) where role <> 'customer'`,
  // Every staff action against a customer record, kept separately from auth_events
  // so an operator cannot quietly suspend or reinstate an account.
  `create table if not exists admin_actions (
     id          bigserial primary key,
     admin_id    bigint      not null references users (id),
     target_id   bigint      references users (id) on delete set null,
     action      text        not null,
     detail      text,
     ip          text,
     created_at  timestamptz not null default now()
   )`,
  `create index if not exists admin_actions_created_idx on admin_actions (created_at desc)`,
  `create index if not exists admin_actions_target_idx on admin_actions (target_id, created_at desc)`,
  // Single-use, expiring links for "set your password" invites and resets. Only the
  // hash is stored, so the link in someone's inbox cannot be rebuilt from the database.
  `create table if not exists password_tokens (
     id         bigserial primary key,
     token_hash text        not null unique,
     user_id    bigint      not null references users (id) on delete cascade,
     purpose    text        not null,
     expires_at timestamptz not null,
     used_at    timestamptz,
     created_at timestamptz not null default now()
   )`,
  `create index if not exists password_tokens_user_idx on password_tokens (user_id)`,
  // One row per deployed build. The unique commit is what stops a restart, a second
  // instance or a rollback from emailing the admins about the same build twice.
  `create table if not exists deploys (
     id          bigserial primary key,
     commit      text        not null unique,
     subject     text,
     deployed_at timestamptz not null default now(),
     notified_at timestamptz
   )`
];
async function syncAdmins() {
  const emails = (process.env.ADMIN_EMAILS ?? "").split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
  if (emails.length === 0) return 0;
  const res = await query(
    `update users set role = 'admin', updated_at = now()
      where lower(email) = any($1::text[]) and role <> 'admin'`,
    [emails]
  );
  return res.rowCount ?? 0;
}
function isListedAdmin(email) {
  return (process.env.ADMIN_EMAILS ?? "").split(",").map((e) => e.trim().toLowerCase()).filter(Boolean).includes(email.toLowerCase());
}
async function migrate() {
  for (const sql of statements) {
    await query(sql);
  }
}
async function pruneSessions() {
  const res = await query("delete from sessions where expires_at < now()");
  return res.rowCount ?? 0;
}

// shared/countries.ts
var COUNTRIES = [
  { code: "AE", name: "United Arab Emirates" },
  { code: "AL", name: "Albania" },
  { code: "AM", name: "Armenia" },
  { code: "AO", name: "Angola" },
  { code: "AR", name: "Argentina" },
  { code: "AT", name: "Austria" },
  { code: "AU", name: "Australia" },
  { code: "AZ", name: "Azerbaijan" },
  { code: "BA", name: "Bosnia and Herzegovina" },
  { code: "BD", name: "Bangladesh" },
  { code: "BE", name: "Belgium" },
  { code: "BG", name: "Bulgaria" },
  { code: "BH", name: "Bahrain" },
  { code: "BR", name: "Brazil" },
  { code: "BW", name: "Botswana" },
  { code: "CA", name: "Canada" },
  { code: "CH", name: "Switzerland" },
  { code: "CL", name: "Chile" },
  { code: "CM", name: "Cameroon" },
  { code: "CO", name: "Colombia" },
  { code: "CR", name: "Costa Rica" },
  { code: "CY", name: "Cyprus" },
  { code: "CZ", name: "Czechia" },
  { code: "DE", name: "Germany" },
  { code: "DK", name: "Denmark" },
  { code: "DO", name: "Dominican Republic" },
  { code: "DZ", name: "Algeria" },
  { code: "EC", name: "Ecuador" },
  { code: "EE", name: "Estonia" },
  { code: "EG", name: "Egypt" },
  { code: "ES", name: "Spain" },
  { code: "ET", name: "Ethiopia" },
  { code: "FI", name: "Finland" },
  { code: "FR", name: "France" },
  { code: "GB", name: "United Kingdom" },
  { code: "GE", name: "Georgia" },
  { code: "GH", name: "Ghana" },
  { code: "GR", name: "Greece" },
  { code: "GT", name: "Guatemala" },
  { code: "HK", name: "Hong Kong" },
  { code: "HR", name: "Croatia" },
  { code: "HU", name: "Hungary" },
  { code: "ID", name: "Indonesia" },
  { code: "IE", name: "Ireland" },
  { code: "IL", name: "Israel" },
  { code: "IN", name: "India" },
  { code: "IQ", name: "Iraq" },
  { code: "IS", name: "Iceland" },
  { code: "IT", name: "Italy" },
  { code: "JM", name: "Jamaica" },
  { code: "JO", name: "Jordan" },
  { code: "JP", name: "Japan" },
  { code: "KE", name: "Kenya" },
  { code: "KG", name: "Kyrgyzstan" },
  { code: "KH", name: "Cambodia" },
  { code: "KR", name: "South Korea" },
  { code: "KW", name: "Kuwait" },
  { code: "KZ", name: "Kazakhstan" },
  { code: "LB", name: "Lebanon" },
  { code: "LK", name: "Sri Lanka" },
  { code: "LT", name: "Lithuania" },
  { code: "LU", name: "Luxembourg" },
  { code: "LV", name: "Latvia" },
  { code: "MA", name: "Morocco" },
  { code: "MD", name: "Moldova" },
  { code: "ME", name: "Montenegro" },
  { code: "MK", name: "North Macedonia" },
  { code: "MN", name: "Mongolia" },
  { code: "MT", name: "Malta" },
  { code: "MU", name: "Mauritius" },
  { code: "MV", name: "Maldives" },
  { code: "MX", name: "Mexico" },
  { code: "MY", name: "Malaysia" },
  { code: "MZ", name: "Mozambique" },
  { code: "NA", name: "Namibia" },
  { code: "NG", name: "Nigeria" },
  { code: "NL", name: "Netherlands" },
  { code: "NO", name: "Norway" },
  { code: "NP", name: "Nepal" },
  { code: "NZ", name: "New Zealand" },
  { code: "OM", name: "Oman" },
  { code: "PA", name: "Panama" },
  { code: "PE", name: "Peru" },
  { code: "PH", name: "Philippines" },
  { code: "PK", name: "Pakistan" },
  { code: "PL", name: "Poland" },
  { code: "PT", name: "Portugal" },
  { code: "PY", name: "Paraguay" },
  { code: "QA", name: "Qatar" },
  { code: "RO", name: "Romania" },
  { code: "RS", name: "Serbia" },
  { code: "RW", name: "Rwanda" },
  { code: "SA", name: "Saudi Arabia" },
  { code: "SE", name: "Sweden" },
  { code: "SG", name: "Singapore" },
  { code: "SI", name: "Slovenia" },
  { code: "SK", name: "Slovakia" },
  { code: "SN", name: "Senegal" },
  { code: "TH", name: "Thailand" },
  { code: "TN", name: "Tunisia" },
  { code: "TR", name: "Turkey" },
  { code: "TT", name: "Trinidad and Tobago" },
  { code: "TW", name: "Taiwan" },
  { code: "TZ", name: "Tanzania" },
  { code: "UA", name: "Ukraine" },
  { code: "UG", name: "Uganda" },
  { code: "UY", name: "Uruguay" },
  { code: "UZ", name: "Uzbekistan" },
  { code: "VN", name: "Vietnam" },
  { code: "ZA", name: "South Africa" },
  { code: "ZM", name: "Zambia" },
  { code: "ZW", name: "Zimbabwe" },
  { code: "OTHER", name: "Other / not listed" }
];
var OTHER = "OTHER";
var BY_CODE = new Map(COUNTRIES.map((c) => [c.code, c]));
function isValidCountry(code) {
  return BY_CODE.has(code);
}
function needsSophisticatedDeclaration(code) {
  return code === OTHER;
}

// server/auth.ts
var COOKIE = "ns_session";
var SESSION_DAYS = 30;
var MIN_PASSWORD = 10;
var MAX_PASSWORD = 200;
var isProd = process.env.NODE_ENV === "production" || !!process.env.RENDER;
var LIMITS = {
  registerPerIpPerHour: Number(process.env.RATE_REGISTER_IP_HOUR) || 5,
  loginFailPerEmail: Number(process.env.RATE_LOGIN_EMAIL) || 8,
  loginFailPerIp: Number(process.env.RATE_LOGIN_IP) || 20,
  loginWindowMinutes: 15
};
function toPublic(row) {
  return {
    id: String(row.id),
    email: row.email,
    firstName: row.first_name,
    lastName: row.last_name,
    status: row.status,
    role: row.role,
    emailVerified: row.email_verified_at !== null,
    createdAt: new Date(row.created_at).toISOString()
  };
}
var EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
var WEAK = /* @__PURE__ */ new Set([
  "password12",
  "password123",
  "password1234",
  "1234567890",
  "12345678901",
  "qwertyuiop",
  "qwerty12345",
  "iloveyou12",
  "letmein123",
  "trustno1234",
  "nucleus123",
  "nucleusmarkets",
  "changeme123",
  "welcome1234",
  "admin12345"
]);
var Invalid = class extends Error {
  field;
  constructor(message, field) {
    super(message);
    this.field = field;
  }
};
function str(value) {
  return typeof value === "string" ? value.replace(/[\u0000-\u001f\u007f]/g, "").trim() : "";
}
function parseEmail(value) {
  const email = str(value).toLowerCase();
  if (!email) throw new Invalid("Enter your email address.", "email");
  if (email.length > 254 || !EMAIL_RE.test(email)) {
    throw new Invalid("That email address isn't valid.", "email");
  }
  return email;
}
function parsePassword(value, forRegistration) {
  const password = typeof value === "string" ? value : "";
  if (!password) throw new Invalid("Enter your password.", "password");
  if (!forRegistration) return password;
  if (password.length < MIN_PASSWORD) {
    throw new Invalid(`Use at least ${MIN_PASSWORD} characters.`, "password");
  }
  if (password.length > MAX_PASSWORD) throw new Invalid("That password is too long.", "password");
  if (WEAK.has(password.toLowerCase())) {
    throw new Invalid("That password is too easy to guess.", "password");
  }
  if (/^(.)\1+$/.test(password)) {
    throw new Invalid("That password is too easy to guess.", "password");
  }
  return password;
}
function parseName(value, field, label) {
  const name = str(value);
  if (!name) throw new Invalid(`Enter your ${label}.`, field);
  if (name.length > 80) throw new Invalid(`That ${label} is too long.`, field);
  return name;
}
function clientIp(req) {
  return (req.ip ?? req.socket.remoteAddress ?? "").toString().slice(0, 64);
}
async function countEvents(kind, column, value, minutes) {
  const where = column === "ip" ? "ip = $1" : "lower(email) = $1";
  const res = await query(
    `select count(*)::text as n from auth_events
      where kind = $2 and ${where} and created_at > now() - ($3 || ' minutes')::interval`,
    [value, kind, String(minutes)]
  );
  return Number(res.rows[0]?.n ?? 0);
}
async function logEvent(kind, email, ip) {
  await query("insert into auth_events (kind, email, ip) values ($1, $2, $3)", [
    kind,
    email,
    ip
  ]).catch((err) => console.error("[auth] could not record event:", err.message));
}
function hashToken(token) {
  return createHash("sha256").update(token).digest("hex");
}
function readCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) {
      return decodeURIComponent(part.slice(eq + 1).trim());
    }
  }
  return null;
}
function setSessionCookie(res, token) {
  res.cookie(COOKIE, token, {
    httpOnly: true,
    secure: isProd,
    sameSite: "lax",
    path: "/",
    maxAge: SESSION_DAYS * 24 * 60 * 60 * 1e3
  });
}
function clearSessionCookie(res) {
  res.clearCookie(COOKIE, { httpOnly: true, secure: isProd, sameSite: "lax", path: "/" });
}
async function createSession(userId, req) {
  const token = randomBytes2(32).toString("base64url");
  await query(
    `insert into sessions (token_hash, user_id, expires_at, ip, user_agent)
     values ($1, $2, now() + ($3 || ' days')::interval, $4, $5)`,
    [
      hashToken(token),
      userId,
      String(SESSION_DAYS),
      clientIp(req),
      str(req.headers["user-agent"]).slice(0, 300)
    ]
  );
  return token;
}
async function loadSession(req) {
  const token = readCookie(req, COOKIE);
  if (!token) return null;
  const res = await query(
    `select u.id, u.email, u.first_name, u.last_name, u.status, u.role, u.email_verified_at, u.created_at,
            s.id as session_id, (s.last_seen_at < now() - interval '5 minutes') as stale
       from sessions s join users u on u.id = s.user_id
      where s.token_hash = $1 and s.expires_at > now()`,
    [hashToken(token)]
  );
  const row = res.rows[0];
  if (!row) return null;
  if (row.stale) {
    await query("update sessions set last_seen_at = now() where id = $1", [row.session_id]).catch(
      () => {
      }
    );
  }
  return { user: toPublic(row), sessionId: String(row.session_id), status: row.status };
}
async function requireAuth(req, res, next) {
  try {
    const session = await loadSession(req);
    if (!session) {
      clearSessionCookie(res);
      res.status(401).json({ ok: false, message: "Please log in." });
      return;
    }
    if (session.status !== "active") {
      res.status(403).json({ ok: false, message: "This account isn't available. Contact support." });
      return;
    }
    req.user = session.user;
    req.sessionId = session.sessionId;
    next();
  } catch (err) {
    next(err);
  }
}
function requireAdmin(req, res, next) {
  void requireAuth(req, res, () => {
    if (req.user?.role !== "admin") {
      res.status(404).json({ ok: false, message: "Not found" });
      return;
    }
    next();
  });
}
var authRouter = Router();
async function findToken(token) {
  const res = await query(
    `select t.id, t.user_id, t.purpose, u.email, u.first_name
       from password_tokens t join users u on u.id = t.user_id
      where t.token_hash = $1 and t.used_at is null and t.expires_at > now()`,
    [hashToken(token)]
  );
  return res.rows[0] ?? null;
}
authRouter.get("/invite/:token", async (req, res, next) => {
  try {
    const row = await findToken(String(req.params.token));
    if (!row) {
      res.status(404).json({ ok: false, message: "This link has expired or has already been used." });
      return;
    }
    res.json({ ok: true, email: row.email, firstName: row.first_name, purpose: row.purpose });
  } catch (err) {
    next(err);
  }
});
authRouter.post("/set-password", async (req, res, next) => {
  const ip = clientIp(req);
  try {
    const token = String(req.body?.token ?? "");
    const password = parsePassword(req.body?.password, true);
    const row = await findToken(token);
    if (!row) {
      res.status(400).json({ ok: false, message: "This link has expired or has already been used." });
      return;
    }
    const passwordHash = await hashPassword(password);
    await withTransaction(async (client) => {
      await client.query(
        "update users set password_hash = $1, status = 'active', updated_at = now() where id = $2",
        [passwordHash, row.user_id]
      );
      await client.query("update password_tokens set used_at = now() where id = $1", [row.id]);
      await client.query("delete from sessions where user_id = $1", [row.user_id]);
    });
    const fresh = await query(
      `select id, email, first_name, last_name, status, role, email_verified_at, created_at
         from users where id = $1`,
      [row.user_id]
    );
    const user = fresh.rows[0];
    const session = await createSession(user.id, req);
    setSessionCookie(res, session);
    await logEvent(row.purpose === "invite" ? "password_set" : "password_reset", row.email, ip);
    res.json({ ok: true, user: toPublic(user) });
  } catch (err) {
    if (err instanceof Invalid) {
      res.status(400).json({ ok: false, message: err.message, field: err.field });
      return;
    }
    next(err);
  }
});
authRouter.post("/register", async (req, res, next) => {
  const ip = clientIp(req);
  let email = "";
  try {
    const firstName = parseName(req.body?.firstName, "firstName", "first name");
    const lastName = parseName(req.body?.lastName, "lastName", "last name");
    email = parseEmail(req.body?.email);
    const password = parsePassword(req.body?.password, true);
    const terms = req.body?.terms;
    if (!(terms === true || terms === "on" || terms === "true")) {
      throw new Invalid("Please accept the terms of business to continue.", "terms");
    }
    const country = str(req.body?.country).toUpperCase();
    if (!country) throw new Invalid("Select your country of residence.", "country");
    if (!isValidCountry(country)) {
      throw new Invalid("We can't open accounts in that country.", "country");
    }
    const declared = req.body?.sophisticated;
    const isSophisticated = declared === true || declared === "on" || declared === "true";
    if (needsSophisticatedDeclaration(country) && !isSophisticated) {
      throw new Invalid(
        "To continue under 'Other', confirm you qualify as a sophisticated trader.",
        "sophisticated"
      );
    }
    if (await countEvents("register", "ip", ip, 60) >= LIMITS.registerPerIpPerHour) {
      await logEvent("register_throttled", email, ip);
      res.status(429).json({
        ok: false,
        message: "Too many accounts opened from this connection. Try again later."
      });
      return;
    }
    const passwordHash = await hashPassword(password);
    const user = await withTransaction(async (client) => {
      const inserted = await client.query(
        `insert into users (email, first_name, last_name, password_hash, terms_accepted_at, signup_ip, country, sophisticated_at)
         values ($1, $2, $3, $4, now(), $5, $6, case when $7::boolean then now() else null end)
         returning id, email, first_name, last_name, status, role, email_verified_at, created_at`,
        [email, firstName, lastName, passwordHash, ip, country, isSophisticated]
      );
      return inserted.rows[0];
    });
    if (isListedAdmin(email)) {
      await query("update users set role = 'admin', updated_at = now() where id = $1", [user.id]);
      user.role = "admin";
    }
    const token = await createSession(user.id, req);
    setSessionCookie(res, token);
    await logEvent("register", email, ip);
    res.status(201).json({ ok: true, user: toPublic(user) });
  } catch (err) {
    if (err instanceof Invalid) {
      res.status(400).json({ ok: false, message: err.message, field: err.field });
      return;
    }
    if (err.code === "23505") {
      await logEvent("register_duplicate", email, ip);
      res.status(409).json({
        ok: false,
        message: "An account with that email already exists. Log in instead.",
        field: "email"
      });
      return;
    }
    next(err);
  }
});
authRouter.post("/login", async (req, res, next) => {
  const ip = clientIp(req);
  let email = "";
  try {
    email = parseEmail(req.body?.email);
    const password = parsePassword(req.body?.password, false);
    const [byEmail, byIp] = await Promise.all([
      countEvents("login_fail", "email", email, LIMITS.loginWindowMinutes),
      countEvents("login_fail", "ip", ip, LIMITS.loginWindowMinutes)
    ]);
    if (byEmail >= LIMITS.loginFailPerEmail || byIp >= LIMITS.loginFailPerIp) {
      await logEvent("login_throttled", email, ip);
      res.status(429).json({
        ok: false,
        message: "Too many attempts. Wait a few minutes and try again."
      });
      return;
    }
    const found = await query(
      `select id, email, first_name, last_name, status, role, email_verified_at, created_at, password_hash
         from users where lower(email) = $1`,
      [email]
    );
    const row = found.rows[0];
    if (!row) {
      await burnTime(password);
      await logEvent("login_fail", email, ip);
      res.status(401).json({ ok: false, message: "That email or password isn't right." });
      return;
    }
    if (!await verifyPassword(password, row.password_hash)) {
      await logEvent("login_fail", email, ip);
      res.status(401).json({ ok: false, message: "That email or password isn't right." });
      return;
    }
    if (row.status !== "active") {
      await logEvent("login_blocked", email, ip);
      res.status(403).json({ ok: false, message: "This account isn't available. Contact support." });
      return;
    }
    const token = await createSession(row.id, req);
    setSessionCookie(res, token);
    await logEvent("login_ok", email, ip);
    res.json({ ok: true, user: toPublic(row) });
  } catch (err) {
    if (err instanceof Invalid) {
      res.status(400).json({ ok: false, message: err.message, field: err.field });
      return;
    }
    next(err);
  }
});
authRouter.get("/me", async (req, res, next) => {
  try {
    const session = await loadSession(req);
    if (!session) {
      res.status(401).json({ ok: false, message: "Not logged in." });
      return;
    }
    res.json({ ok: true, user: session.user });
  } catch (err) {
    next(err);
  }
});
authRouter.post("/logout", async (req, res, next) => {
  try {
    const token = readCookie(req, COOKIE);
    if (token) await query("delete from sessions where token_hash = $1", [hashToken(token)]);
    clearSessionCookie(res);
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});
authRouter.post("/logout-all", requireAuth, async (req, res, next) => {
  try {
    await query("delete from sessions where user_id = $1", [req.user.id]);
    clearSessionCookie(res);
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// server/admin.ts
import { Router as Router2 } from "express";
var adminRouter = Router2();
adminRouter.use(requireAdmin);
function clientIp2(req) {
  return (req.ip ?? req.socket.remoteAddress ?? "").toString().slice(0, 64);
}
async function record(req, action, targetId, detail) {
  await query(
    "insert into admin_actions (admin_id, target_id, action, detail, ip) values ($1, $2, $3, $4, $5)",
    [req.user.id, targetId, action, detail, clientIp2(req)]
  ).catch((err) => console.error("[admin] could not record action:", err.message));
}
adminRouter.get("/overview", async (_req, res, next) => {
  try {
    const result = await query(`
      select
        (select count(*) from users where role = 'customer')                                    as customers,
        (select count(*) from users where role = 'customer' and created_at > now() - interval '24 hours') as new_today,
        (select count(*) from users where role = 'customer' and created_at > now() - interval '7 days')   as new_week,
        (select count(*) from users where status <> 'active')                                   as suspended,
        (select count(*) from sessions where expires_at > now())                                as live_sessions,
        (select count(*) from auth_events where kind = 'login_fail'  and created_at > now() - interval '24 hours') as failed_logins,
        (select count(*) from auth_events where kind like '%throttled' and created_at > now() - interval '24 hours') as throttled
    `);
    const row = result.rows[0] ?? {};
    const num = (k) => Number(row[k] ?? 0);
    res.json({
      ok: true,
      overview: {
        customers: num("customers"),
        newToday: num("new_today"),
        newWeek: num("new_week"),
        suspended: num("suspended"),
        liveSessions: num("live_sessions"),
        failedLogins: num("failed_logins"),
        throttled: num("throttled")
      }
    });
  } catch (err) {
    next(err);
  }
});
adminRouter.get("/signups", async (req, res, next) => {
  try {
    const days = Math.min(Math.max(Number(req.query.days) || 30, 7), 180);
    const rows = await query(
      `select d.day::date as day, count(u.id)::text as n
         from generate_series(current_date - ($1::int - 1), current_date, interval '1 day') as d(day)
         left join users u
           on u.created_at >= d.day and u.created_at < d.day + interval '1 day'
          and u.role = 'customer'
        group by d.day
        order by d.day`,
      [days]
    );
    res.json({
      ok: true,
      days: rows.rows.map((r) => ({
        day: new Date(r.day).toISOString().slice(0, 10),
        count: Number(r.n)
      }))
    });
  } catch (err) {
    next(err);
  }
});
adminRouter.get("/customers", async (req, res, next) => {
  try {
    const q = typeof req.query.q === "string" ? req.query.q.trim().slice(0, 120) : "";
    const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
    const offset = Math.max(Number(req.query.offset) || 0, 0);
    const like = q ? `%${q.toLowerCase()}%` : null;
    const rows = await query(
      `select id, email, first_name, last_name, status, role, email_verified_at,
              created_at, signup_ip,
              (select count(*) from sessions s where s.user_id = u.id and s.expires_at > now()) as live_sessions,
              (select max(created_at) from auth_events e
                where lower(e.email) = lower(u.email) and e.kind = 'login_ok') as last_login
         from users u
        where ($1::text is null
               or lower(email) like $1 or lower(first_name) like $1 or lower(last_name) like $1)
        order by created_at desc
        limit $2 offset $3`,
      [like, limit, offset]
    );
    const total = await query(
      `select count(*)::text as n from users
        where ($1::text is null
               or lower(email) like $1 or lower(first_name) like $1 or lower(last_name) like $1)`,
      [like]
    );
    res.json({
      ok: true,
      total: Number(total.rows[0]?.n ?? 0),
      limit,
      offset,
      customers: rows.rows.map((r) => ({
        id: String(r.id),
        email: r.email,
        firstName: r.first_name,
        lastName: r.last_name,
        status: r.status,
        role: r.role,
        emailVerified: r.email_verified_at !== null,
        createdAt: new Date(r.created_at).toISOString(),
        signupIp: r.signup_ip,
        liveSessions: Number(r.live_sessions ?? 0),
        lastLogin: r.last_login ? new Date(r.last_login).toISOString() : null
      }))
    });
  } catch (err) {
    next(err);
  }
});
adminRouter.get("/customers/:id", async (req, res, next) => {
  try {
    const id = req.params.id;
    if (!/^\d+$/.test(id)) {
      res.status(400).json({ ok: false, message: "Bad id." });
      return;
    }
    const found = await query(
      `select id, email, first_name, last_name, status, role, email_verified_at,
              terms_accepted_at, created_at, updated_at, signup_ip, country, sophisticated_at
         from users where id = $1`,
      [id]
    );
    const u = found.rows[0];
    if (!u) {
      res.status(404).json({ ok: false, message: "No such customer." });
      return;
    }
    const events = await query(
      `select kind, ip, created_at from auth_events
        where lower(email) = lower($1) order by created_at desc limit 25`,
      [u.email]
    );
    const sessions = await query(
      `select id, created_at, last_seen_at, expires_at, ip, user_agent
         from sessions where user_id = $1 order by last_seen_at desc limit 10`,
      [id]
    );
    res.json({
      ok: true,
      customer: {
        id: String(u.id),
        email: u.email,
        firstName: u.first_name,
        lastName: u.last_name,
        status: u.status,
        role: u.role,
        emailVerified: u.email_verified_at !== null,
        termsAcceptedAt: u.terms_accepted_at ? new Date(u.terms_accepted_at).toISOString() : null,
        createdAt: new Date(u.created_at).toISOString(),
        signupIp: u.signup_ip,
        country: u.country ?? null,
        sophisticatedAt: u.sophisticated_at ? new Date(u.sophisticated_at).toISOString() : null
      },
      events: events.rows.map((e) => ({
        kind: e.kind,
        ip: e.ip,
        at: new Date(e.created_at).toISOString()
      })),
      sessions: sessions.rows.map((s) => ({
        id: String(s.id),
        createdAt: new Date(s.created_at).toISOString(),
        lastSeenAt: new Date(s.last_seen_at).toISOString(),
        expiresAt: new Date(s.expires_at).toISOString(),
        ip: s.ip,
        userAgent: s.user_agent
      }))
    });
  } catch (err) {
    next(err);
  }
});
adminRouter.post("/customers/:id/status", async (req, res, next) => {
  try {
    const id = req.params.id;
    const status = String(req.body?.status ?? "");
    if (!/^\d+$/.test(id)) {
      res.status(400).json({ ok: false, message: "Bad id." });
      return;
    }
    if (status !== "active" && status !== "suspended") {
      res.status(400).json({ ok: false, message: "Status must be active or suspended." });
      return;
    }
    if (id === req.user.id) {
      res.status(400).json({ ok: false, message: "You can't change your own status." });
      return;
    }
    const updated = await query(
      "update users set status = $1, updated_at = now() where id = $2 returning id, email, status",
      [status, id]
    );
    const row = updated.rows[0];
    if (!row) {
      res.status(404).json({ ok: false, message: "No such customer." });
      return;
    }
    if (status === "suspended") {
      await query("delete from sessions where user_id = $1", [id]);
    }
    await record(req, `status:${status}`, id, String(row.email));
    res.json({ ok: true, customer: { id: String(row.id), status: row.status } });
  } catch (err) {
    next(err);
  }
});
adminRouter.post("/customers/:id/logout", async (req, res, next) => {
  try {
    const id = req.params.id;
    if (!/^\d+$/.test(id)) {
      res.status(400).json({ ok: false, message: "Bad id." });
      return;
    }
    const gone = await query("delete from sessions where user_id = $1", [id]);
    await record(req, "sessions:revoked", id, `${gone.rowCount ?? 0} session(s)`);
    res.json({ ok: true, revoked: gone.rowCount ?? 0 });
  } catch (err) {
    next(err);
  }
});
adminRouter.get("/events", async (req, res, next) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 60, 1), 300);
    const kind = typeof req.query.kind === "string" ? req.query.kind.slice(0, 40) : "";
    const rows = await query(
      `select kind, email, ip, created_at from auth_events
        where ($1::text = '' or kind = $1)
        order by created_at desc limit $2`,
      [kind, limit]
    );
    res.json({
      ok: true,
      events: rows.rows.map((e) => ({
        kind: e.kind,
        email: e.email,
        ip: e.ip,
        at: new Date(e.created_at).toISOString()
      }))
    });
  } catch (err) {
    next(err);
  }
});
adminRouter.get("/actions", async (req, res, next) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 60, 1), 300);
    const rows = await query(
      `select a.action, a.detail, a.ip, a.created_at,
              admin.email as admin_email, a.target_id
         from admin_actions a join users admin on admin.id = a.admin_id
        order by a.created_at desc limit $1`,
      [limit]
    );
    res.json({
      ok: true,
      actions: rows.rows.map((a) => ({
        action: a.action,
        detail: a.detail,
        ip: a.ip,
        adminEmail: a.admin_email,
        targetId: a.target_id ? String(a.target_id) : null,
        at: new Date(a.created_at).toISOString()
      }))
    });
  } catch (err) {
    next(err);
  }
});

// server/deploy-notice.ts
import fs from "node:fs";
import path from "node:path";

// server/mailer.ts
var ENDPOINT = "https://api.resend.com/emails";
function adminRecipients() {
  return (process.env.ADMIN_EMAILS ?? "").split(",").map((e) => e.trim()).filter(Boolean);
}
function mailConfigured() {
  return Boolean(process.env.RESEND_API_KEY) && adminRecipients().length > 0;
}
async function sendMail(opts) {
  const key = process.env.RESEND_API_KEY;
  if (!key || opts.to.length === 0) return null;
  try {
    const res = await fetch(ENDPOINT, {
      method: "POST",
      headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: process.env.MAIL_FROM ?? "Nucleus Markets <support@nucleusmarkets.com>",
        reply_to: process.env.MAIL_REPLY_TO ?? "support@nucleusmarkets.com",
        to: opts.to,
        subject: opts.subject,
        html: opts.html,
        text: opts.text
      })
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      console.error("[mail] send failed:", body.message ?? res.status);
      return null;
    }
    return body.id ?? null;
  } catch (err) {
    console.error("[mail] send threw:", err.message);
    return null;
  }
}
function escapeHtml(s) {
  return s.replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]
  );
}
function deployEmail(info, site) {
  const subject = `Nucleus Markets deployed - ${info.subject}`.slice(0, 180);
  const safeSubject = escapeHtml(info.subject);
  const safeBody = info.body ? escapeHtml(info.body).replace(/\n/g, "<br>") : "";
  const when = new Date(info.builtAt ?? Date.now()).toUTCString();
  const html = `<!doctype html>
<html><body style="margin:0;background:#05060d;font-family:-apple-system,Segoe UI,Inter,Helvetica,Arial,sans-serif;color:#e6e8f2">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#05060d;padding:40px 16px">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#0a0c18;border:1px solid rgba(255,255,255,0.08);border-radius:18px;padding:32px">
        <tr><td>
          <p style="margin:0;font-size:12px;letter-spacing:4px;color:#22d3ee;text-transform:uppercase">Nucleus Markets</p>
          <h1 style="margin:14px 0 0;font-size:22px;line-height:1.3;color:#ffffff;font-weight:600">${safeSubject}</h1>
          <p style="margin:10px 0 0;font-size:13px;color:#6b7391">
            <code style="color:#8fa0bd">${escapeHtml(info.commit)}</code> &middot; ${when}
          </p>
          ${safeBody ? `<div style="margin:22px 0 0;padding:16px;background:rgba(255,255,255,0.03);border-radius:12px;font-size:14px;line-height:1.65;color:#aab0c6">${safeBody}</div>` : ""}
          <p style="margin:26px 0 0">
            <a href="${site}/admin" style="display:inline-block;background:#22d3ee;color:#05060d;text-decoration:none;font-weight:600;font-size:14px;padding:12px 24px;border-radius:999px">Open the back office</a>
          </p>
          <p style="margin:24px 0 0;padding-top:18px;border-top:1px solid rgba(255,255,255,0.08);font-size:12px;line-height:1.6;color:#6b7391">
            Sent automatically to every admin whenever ${escapeHtml(site.replace(/^https?:\/\//, ""))} is deployed.
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
  const text = [
    "Nucleus Markets - deployed",
    "",
    info.subject,
    `${info.commit} - ${when}`,
    info.body ? `
${info.body}` : "",
    "",
    `Back office: ${site}/admin`
  ].join("\n");
  return { subject, html, text };
}

// server/deploy-notice.ts
async function announceDeploy(dir) {
  const file = path.join(dir, "version.json");
  if (!fs.existsSync(file)) return;
  let info;
  try {
    info = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (err) {
    console.error("[deploy] version.json is not readable:", err.message);
    return;
  }
  if (!info.commit) return;
  const inserted = await query(
    `insert into deploys (commit, subject) values ($1, $2)
     on conflict (commit) do nothing
     returning id`,
    [info.commit, info.subject ?? null]
  );
  if (inserted.rowCount === 0) {
    console.log(`[deploy] build ${info.commit} already announced`);
    return;
  }
  if (!mailConfigured()) {
    console.warn("[deploy] no RESEND_API_KEY or ADMIN_EMAILS - not emailing anyone");
    return;
  }
  const site = process.env.SITE_URL ?? "https://nucleusmarkets.com";
  const to = adminRecipients();
  const mail = deployEmail(info, site);
  const id = await sendMail({ to, ...mail });
  if (id) {
    await query("update deploys set notified_at = now() where id = $1", [inserted.rows[0].id]);
    console.log(`[deploy] told ${to.length} admin(s) about ${info.commit} (resend ${id})`);
  } else {
    console.error(`[deploy] could not email admins about ${info.commit}`);
  }
}

// server/index.ts
var here = path2.dirname(fileURLToPath(import.meta.url));
var publicDir = path2.join(here, "public");
var app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "blob:"],
        mediaSrc: ["'self'", "blob:"],
        connectSrc: ["'self'"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"]
      }
    },
    crossOriginEmbedderPolicy: false
  })
);
app.use(compression());
app.use(express.json({ limit: "100kb" }));
app.get("/api/health", async (_req, res) => {
  const database = dbConfigured ? await dbHealthy() ? "up" : "down" : "not configured";
  res.json({ ok: true, service: "nucleus-markets", database, time: (/* @__PURE__ */ new Date()).toISOString() });
});
if (dbConfigured) {
  app.use("/api/auth", authRouter);
  app.use("/api/admin", adminRouter);
} else {
  app.use("/api/auth", (_req, res) => {
    res.status(503).json({
      ok: false,
      message: "Account opening goes live shortly. We'll be ready for you very soon."
    });
  });
}
app.use("/api", (_req, res) => res.status(404).json({ ok: false, message: "Not found" }));
if (fs2.existsSync(publicDir)) {
  app.use(
    "/assets",
    express.static(path2.join(publicDir, "assets"), { immutable: true, maxAge: "1y" })
  );
  app.use(express.static(publicDir, { maxAge: "1h", index: false }));
  app.get("*", (_req, res) => {
    res.setHeader("Cache-Control", "no-cache");
    res.sendFile(path2.join(publicDir, "index.html"));
  });
}
app.use((err, req, res, _next) => {
  console.error(`[error] ${req.method} ${req.path}:`, err.stack ?? err.message);
  if (res.headersSent) return;
  res.status(500).json({ ok: false, message: "Something went wrong on our side. Please try again." });
});
var port = Number(process.env.PORT) || 5e3;
async function start() {
  if (dbConfigured) {
    try {
      await migrate();
      const pruned = await pruneSessions();
      const promoted = await syncAdmins();
      console.log(`[db] schema ready, ${pruned} expired session(s) pruned`);
      if (promoted > 0) console.log(`[db] promoted ${promoted} account(s) to admin`);
      void announceDeploy(here).catch(
        (err) => console.error("[deploy] announce failed:", err.message)
      );
      setInterval(
        () => {
          pruneSessions().catch((err) => console.error("[db] prune failed:", err.message));
        },
        60 * 60 * 1e3
      ).unref();
    } catch (err) {
      console.error("[db] migration failed:", err.message);
    }
  } else {
    console.warn("[db] DATABASE_URL is not set - account opening is disabled");
  }
  const server = app.listen(port, "0.0.0.0", () => {
    console.log(`nucleus-markets listening on :${port}`);
  });
  for (const signal of ["SIGTERM", "SIGINT"]) {
    process.on(signal, () => {
      server.close(() => {
        pool?.end().finally(() => process.exit(0));
      });
    });
  }
}
void start();
