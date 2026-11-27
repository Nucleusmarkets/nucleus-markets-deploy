// server/index.ts
import express from "express";
import helmet from "helmet";
import compression from "compression";
import path2 from "node:path";
import fs2 from "node:fs";
import { fileURLToPath } from "node:url";

// server/auth.ts
import { createHash, randomBytes as randomBytes3 } from "node:crypto";
import { Router as Router2 } from "express";

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
  // ---------------------------------------------------------------- IB / affiliates
  // Every account gets a referral code; being an IB is a separate approval.
  `alter table users add column if not exists referral_code text`,
  `alter table users add column if not exists referred_by bigint references users (id) on delete set null`,
  `alter table users add column if not exists ib_approved_at timestamptz`,
  `alter table users add column if not exists commission_plan_id bigint`,
  `create unique index if not exists users_referral_code_key on users (referral_code) where referral_code is not null`,
  `create index if not exists users_referred_by_idx on users (referred_by)`,
  `create table if not exists commission_plans (
     id          bigserial primary key,
     name        text        not null unique,
     per_lot     numeric(12,4) not null default 0,
     revenue_pct numeric(6,3)  not null default 0,
     is_default  boolean     not null default false,
     created_at  timestamptz not null default now()
   )`,
  /*
   * The earnings ledger. One row per accrual, and nothing else is ever counted as
   * earnings - on a sibling brand, payout receipts and profit-share were added to
   * this total and overstated what affiliates were owed. Payouts live in their own
   * table and are only ever subtracted.
   */
  `create table if not exists commissions (
     id          bigserial primary key,
     ib_id       bigint      not null references users (id) on delete cascade,
     customer_id bigint      references users (id) on delete set null,
     amount      numeric(14,2) not null check (amount >= 0),
     source      text        not null,
     note        text,
     created_at  timestamptz not null default now()
   )`,
  `create index if not exists commissions_ib_idx on commissions (ib_id, created_at desc)`,
  `create table if not exists payout_requests (
     id           bigserial primary key,
     ib_id        bigint      not null references users (id) on delete cascade,
     amount       numeric(14,2) not null check (amount > 0),
     destination  text        not null,
     status       text        not null default 'requested',
     note         text,
     requested_at timestamptz not null default now(),
     decided_at   timestamptz,
     decided_by   bigint      references users (id),
     decided_note text
   )`,
  `create index if not exists payout_requests_ib_idx on payout_requests (ib_id, requested_at desc)`,
  `create index if not exists payout_requests_status_idx on payout_requests (status, requested_at)`,
  `insert into commission_plans (name, per_lot, revenue_pct, is_default)
     values ('Standard IB', 3.0000, 0, true)
     on conflict (name) do nothing`,
  // Backfill codes for accounts that predate referrals. New accounts get theirs at
  // registration; the unique index is what actually guarantees no collision.
  `update users set referral_code = upper(substr(md5(random()::text || id::text), 1, 8))
     where referral_code is null`,
  // One row per deployed build. The unique commit is what stops a restart, a second
  // instance or a rollback from emailing the admins about the same build twice.
  `create table if not exists deploys (
     id          bigserial primary key,
     commit      text        not null unique,
     subject     text,
     deployed_at timestamptz not null default now(),
     notified_at timestamptz
   )`,
  // "Continue with Google": the stable Google account id, not the email, is what
  // identifies a returning Google user, since an address can change hands.
  `alter table users add column if not exists google_sub text`,
  `create unique index if not exists users_google_sub_key on users (google_sub) where google_sub is not null`
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

// server/ip.ts
import { isIP } from "node:net";
var behindCloudflare = !!process.env.RENDER || process.env.TRUST_CF_CONNECTING_IP === "1";
function visitorIp(req) {
  if (behindCloudflare) {
    const cf = req.headers["cf-connecting-ip"];
    const value = (Array.isArray(cf) ? cf[0] : cf)?.trim();
    if (value && isIP(value)) return value;
  }
  return (req.ip ?? req.socket.remoteAddress ?? "").toString().slice(0, 64);
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
function isValidCountry(code2) {
  return BY_CODE.has(code2);
}
function needsSophisticatedDeclaration(code2) {
  return code2 === OTHER;
}

// server/ib.ts
import { randomBytes as randomBytes2 } from "node:crypto";
import { Router } from "express";
var ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
function code(length = 8) {
  const bytes = randomBytes2(length);
  let out = "";
  for (let i = 0; i < length; i++) out += ALPHABET[bytes[i] % ALPHABET.length];
  return out;
}
async function assignReferralCode(userId) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const candidate = code();
    try {
      const res = await query(
        "update users set referral_code = $1 where id = $2 and referral_code is null returning referral_code",
        [candidate, userId]
      );
      if (res.rowCount === 0) {
        const existing = await query(
          "select referral_code from users where id = $1",
          [userId]
        );
        return existing.rows[0]?.referral_code ?? candidate;
      }
      return candidate;
    } catch (err) {
      if (err.code !== "23505") throw err;
    }
  }
  throw new Error("could not allocate a referral code");
}
async function referrerIdFor(raw) {
  const value = typeof raw === "string" ? raw.trim().toUpperCase().slice(0, 16) : "";
  if (!value) return null;
  const res = await query(
    "select id from users where referral_code = $1 and status = 'active'",
    [value]
  );
  return res.rows[0]?.id ?? null;
}
async function balanceFor(ibId) {
  const res = await query(
    `select
       coalesce((select sum(amount) from commissions where ib_id = $1), 0)::text as earned,
       coalesce((select sum(amount) from payout_requests where ib_id = $1 and status = 'paid'), 0)::text as paid,
       coalesce((select sum(amount) from payout_requests where ib_id = $1 and status = 'requested'), 0)::text as requested`,
    [ibId]
  );
  const row = res.rows[0] ?? {};
  const earned = Number(row.earned ?? 0);
  const paid = Number(row.paid ?? 0);
  const requested = Number(row.requested ?? 0);
  return {
    earned,
    paid,
    requested,
    available: Math.max(earned - paid - requested, 0)
  };
}
var ibRouter = Router();
ibRouter.use(requireAuth);
ibRouter.get("/overview", async (req, res, next) => {
  try {
    const me = req.user;
    const info = await query(
      `select u.referral_code, u.ib_approved_at,
              (select count(*) from users r where r.referred_by = u.id)::text as n
         from users u where u.id = $1`,
      [me.id]
    );
    const row = info.rows[0];
    let referralCode = row?.referral_code ?? null;
    if (!referralCode) referralCode = await assignReferralCode(me.id);
    res.json({
      ok: true,
      ib: {
        referralCode,
        link: `${siteUrl()}/r/${referralCode}`,
        approved: row?.ib_approved_at !== null && row?.ib_approved_at !== void 0,
        referrals: Number(row?.n ?? 0),
        ...await balanceFor(me.id)
      }
    });
  } catch (err) {
    next(err);
  }
});
ibRouter.get("/referrals", async (req, res, next) => {
  try {
    const rows = await query(
      `select id, first_name, left(email, 2) as hint, country, created_at, status
         from users where referred_by = $1 order by created_at desc limit 200`,
      [req.user.id]
    );
    res.json({
      ok: true,
      referrals: rows.rows.map((r) => ({
        id: String(r.id),
        name: r.first_name || `${r.hint}***`,
        country: r.country ?? null,
        status: r.status,
        joinedAt: new Date(r.created_at).toISOString()
      }))
    });
  } catch (err) {
    next(err);
  }
});
ibRouter.get("/commissions", async (req, res, next) => {
  try {
    const rows = await query(
      `select amount::text, source, note, created_at from commissions
        where ib_id = $1 order by created_at desc limit 100`,
      [req.user.id]
    );
    res.json({
      ok: true,
      commissions: rows.rows.map((r) => ({
        amount: Number(r.amount),
        source: r.source,
        note: r.note,
        at: new Date(r.created_at).toISOString()
      }))
    });
  } catch (err) {
    next(err);
  }
});
ibRouter.get("/payouts", async (req, res, next) => {
  try {
    const rows = await query(
      `select id, amount::text, destination, status, note, decided_note, requested_at, decided_at
         from payout_requests where ib_id = $1 order by requested_at desc limit 100`,
      [req.user.id]
    );
    res.json({
      ok: true,
      payouts: rows.rows.map((r) => ({
        id: String(r.id),
        amount: Number(r.amount),
        destination: r.destination,
        status: r.status,
        note: r.note,
        decidedNote: r.decided_note,
        requestedAt: new Date(r.requested_at).toISOString(),
        decidedAt: r.decided_at ? new Date(r.decided_at).toISOString() : null
      }))
    });
  } catch (err) {
    next(err);
  }
});
ibRouter.post("/payouts", async (req, res, next) => {
  try {
    const me = req.user;
    const approved = await query(
      "select ib_approved_at from users where id = $1",
      [me.id]
    );
    if (!approved.rows[0]?.ib_approved_at) {
      res.status(403).json({ ok: false, message: "Your partner account isn't approved yet." });
      return;
    }
    const amount = Number(req.body?.amount);
    const destination = String(req.body?.destination ?? "").trim().slice(0, 200);
    if (!Number.isFinite(amount) || amount <= 0) {
      res.status(400).json({ ok: false, message: "Enter an amount.", field: "amount" });
      return;
    }
    if (!destination) {
      res.status(400).json({ ok: false, message: "Where should it be sent?", field: "destination" });
      return;
    }
    const created = await withTransaction(async (client) => {
      await client.query("select id from users where id = $1 for update", [me.id]);
      const sums = await client.query(
        `select
           coalesce((select sum(amount) from commissions where ib_id = $1), 0)::text as earned,
           coalesce((select sum(amount) from payout_requests where ib_id = $1 and status = 'paid'), 0)::text as paid,
           coalesce((select sum(amount) from payout_requests where ib_id = $1 and status = 'requested'), 0)::text as requested`,
        [me.id]
      );
      const s = sums.rows[0];
      const available = Number(s.earned) - Number(s.paid) - Number(s.requested);
      if (amount > available + 1e-9) {
        return { tooMuch: true, available };
      }
      const row = await client.query(
        `insert into payout_requests (ib_id, amount, destination) values ($1, $2, $3) returning id`,
        [me.id, amount.toFixed(2), destination]
      );
      return { tooMuch: false, id: row.rows[0].id };
    });
    if (created.tooMuch) {
      res.status(400).json({
        ok: false,
        message: `You can request up to ${created.available.toFixed(2)} right now.`,
        field: "amount"
      });
      return;
    }
    res.status(201).json({ ok: true, id: created.id });
  } catch (err) {
    next(err);
  }
});

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
function shell(opts) {
  return `<!doctype html>
<html><body style="margin:0;background:#05060d;font-family:-apple-system,Segoe UI,Inter,Helvetica,Arial,sans-serif;color:#e6e8f2">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#05060d;padding:40px 16px">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#0a0c18;border:1px solid rgba(255,255,255,0.08);border-radius:18px;padding:36px">
        <tr><td>
          <p style="margin:0;font-size:12px;letter-spacing:4px;color:#22d3ee;text-transform:uppercase">Nucleus Markets</p>
          <h1 style="margin:16px 0 0;font-size:25px;line-height:1.25;color:#ffffff;font-weight:600">${opts.title}</h1>
          <div style="margin:16px 0 0;font-size:15px;line-height:1.65;color:#aab0c6">${opts.body}</div>
          ${opts.cta ? `<p style="margin:28px 0 0"><a href="${opts.cta.href}" style="display:inline-block;background:#22d3ee;color:#05060d;text-decoration:none;font-weight:600;font-size:15px;padding:14px 26px;border-radius:999px">${opts.cta.label}</a></p>
          <p style="margin:22px 0 0;font-size:13px;line-height:1.6;color:#6b7391">If the button does not work, paste this into your browser:<br><span style="color:#8fa0bd;word-break:break-all">${opts.cta.href}</span></p>` : ""}
          <p style="margin:28px 0 0;padding-top:20px;border-top:1px solid rgba(255,255,255,0.08);font-size:13px;line-height:1.6;color:#6b7391">${opts.footer}</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
}
var hello = (name) => name ? `Hi ${escapeHtml(name)},` : "Hi,";
function verificationEmail(firstName, link) {
  return {
    subject: "Confirm your email address",
    html: shell({
      title: "Confirm your email",
      body: `<p style="margin:0">${hello(firstName)}</p><p style="margin:14px 0 0">Confirm this address so we can reach you about your account. The link works once and expires in 24 hours.</p>`,
      cta: { label: "Confirm my email", href: link },
      footer: "If you did not open a Nucleus Markets account, ignore this and the link expires on its own."
    }),
    text: `${firstName ? `Hi ${firstName},` : "Hi,"}

Confirm your email address (works once, expires in 24 hours):
${link}

If you did not open a Nucleus Markets account, ignore this.`
  };
}
function resetEmail(firstName, link) {
  return {
    subject: "Reset your Nucleus Markets password",
    html: shell({
      title: "Reset your password",
      body: `<p style="margin:0">${hello(firstName)}</p><p style="margin:14px 0 0">Choose a new password using the link below. It works once and expires in 2 hours. Setting a new password signs you out everywhere else.</p>`,
      cta: { label: "Set a new password", href: link },
      footer: "If you did not ask for this, you can ignore it - your password has not changed and the link expires on its own."
    }),
    text: `${firstName ? `Hi ${firstName},` : "Hi,"}

Reset your password (works once, expires in 2 hours):
${link}

If you did not ask for this, ignore it - nothing has changed.`
  };
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
  return visitorIp(req);
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
  const token = randomBytes3(32).toString("base64url");
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
var authRouter = Router2();
function siteUrl() {
  return (process.env.SITE_URL ?? "https://nucleusmarkets.com").replace(/\/$/, "");
}
async function sendVerification(userId, email, firstName) {
  try {
    const token = await createPasswordToken(userId, "verify", 24);
    const mail = verificationEmail(firstName, `${siteUrl()}/verify?token=${token}`);
    await sendMail({ to: [email], ...mail });
  } catch (err) {
    console.error("[auth] verification mail failed:", err.message);
  }
}
async function createPasswordToken(userId, purpose, hours = 72) {
  const token = randomBytes3(32).toString("base64url");
  await query(
    `insert into password_tokens (token_hash, user_id, purpose, expires_at)
     values ($1, $2, $3, now() + ($4 || ' hours')::interval)`,
    [hashToken(token), userId, purpose, String(hours)]
  );
  return token;
}
async function findToken(token) {
  const res = await query(
    `select t.id, t.user_id, t.purpose, u.email, u.first_name
       from password_tokens t join users u on u.id = t.user_id
      where t.token_hash = $1 and t.purpose in ('invite', 'reset')
        and t.used_at is null and t.expires_at > now()`,
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
    const referredBy = await referrerIdFor(req.body?.ref);
    const user = await withTransaction(async (client) => {
      const inserted = await client.query(
        `insert into users (email, first_name, last_name, password_hash, terms_accepted_at, signup_ip,
                            country, sophisticated_at, referred_by)
         values ($1, $2, $3, $4, now(), $5, $6, case when $7::boolean then now() else null end, $8)
         returning id, email, first_name, last_name, status, role, email_verified_at, created_at`,
        [email, firstName, lastName, passwordHash, ip, country, isSophisticated, referredBy]
      );
      return inserted.rows[0];
    });
    if (isListedAdmin(email)) {
      await query("update users set role = 'admin', updated_at = now() where id = $1", [user.id]);
      user.role = "admin";
    }
    void assignReferralCode(user.id).catch((e) => console.error("[ib] code:", e.message));
    void sendVerification(user.id, email, firstName);
    await logEvent("verify_sent", email, ip);
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
authRouter.post("/verify", async (req, res, next) => {
  try {
    const token = String(req.body?.token ?? "");
    const found = await query(
      `select t.id, t.user_id, u.email from password_tokens t join users u on u.id = t.user_id
        where t.token_hash = $1 and t.purpose = 'verify' and t.used_at is null and t.expires_at > now()`,
      [hashToken(token)]
    );
    const row = found.rows[0];
    if (!row) {
      res.status(400).json({ ok: false, message: "This link has expired or has already been used." });
      return;
    }
    await withTransaction(async (client) => {
      await client.query(
        "update users set email_verified_at = now(), updated_at = now() where id = $1",
        [row.user_id]
      );
      await client.query("update password_tokens set used_at = now() where id = $1", [row.id]);
    });
    await logEvent("email_verified", row.email, clientIp(req));
    res.json({ ok: true, email: row.email });
  } catch (err) {
    next(err);
  }
});
authRouter.post("/resend-verification", requireAuth, async (req, res, next) => {
  try {
    const user = req.user;
    if (user.emailVerified) {
      res.json({ ok: true, message: "That address is already confirmed." });
      return;
    }
    const ip = clientIp(req);
    if (await countEvents("verify_sent", "email", user.email, 60) >= 5) {
      res.status(429).json({ ok: false, message: "Too many emails. Try again in an hour." });
      return;
    }
    await sendVerification(user.id, user.email, user.firstName);
    await logEvent("verify_sent", user.email, ip);
    res.json({ ok: true, message: "Sent. Check your inbox." });
  } catch (err) {
    next(err);
  }
});
authRouter.post("/forgot", async (req, res, next) => {
  const ip = clientIp(req);
  const same = {
    ok: true,
    message: "If that address has an account, a reset link is on its way."
  };
  try {
    const email = parseEmail(req.body?.email);
    if (await countEvents("reset_sent", "ip", ip, 60) >= 5) {
      await logEvent("reset_throttled", email, ip);
      res.json(same);
      return;
    }
    const found = await query(
      "select id, first_name from users where lower(email) = $1 and status = 'active'",
      [email]
    );
    const row = found.rows[0];
    if (row) {
      const token = await createPasswordToken(row.id, "reset", 2);
      const link = `${siteUrl()}/set-password?token=${token}`;
      const mail = resetEmail(row.first_name, link);
      await sendMail({ to: [email], ...mail });
      await logEvent("reset_sent", email, ip);
    }
    res.json(same);
  } catch (err) {
    if (err instanceof Invalid) {
      res.json(same);
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
import { Router as Router3 } from "express";
var adminRouter = Router3();
adminRouter.use(requireAdmin);
function clientIp2(req) {
  return visitorIp(req);
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
adminRouter.get("/ib", async (_req, res, next) => {
  try {
    const rows = await query(
      `select u.id, u.email, u.first_name, u.last_name, u.referral_code, u.ib_approved_at,
              (select count(*) from users r where r.referred_by = u.id)::text as referrals,
              coalesce((select sum(amount) from commissions c where c.ib_id = u.id), 0)::text as earned,
              coalesce((select sum(amount) from payout_requests p where p.ib_id = u.id and p.status = 'paid'), 0)::text as paid,
              coalesce((select sum(amount) from payout_requests p where p.ib_id = u.id and p.status = 'requested'), 0)::text as requested
         from users u
        where u.ib_approved_at is not null
           or exists (select 1 from users r where r.referred_by = u.id)
        order by u.ib_approved_at nulls last, u.created_at desc
        limit 200`
    );
    res.json({
      ok: true,
      partners: rows.rows.map((r) => {
        const earned = Number(r.earned);
        const paid = Number(r.paid);
        const requested = Number(r.requested);
        return {
          id: String(r.id),
          email: r.email,
          name: `${r.first_name ?? ""} ${r.last_name ?? ""}`.trim(),
          referralCode: r.referral_code,
          approved: r.ib_approved_at !== null,
          referrals: Number(r.referrals),
          earned,
          paid,
          requested,
          // Same formula as the partner's own view, so the two never disagree.
          available: Math.max(earned - paid - requested, 0)
        };
      })
    });
  } catch (err) {
    next(err);
  }
});
adminRouter.post("/ib/:id/status", async (req, res, next) => {
  try {
    const id = req.params.id;
    const approve = req.body?.approved === true;
    if (!/^\d+$/.test(id)) {
      res.status(400).json({ ok: false, message: "Bad id." });
      return;
    }
    const updated = await query(
      `update users set ib_approved_at = ${approve ? "now()" : "null"}, updated_at = now()
        where id = $1 returning email`,
      [id]
    );
    if (updated.rowCount === 0) {
      res.status(404).json({ ok: false, message: "No such account." });
      return;
    }
    await record(req, approve ? "ib:approved" : "ib:revoked", id, updated.rows[0].email);
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});
adminRouter.post("/ib/:id/commission", async (req, res, next) => {
  try {
    const id = req.params.id;
    const amount = Number(req.body?.amount);
    const note = String(req.body?.note ?? "").trim().slice(0, 300);
    if (!/^\d+$/.test(id)) {
      res.status(400).json({ ok: false, message: "Bad id." });
      return;
    }
    if (!Number.isFinite(amount) || amount <= 0) {
      res.status(400).json({ ok: false, message: "Enter a positive amount.", field: "amount" });
      return;
    }
    await query(
      "insert into commissions (ib_id, amount, source, note) values ($1, $2, 'manual', $3)",
      [id, amount.toFixed(2), note || null]
    );
    await record(req, "ib:commission", id, `${amount.toFixed(2)}${note ? ` - ${note}` : ""}`);
    res.status(201).json({ ok: true });
  } catch (err) {
    next(err);
  }
});
adminRouter.get("/payouts", async (req, res, next) => {
  try {
    const status = typeof req.query.status === "string" ? req.query.status.slice(0, 20) : "";
    const rows = await query(
      `select p.id, p.amount::text, p.destination, p.status, p.note, p.decided_note,
              p.requested_at, p.decided_at, u.email, u.id as ib_id
         from payout_requests p join users u on u.id = p.ib_id
        where ($1::text = '' or p.status = $1)
        order by case when p.status = 'requested' then 0 else 1 end, p.requested_at desc
        limit 200`,
      [status]
    );
    res.json({
      ok: true,
      payouts: rows.rows.map((r) => ({
        id: String(r.id),
        ibId: String(r.ib_id),
        email: r.email,
        amount: Number(r.amount),
        destination: r.destination,
        status: r.status,
        decidedNote: r.decided_note,
        requestedAt: new Date(r.requested_at).toISOString(),
        decidedAt: r.decided_at ? new Date(r.decided_at).toISOString() : null
      }))
    });
  } catch (err) {
    next(err);
  }
});
adminRouter.post("/payouts/:id/decide", async (req, res, next) => {
  try {
    const id = req.params.id;
    const status = String(req.body?.status ?? "");
    const note = String(req.body?.note ?? "").trim().slice(0, 300);
    if (!/^\d+$/.test(id)) {
      res.status(400).json({ ok: false, message: "Bad id." });
      return;
    }
    if (status !== "paid" && status !== "rejected") {
      res.status(400).json({ ok: false, message: "Decision must be paid or rejected." });
      return;
    }
    const updated = await query(
      `update payout_requests p set status = $1, decided_at = now(), decided_by = $2, decided_note = $3
         from users u
        where p.id = $4 and p.status = 'requested' and u.id = p.ib_id
        returning p.amount::text, u.email, p.ib_id`,
      [status, req.user.id, note || null, id]
    );
    if (updated.rowCount === 0) {
      res.status(409).json({ ok: false, message: "That request has already been decided." });
      return;
    }
    const row = updated.rows[0];
    await record(req, `payout:${status}`, row.ib_id, `${row.amount} to ${row.email}`);
    res.json({ ok: true });
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

// server/google.ts
import { createHash as createHash2, randomBytes as randomBytes4, timingSafeEqual as timingSafeEqual2 } from "node:crypto";
import { Router as Router4 } from "express";
var CLIENT_ID = process.env.GOOGLE_CLIENT_ID ?? "";
var CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET ?? "";
var SITE = (process.env.SITE_URL ?? "https://nucleusmarkets.com").replace(/\/+$/, "");
var REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI ?? `${SITE}/api/auth/google/callback`;
var isProd2 = process.env.NODE_ENV === "production" || !!process.env.RENDER;
var googleEnabled = CLIENT_ID.length > 0 && CLIENT_SECRET.length > 0;
var STATE_COOKIE = "ns_g_state";
var STATE_PATH = "/api/auth/google";
var STATE_MINUTES = 10;
var b64url = (buf) => buf.toString("base64url");
function sameSecret(a, b) {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual2(x, y);
}
function fail(res, mode, code2) {
  res.redirect(303, `/${mode}?google=${encodeURIComponent(code2)}`);
}
function clearState(res) {
  res.clearCookie(STATE_COOKIE, { httpOnly: true, secure: isProd2, sameSite: "lax", path: STATE_PATH });
}
function readIdToken(idToken) {
  const parts = idToken.split(".");
  if (parts.length !== 3) return null;
  try {
    const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    const issOk = claims.iss === "https://accounts.google.com" || claims.iss === "accounts.google.com";
    const audOk = claims.aud === CLIENT_ID;
    const fresh = typeof claims.exp === "number" && claims.exp * 1e3 > Date.now() - 6e4;
    if (!issOk || !audOk || !fresh || !claims.sub) return null;
    return claims;
  } catch {
    return null;
  }
}
var clean = (v, max2 = 80) => typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, max2) : "";
var placeholderHash = () => `scrypt$16384$8$1$${randomBytes4(16).toString("base64")}$${randomBytes4(64).toString("base64")}`;
var googleRouter = Router4();
googleRouter.get("/google/start", (req, res) => {
  const mode = req.query.mode === "register" ? "register" : "login";
  if (!googleEnabled) return fail(res, mode, "off");
  const pending = {
    state: b64url(randomBytes4(24)),
    verifier: b64url(randomBytes4(48)),
    mode,
    terms: mode === "register" && req.query.terms === "1",
    country: mode === "register" ? clean(req.query.country, 8).toUpperCase() : "",
    sophisticated: mode === "register" && req.query.sophisticated === "1"
  };
  res.cookie(STATE_COOKIE, b64url(Buffer.from(JSON.stringify(pending))), {
    httpOnly: true,
    secure: isProd2,
    // Lax, not Strict: the callback is a top-level navigation coming back from Google.
    sameSite: "lax",
    path: STATE_PATH,
    maxAge: STATE_MINUTES * 60 * 1e3
  });
  const challenge = b64url(createHash2("sha256").update(pending.verifier).digest());
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.search = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "openid email profile",
    state: pending.state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    prompt: "select_account"
  }).toString();
  res.redirect(302, url.toString());
});
googleRouter.get("/google/callback", async (req, res) => {
  const ip = clientIp(req);
  const raw = readCookie(req, STATE_COOKIE);
  clearState(res);
  let pending = null;
  try {
    pending = raw ? JSON.parse(Buffer.from(raw, "base64url").toString("utf8")) : null;
  } catch {
    pending = null;
  }
  const mode = pending?.mode === "register" ? "register" : "login";
  if (typeof req.query.error === "string") return fail(res, mode, "cancelled");
  const state = typeof req.query.state === "string" ? req.query.state : "";
  const code2 = typeof req.query.code === "string" ? req.query.code : "";
  if (!googleEnabled) return fail(res, mode, "off");
  if (!pending || !state || !code2 || !sameSecret(state, pending.state)) {
    await logEvent("google_bad_state", null, ip);
    return fail(res, mode, "expired");
  }
  try {
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code: code2,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
        grant_type: "authorization_code",
        code_verifier: pending.verifier
      }),
      signal: AbortSignal.timeout(1e4)
    });
    const tokens = await tokenRes.json().catch(() => ({}));
    if (!tokenRes.ok || !tokens.id_token) {
      console.error("[google] token exchange failed:", tokenRes.status, tokens.error ?? "");
      return fail(res, mode, "failed");
    }
    const claims = readIdToken(tokens.id_token);
    const email = clean(claims?.email, 254).toLowerCase();
    const verified = claims?.email_verified === true || claims?.email_verified === "true";
    if (!claims || !email || !verified) {
      await logEvent("google_unverified", email || null, ip);
      return fail(res, mode, "unverified");
    }
    const sub = claims.sub;
    let found = await query(
      "select id, status, google_sub from users where google_sub = $1",
      [sub]
    );
    let row = found.rows[0];
    let kind = "google_login";
    if (!row) {
      found = await query("select id, status, google_sub from users where lower(email) = $1", [email]);
      row = found.rows[0];
      if (row?.google_sub && row.google_sub !== sub) {
        await logEvent("google_conflict", email, ip);
        return fail(res, mode, "conflict");
      }
      if (row) {
        await query(
          `update users set google_sub = $1, email_verified_at = coalesce(email_verified_at, now()),
                  updated_at = now() where id = $2`,
          [sub, row.id]
        );
        kind = "google_link";
      }
    }
    if (!row) {
      if (!pending.terms || !pending.country || needsSophisticatedDeclaration(pending.country) && !pending.sophisticated) {
        await logEvent("google_needs_terms", email, ip);
        return fail(res, "register", "terms");
      }
      if (!isValidCountry(pending.country)) {
        await logEvent("google_bad_country", email, ip);
        return fail(res, "register", "country");
      }
      if (await countEvents("register", "ip", ip, 60) >= LIMITS.registerPerIpPerHour) {
        await logEvent("register_throttled", email, ip);
        return fail(res, "register", "throttled");
      }
      const first = clean(claims.given_name) || clean(claims.name).split(" ")[0] || "Nucleus";
      const last = clean(claims.family_name) || clean(claims.name).split(" ").slice(1).join(" ") || "Customer";
      const inserted = await query(
        `insert into users (email, first_name, last_name, password_hash, terms_accepted_at, signup_ip,
                            google_sub, email_verified_at, country, sophisticated_at)
         values ($1, $2, $3, $4, now(), $5, $6, now(), $7, case when $8::boolean then now() else null end)
         returning id, status, google_sub`,
        [email, first, last, placeholderHash(), ip, sub, pending.country, pending.sophisticated]
      );
      row = inserted.rows[0];
      if (isListedAdmin(email)) {
        await query("update users set role = 'admin', updated_at = now() where id = $1", [row.id]);
      }
      await logEvent("register", email, ip);
      kind = "google_register";
    }
    if (row.status !== "active") {
      await logEvent("login_blocked", email, ip);
      return fail(res, mode, "blocked");
    }
    const token = await createSession(row.id, req);
    setSessionCookie(res, token);
    await logEvent(kind, email, ip);
    res.redirect(303, "/portal");
  } catch (err) {
    console.error("[google] callback error:", err.message);
    return fail(res, mode, "failed");
  }
});

// server/deploy-notice.ts
import fs from "node:fs";
import path from "node:path";
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
app.get("/api/auth/providers", (_req, res) => {
  res.json({ ok: true, google: dbConfigured && googleEnabled });
});
if (dbConfigured) {
  app.use("/api/auth", googleRouter);
  app.use("/api/auth", authRouter);
  app.use("/api/admin", adminRouter);
  app.use("/api/ib", ibRouter);
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
