import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { createSalt, deriveKey, openVault, sealVault } from "../web/js/crypto.js";
import { vaultSchema } from "../src/worker/vault.js";
import worker from "../src/worker/index.js";

const sample = [{
  id: "note-1",
  title: "私密标题",
  body: "测试正文 🔐",
  tags: ["个人"],
  updatedAt: "2026-11-23T00:00:00.000Z",
}];
const passphrase = "test-only-passphrase";
const migration = readFileSync(new URL("../migrations/0001_vault.sql", import.meta.url), "utf8");
const origin = "https://notes.example.com";
const url = `${origin}/api/vault`;
const accessPassword = "test-only-random-style-password-123456";

function login(env, password, requestOrigin = origin) {
  return worker.fetch(new Request(`${origin}/api/session`, {
    method: "POST",
    headers: { Origin: requestOrigin, "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  }), env);
}

function passwordEnv() {
  return { APP_PASSWORD: accessPassword, LOGIN_LIMIT: { limit: async () => ({ success: true }) } };
}

test("vault encrypts every save with a fresh IV and authenticates the contents", async () => {
  const salt = createSalt();
  const key = await deriveKey(passphrase, salt);
  const first = await sealVault(key, salt, sample);
  const second = await sealVault(key, salt, sample);
  const empty = await sealVault(key, salt, []);
  assert.notEqual(first.iv, second.iv);
  assert.equal(first.ciphertext.length, empty.ciphertext.length);
  assert.equal(key.extractable, false);
  assert.ok(!JSON.stringify(first).includes(sample[0].title));
  assert.deepEqual(await openVault(await deriveKey(passphrase, salt), second), sample);

  await assert.rejects(openVault(await deriveKey("incorrect", salt), first), { name: "OperationError" });
  const bytes = Buffer.from(first.ciphertext, "base64");
  bytes[0] ^= 1;
  await assert.rejects(openVault(key, { ...first, ciphertext: bytes.toString("base64") }),
    { name: "OperationError" });

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const legacy = await crypto.subtle.encrypt({
    name: "AES-GCM", iv, additionalData: encoder.encode("cfe2e-note/vault/v1"),
  }, key, encoder.encode(JSON.stringify({ notes: sample })));
  assert.deepEqual(await openVault(key, {
    ...first, iv: Buffer.from(iv).toString("base64"), ciphertext: Buffer.from(legacy).toString("base64"),
  }), sample);
});

test("the first authenticated session initializes a fresh database and stale writes are rejected", async () => {
  const database = new DatabaseSync(":memory:");
  try {
    assert.equal(vaultSchema, migration.trim());
    const env = {
      ...passwordEnv(),
      DB: {
        prepare(query) {
          const statement = database.prepare(query);
          return {
            run: () => statement.run(),
            first: () => statement.get(),
            bind: (...params) => ({ first: () => statement.get(...params) }),
          };
        },
      },
    };
    const salt = createSalt();
    const key = await deriveKey(passphrase, salt);
    const blank = await sealVault(key, salt, []);
    const next = await sealVault(key, salt, sample);
    const tableExists = () => !!database.prepare("SELECT 1 FROM sqlite_master WHERE name = 'vault'").get();
    assert.equal((await login(env, "wrong-access-password-only-used-in-tests")).status, 401);
    assert.equal(tableExists(), false);
    const [authenticated, concurrent] = await Promise.all([login(env, accessPassword), login(env, accessPassword)]);
    assert.equal(authenticated.status, 200);
    assert.equal(concurrent.status, 200);
    assert.equal(tableExists(), true);
    const { token } = await authenticated.json();
    const authHeaders = { Authorization: `Bearer ${token}` };
    const get = (headers = authHeaders) => worker.fetch(new Request(url, { headers }), env);
    const put = (body, headers = {}) => worker.fetch(new Request(url, {
      method: "PUT",
      headers: { Origin: origin, ...authHeaders, "Content-Type": "application/json", ...headers },
      body: JSON.stringify(body),
    }), env);

    assert.equal((await get({})).status, 401);
    assert.equal((await get()).status, 404);
    assert.equal((await put(blank)).status, 428);
    assert.equal((await put(blank, { Origin: "https://other.example", "If-None-Match": "*" })).status, 403);
    assert.equal((await put({ ...blank, title: sample[0].title }, { "If-None-Match": "*" })).status, 400);
    assert.equal((await put({ ciphertext: "a".repeat(1_000_000) }, { "If-None-Match": "*" })).status, 413);
    assert.equal((await put(blank, { "If-None-Match": "*" })).status, 201);
    assert.equal((await put(next, { "If-None-Match": "*" })).status, 412);

    const updates = await Promise.all([
      put(next, { "If-Match": '"1"' }),
      put(blank, { "If-Match": '"1"' }),
    ]);
    assert.deepEqual(updates.map(({ status }) => status).sort(), [200, 412]);
    const winner = updates[0].status === 200 ? next : blank;
    const response = await get();
    assert.equal(response.headers.get("ETag"), '"2"');
    assert.equal(response.headers.get("Cache-Control"), "no-store");
    assert.deepEqual(await response.json(), winner);
    database.exec(migration);
    assert.deepEqual(JSON.parse(database.prepare("SELECT envelope FROM vault").get().envelope), winner);
    assert.equal((await login(env, accessPassword)).status, 200);
    assert.deepEqual(JSON.parse(database.prepare("SELECT envelope FROM vault").get().envelope), winner);
  } finally {
    database.close();
  }
});

test("worker serves the login page and restricts the API to same-origin password sessions", async (t) => {
  const rateKeys = [];
  const env = passwordEnv();
  env.DB = { prepare: () => ({ run() {} }) };
  env.ASSETS = {
    fetch: async (request) => new URL(request.url).pathname === "/"
      ? new Response(readFileSync(new URL("../web/index.html", import.meta.url)), {
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "max-age=3600" },
      })
      : new Response(null, { status: 404 }),
  };
  env.LOGIN_LIMIT.limit = async ({ key }) => {
    rateKeys.push(key);
    return { success: true };
  };
  const request = (path, token, overrides = {}) => worker.fetch(new Request(`${origin}${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  }), { ...env, ...overrides });

  assert.equal((await request("/api/vault", undefined, { APP_PASSWORD: "" })).status, 503);
  const root = await request("/");
  assert.equal(root.status, 200);
  assert.match(root.headers.get("Content-Type"), /^text\/html/);
  assert.equal(root.headers.get("Cache-Control"), "no-store");
  assert.match(root.headers.get("Content-Security-Policy"), /connect-src 'self'/);
  assert.match(await root.text(), /登录门禁/);
  assert.equal((await request("/api/vault")).status, 401);
  assert.equal((await login(env, accessPassword, "https://other.example")).status, 403);
  assert.equal((await login(env, "test-only-wrong-password-value-123456")).status, 401);
  const limited = { ...env, LOGIN_LIMIT: { limit: async () => ({ success: false }) } };
  assert.equal((await login(limited, accessPassword)).status, 429);

  const preflight = await worker.fetch(new Request(url, {
    method: "OPTIONS", headers: { Origin: "https://other.example" },
  }), env);
  assert.equal(preflight.status, 405);
  assert.equal(preflight.headers.get("Access-Control-Allow-Origin"), null);
  assert.equal(preflight.headers.get("Access-Control-Allow-Credentials"), null);

  const signIn = await login(env, accessPassword);
  assert.equal(signIn.status, 200);
  assert.equal(signIn.headers.get("Set-Cookie"), null);
  assert.equal(signIn.headers.get("Cache-Control"), "no-store");
  const { token } = await signIn.json();
  assert.ok(rateKeys.every((key) => /^[A-Za-z0-9_-]{43}$/.test(key)));
  const allowed = await request("/api/vault", token, {
    DB: { prepare: () => ({ first: () => null }) },
  });
  assert.equal(allowed.status, 404);
  assert.equal((await worker.fetch(new Request(url, {
    headers: { Origin: "https://other.example", Authorization: `Bearer ${token}` },
  }), env)).status, 403);

  const fields = token.split(".");
  fields[3] = (fields[3][0] === "A" ? "B" : "A") + fields[3].slice(1);
  assert.equal((await request("/api/vault", fields.join("."))).status, 401);
  assert.equal((await request("/api/vault", token, { APP_PASSWORD: accessPassword + "-rotated" })).status, 401);
  assert.equal((await worker.fetch(new Request("https://other.example/api/vault", {
    headers: { Authorization: `Bearer ${token}` },
  }), env)).status, 401);

  assert.equal((await worker.fetch(new Request(url, {
    headers: { Cookie: `session=${token}` },
  }), env)).status, 401);

  t.mock.timers.enable({ apis: ["Date"], now: Date.now() });
  t.mock.timers.tick(15 * 60 * 1000);
  assert.equal((await request("/api/vault", token)).status, 401);
});
