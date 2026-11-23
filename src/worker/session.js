import { error, headers, readText } from "./http.js";

const encoder = new TextEncoder();
const hmac = { name: "HMAC", hash: "SHA-256" };
const passwordCheck = encoder.encode("cfe2e-note/password/v1");
const sessionSeconds = 15 * 60;
const tokenPattern = /^(v1\.(\d{1,12})\.[A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})$/;

export function isConfigured(password) {
  return typeof password === "string" && password.length >= 32 && password.length <= 256;
}

export function isLoopback(url) {
  return url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
}

function encodeToken(bytes) {
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function decodeToken(value) {
  return Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/")),
    (character) => character.charCodeAt(0));
}

function keyFor(password) {
  return crypto.subtle.importKey("raw", encoder.encode(password), hmac, false, ["sign", "verify"]);
}

function sessionMessage(url, token) {
  return encoder.encode(`cfe2e-note/session/${url.origin}/${token}`);
}

export async function hasSession(request, url, password) {
  const value = request.headers.get("Authorization");
  const fields = value?.startsWith("Bearer ") && tokenPattern.exec(value.slice(7));
  if (!fields) return false;

  const [, token, expires, signature] = fields;
  if (Number(expires) <= Math.floor(Date.now() / 1000)) return false;
  return crypto.subtle.verify(hmac, await keyFor(password), decodeToken(signature), sessionMessage(url, token));
}

export async function logIn(request, url, env) {
  const contentType = request.headers.get("Content-Type")?.split(";")[0].trim().toLowerCase();
  if (contentType !== "application/json") return error(415, "Expected JSON");
  const key = await keyFor(env.APP_PASSWORD);
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const bucket = Math.floor(Date.now() / 60_000);
  const digest = await crypto.subtle.sign(hmac, key, encoder.encode(`cfe2e-note/limit/${bucket}/${ip}`));
  const { success } = await env.LOGIN_LIMIT.limit({ key: encodeToken(new Uint8Array(digest)) });
  if (!success) return error(429, "Too many sign-in attempts");

  const body = await readText(request, 4096);
  if (body === null) return error(413, "Login request is too large");
  let attempt;
  try {
    attempt = JSON.parse(body)?.password;
  } catch {
    return error(400, "Invalid sign-in request");
  }
  if (!isConfigured(attempt)) return error(401, "Invalid access password");
  const proof = await crypto.subtle.sign(hmac, await keyFor(attempt), passwordCheck);
  if (!await crypto.subtle.verify(hmac, key, proof, passwordCheck)) {
    return error(401, "Invalid access password");
  }

  const expires = Math.floor(Date.now() / 1000) + sessionSeconds;
  const nonce = encodeToken(crypto.getRandomValues(new Uint8Array(16)));
  const token = `v1.${expires}.${nonce}`;
  const signature = new Uint8Array(await crypto.subtle.sign(hmac, key, sessionMessage(url, token)));
  return Response.json({ token: `${token}.${encodeToken(signature)}` }, { headers });
}
