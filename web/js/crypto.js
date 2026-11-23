import { hasFields, KDF_ITERATIONS, MAX_ENVELOPE_BYTES, validateEnvelope } from "./vault-format.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const additionalData = encoder.encode("cfe2e-note/vault/v1");
const paddingBlock = 32 * 1024;

function encodeBytes(bytes) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 8192) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  }
  return btoa(binary);
}

function decodeBytes(value) {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

export function createSalt() {
  return encodeBytes(crypto.getRandomValues(new Uint8Array(16)));
}

export async function deriveKey(passphrase, salt) {
  const bytes = encoder.encode(passphrase);
  passphrase = "";
  let material;
  try {
    material = await crypto.subtle.importKey("raw", bytes, "PBKDF2", false, ["deriveKey"]);
  } finally {
    bytes.fill(0);
  }
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: KDF_ITERATIONS,
      salt: decodeBytes(salt),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function sealVault(key, salt, notes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const envelope = {
    format: 1,
    kdf: { name: "PBKDF2", hash: "SHA-256", iterations: KDF_ITERATIONS },
    salt,
    iv: encodeBytes(iv),
    ciphertext: "",
  };
  const json = encoder.encode(JSON.stringify({ notes }));
  const maxPlaintext = 3 * Math.floor((MAX_ENVELOPE_BYTES - JSON.stringify(envelope).length) / 4) - 16;
  if (json.length > maxPlaintext) {
    json.fill(0);
    throw new RangeError("Vault size limit exceeded");
  }
  // JSON permits trailing spaces, allowing old format-1 clients to read padded vaults.
  const length = Math.min(maxPlaintext, Math.ceil(json.length / paddingBlock) * paddingBlock);
  const plaintext = new Uint8Array(length).fill(0x20);
  plaintext.set(json);
  json.fill(0);
  try {
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData }, key, plaintext);
    envelope.ciphertext = encodeBytes(new Uint8Array(ciphertext));
    return envelope;
  } finally {
    plaintext.fill(0);
  }
}

export async function openVault(key, envelope) {
  if (!validateEnvelope(envelope)) throw new Error("Unsupported vault format");
  const plaintext = new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: decodeBytes(envelope.iv), additionalData },
    key,
    decodeBytes(envelope.ciphertext),
  ));
  let notes;
  try {
    ({ notes } = JSON.parse(decoder.decode(plaintext)));
  } finally {
    plaintext.fill(0);
  }
  if (!Array.isArray(notes) || !notes.every(isNote) ||
      new Set(notes.map(({ id }) => id)).size !== notes.length) {
    throw new Error("Invalid vault contents");
  }
  return notes;
}

function isNote(note) {
  return hasFields(note, ["id", "title", "body", "tags", "updatedAt"]) &&
    typeof note.id === "string" && note.id.length > 0 &&
    typeof note.title === "string" && typeof note.body === "string" &&
    Array.isArray(note.tags) && note.tags.every((tag) => typeof tag === "string") &&
    typeof note.updatedAt === "string" && Number.isFinite(Date.parse(note.updatedAt));
}
