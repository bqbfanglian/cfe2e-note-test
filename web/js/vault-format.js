const base64 = /^[A-Za-z0-9+/]+={0,2}$/;

export const MAX_ENVELOPE_BYTES = 1_000_000;
export const KDF_ITERATIONS = 600_000;

function isBase64(value) {
  return typeof value === "string" && value.length % 4 === 0 && base64.test(value);
}

export function hasFields(value, fields) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((name) => Object.hasOwn(value, name));
}

export function validateEnvelope(value) {
  return hasFields(value, ["format", "kdf", "salt", "iv", "ciphertext"]) &&
    value.format === 1 &&
    hasFields(value.kdf, ["name", "hash", "iterations"]) &&
    value.kdf.name === "PBKDF2" && value.kdf.hash === "SHA-256" &&
    value.kdf.iterations === KDF_ITERATIONS &&
    isBase64(value.salt) && value.salt.length === 24 && value.salt.endsWith("==") &&
    isBase64(value.iv) && value.iv.length === 16 && !value.iv.includes("=") &&
    isBase64(value.ciphertext) && value.ciphertext.length >= 24 &&
    value.ciphertext.length < MAX_ENVELOPE_BYTES;
}
