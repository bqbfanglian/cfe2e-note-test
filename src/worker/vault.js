import { MAX_ENVELOPE_BYTES, validateEnvelope } from "../../web/js/vault-format.js";
import { error, headers, readText } from "./http.js";

export const vaultSchema = `CREATE TABLE IF NOT EXISTS vault (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  revision INTEGER NOT NULL CHECK (revision >= 1),
  envelope TEXT NOT NULL
);`;

export async function handleVault(request, db) {
  if (request.method === "GET") {
    const row = await db.prepare("SELECT revision, envelope FROM vault WHERE id = 1").first();
    if (!row) return error(404, "Vault has not been created");
    return new Response(row.envelope, {
      headers: {
        ...headers,
        "Content-Type": "application/json; charset=utf-8",
        ETag: `"${row.revision}"`,
      },
    });
  }

  if (request.method !== "PUT") return error(405, "Method not allowed", { Allow: "GET, PUT" });
  const match = request.headers.get("If-Match");
  const noneMatch = request.headers.get("If-None-Match");
  const create = noneMatch === "*" && match === null;
  const revision = match && /^"[1-9][0-9]*"$/.test(match) ? Number(match.slice(1, -1)) : NaN;
  if (!create && (noneMatch !== null || !Number.isSafeInteger(revision))) {
    return error(428, "A vault revision or a creation precondition is required");
  }

  const contentType = request.headers.get("Content-Type")?.split(";")[0].trim().toLowerCase();
  if (contentType !== "application/json") return error(415, "Expected JSON");

  const body = await readText(request, MAX_ENVELOPE_BYTES);
  if (body === null) return error(413, "Vault is too large");
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    return error(400, "Invalid encrypted vault");
  }
  if (!validateEnvelope(parsed)) return error(400, "Invalid encrypted vault");
  const envelope = JSON.stringify(parsed);

  const changed = create
    ? await db.prepare(`
        INSERT INTO vault (id, revision, envelope) VALUES (1, 1, ?)
        ON CONFLICT(id) DO NOTHING
        RETURNING revision
      `).bind(envelope).first()
    : await db.prepare(`
        UPDATE vault SET envelope = ?, revision = revision + 1
        WHERE id = 1 AND revision = ?
        RETURNING revision
      `).bind(envelope, revision).first();

  if (!changed) return error(412, "Vault revision has changed");
  return Response.json(changed, { status: create ? 201 : 200, headers });
}

