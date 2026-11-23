import { error, serveAsset } from "./http.js";
import { hasSession, isConfigured, isLoopback, logIn } from "./session.js";
import { handleVault, vaultSchema } from "./vault.js";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;
    if (url.protocol !== "https:" && !isLoopback(url)) return error(403, "HTTPS is required");

    try {
      if (!pathname.startsWith("/api/")) {
        if (request.method !== "GET" && request.method !== "HEAD") {
          return error(405, "Method not allowed", { Allow: "GET, HEAD" });
        }
        return await serveAsset(request, env.ASSETS);
      }
      if (pathname !== "/api/session" && pathname !== "/api/vault") {
        return error(404, "Unknown API route");
      }
      const allow = pathname === "/api/session" ? ["POST"] : ["GET", "PUT"];
      if (!allow.includes(request.method)) return error(405, "Method not allowed", { Allow: allow.join(", ") });
      const origin = request.headers.get("Origin");
      if (origin !== url.origin && (origin !== null || request.method !== "GET")) {
        return error(403, "Origin denied");
      }
      if (!isConfigured(env.APP_PASSWORD)) return error(503, "Access password is not configured");

      if (pathname === "/api/session") {
        const response = await logIn(request, url, env);
        if (response.ok) await env.DB.prepare(vaultSchema).run();
        return response;
      }
      if (!await hasSession(request, url, env.APP_PASSWORD)) return error(401, "Sign-in required");
      return await handleVault(request, env.DB);
    } catch {
      return error(500, "Worker request failed");
    }
  },
};
