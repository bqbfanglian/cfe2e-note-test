export const headers = {
  "Cache-Control": "no-store",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
};

export async function serveAsset(request, assets) {
  const asset = await assets.fetch(request);
  const responseHeaders = new Headers(asset.headers);
  for (const [name, value] of Object.entries(headers)) responseHeaders.set(name, value);
  responseHeaders.set("Content-Security-Policy",
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
  responseHeaders.set("Cross-Origin-Opener-Policy", "same-origin");
  responseHeaders.set("Cross-Origin-Resource-Policy", "same-origin");
  return new Response(asset.body, { status: asset.status, statusText: asset.statusText, headers: responseHeaders });
}

export function error(status, message, extraHeaders) {
  return Response.json({ error: message }, { status, headers: { ...headers, ...extraHeaders } });
}

export async function readText(request, limit) {
  if (Number(request.headers.get("Content-Length")) > limit) return null;
  if (!request.body) return "";

  const reader = request.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let length = 0;
  let text = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > limit) {
        await reader.cancel();
        return null;
      }
      text += decoder.decode(value, { stream: true });
    }
    return text + decoder.decode();
  } catch {
    return "";
  } finally {
    reader.releaseLock();
  }
}
