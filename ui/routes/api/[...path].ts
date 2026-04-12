/**
 * Server-side API proxy.
 *
 * In development the Vite dev server proxies /api → http://localhost:8080.
 * In production (Docker) this route forwards the request to the backend
 * API server whose address is set via API_BASE_URL env var.
 *
 * All methods and request/response bodies are forwarded as-is.
 */
import { define } from "../../utils.ts";

const BACKEND = Deno.env.get("API_BASE_URL") ?? "http://localhost:8080";

async function proxy(ctx: { req: Request; params: Record<string, string> }): Promise<Response> {
  const path = ctx.params["path"] ?? "";
  const url = new URL(ctx.req.url);
  const target = `${BACKEND}/api/${path}${url.search}`;

  const headers = new Headers(ctx.req.headers);
  // Remove hop-by-hop headers that shouldn't be forwarded
  headers.delete("host");
  headers.delete("connection");

  const upstream = await fetch(target, {
    method: ctx.req.method,
    headers,
    body: ["GET", "HEAD"].includes(ctx.req.method) ? undefined : ctx.req.body,
    // @ts-ignore — Deno fetch supports duplex
    duplex: "half",
  });

  const resHeaders = new Headers(upstream.headers);
  resHeaders.delete("transfer-encoding");

  return new Response(upstream.body, {
    status: upstream.status,
    headers: resHeaders,
  });
}

export const handler = define.handlers({
  GET: proxy,
  POST: proxy,
  PUT: proxy,
  DELETE: proxy,
  PATCH: proxy,
  OPTIONS: proxy,
});
