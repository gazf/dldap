/**
 * POST /api/auth  — 認証・トークン発行
 * DELETE /api/auth — ログアウト・トークン失効
 */

import type { Config } from "../../../config/default.ts";
import { createToken, extractBearerToken, revokeToken } from "../auth.ts";
import { badRequest, json, noContent, unauthorized } from "../helpers/response.ts";

export async function handleAuthPost(
  req: Request,
  kv: Deno.Kv,
  config: Config,
  ttlSeconds: number,
): Promise<Response> {
  let body: { password?: string };
  try {
    body = await req.json();
  } catch {
    return badRequest("Invalid JSON body");
  }

  if (!body.password) return badRequest("password is required");

  if (body.password !== config.adminPassword) {
    return unauthorized();
  }

  const token = await createToken(kv, ttlSeconds);
  return json({ token, expiresIn: ttlSeconds }, 200);
}

export async function handleAuthDelete(
  req: Request,
  kv: Deno.Kv,
): Promise<Response> {
  const token = extractBearerToken(req);
  if (token) await revokeToken(kv, token);
  return noContent();
}
