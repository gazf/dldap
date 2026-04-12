/**
 * ミドルウェア: 認証チェック・CORS・エラーハンドリング。
 */

import { extractBearerToken, validateToken } from "./auth.ts";
import { unauthorized } from "./helpers/response.ts";

/** CORS プリフライト・ヘッダー付与。 */
export function corsHeaders(origin: string): HeadersInit {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

/** レスポンスに CORS ヘッダーを付与して返す。 */
export function withCors(res: Response, origin: string): Response {
  const headers = new Headers(res.headers);
  for (const [k, v] of Object.entries(corsHeaders(origin))) {
    headers.set(k, v);
  }
  return new Response(res.body, { status: res.status, headers });
}

/** Bearer トークンを検証し、無効な場合は 401 を返す。 */
export async function requireAuth(
  req: Request,
  kv: Deno.Kv,
): Promise<Response | null> {
  const token = extractBearerToken(req);
  if (!token) return unauthorized();
  const valid = await validateToken(kv, token);
  if (!valid) return unauthorized();
  return null; // 認証成功
}
