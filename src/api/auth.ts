/**
 * 不透明トークン（Opaque Token）によるセッション管理。
 *
 * トークンは crypto.getRandomValues() で生成した 32 バイトの乱数を
 * hex 文字列化したもの。Deno KV に有効期限付きで保存する。
 */

const SESSION_PREFIX = "api_session";

interface SessionValue {
  createdAt: number;
  expiresAt: number;
}

/** ランダムトークンを生成して KV に保存する。トークン文字列を返す。 */
export async function createToken(
  kv: Deno.Kv,
  ttlSeconds: number,
): Promise<string> {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const token = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const now = Date.now();
  await kv.set([SESSION_PREFIX, token], {
    createdAt: now,
    expiresAt: now + ttlSeconds * 1000,
  } satisfies SessionValue);

  return token;
}

/** トークンが有効かどうか検証する。期限切れは KV から削除して false を返す。 */
export async function validateToken(
  kv: Deno.Kv,
  token: string,
): Promise<boolean> {
  const result = await kv.get<SessionValue>([SESSION_PREFIX, token]);
  if (!result.value) return false;
  if (Date.now() > result.value.expiresAt) {
    await kv.delete([SESSION_PREFIX, token]);
    return false;
  }
  return true;
}

/** トークンを明示的に無効化する。 */
export async function revokeToken(kv: Deno.Kv, token: string): Promise<void> {
  await kv.delete([SESSION_PREFIX, token]);
}

/** Authorization: Bearer <token> ヘッダーからトークンを取り出す。 */
export function extractBearerToken(req: Request): string | null {
  const auth = req.headers.get("Authorization");
  if (!auth?.startsWith("Bearer ")) return null;
  return auth.slice(7).trim() || null;
}
