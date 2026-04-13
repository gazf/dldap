/**
 * URL ルーティング。Deno 標準の URLPattern を使用。外部依存なし。
 */

import type { Config } from "../../config/default.ts";
import type { DirectoryStore } from "../store/types.ts";
import { requireAuth } from "./middleware.ts";
import { handleAuthDelete, handleAuthPost } from "./handlers/auth.ts";
import { handleStatus, handleUpdateSID } from "./handlers/status.ts";
import {
  handleChangePassword,
  handleCreateUser,
  handleDeleteUser,
  handleGetUser,
  handleListUsers,
  handleUpdateUser,
} from "./handlers/users.ts";
import {
  handleAddMember,
  handleCreateGroup,
  handleDeleteGroup,
  handleGetGroup,
  handleListGroups,
  handleRemoveMember,
  handleUpdateGroup,
} from "./handlers/groups.ts";
import {
  handleCreateOU,
  handleDeleteOU,
  handleListOUs,
} from "./handlers/ous.ts";
import { notFound } from "./helpers/response.ts";

export interface RouterConfig {
  store: DirectoryStore;
  config: Config;
  kv: Deno.Kv;
  sessionTTL: number;
  corsOrigin: string;
}

// ---------------------------------------------------------------------------
// ルートテーブル（URLPattern + メソッド）
// ---------------------------------------------------------------------------

export async function route(req: Request, cfg: RouterConfig): Promise<Response> {
  const url = new URL(req.url);
  const method = req.method.toUpperCase();

  // CORS プリフライト
  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": cfg.corsOrigin,
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
      },
    });
  }

  // 認証不要ルート
  if (method === "POST" && url.pathname === "/api/auth") {
    return handleAuthPost(req, cfg.kv, cfg.config, cfg.sessionTTL);
  }

  // 認証必須ルート
  const authError = await requireAuth(req, cfg.kv);
  if (authError) return authError;

  // DELETE /api/auth
  if (method === "DELETE" && url.pathname === "/api/auth") {
    return handleAuthDelete(req, cfg.kv);
  }

  // GET /api/status
  if (method === "GET" && url.pathname === "/api/status") {
    return handleStatus(cfg.store, cfg.config);
  }

  // PUT /api/status/sid
  if (method === "PUT" && url.pathname === "/api/status/sid") {
    return handleUpdateSID(req, cfg.kv, cfg.config);
  }

  // --- ユーザー ---
  if (url.pathname === "/api/users") {
    if (method === "GET") return handleListUsers(cfg.store, cfg.config);
    if (method === "POST") return handleCreateUser(req, cfg.store, cfg.config);
  }

  const userMatch = new URLPattern({ pathname: "/api/users/:uid" }).exec(url);
  if (userMatch) {
    const uid = userMatch.pathname.groups["uid"]!;
    if (method === "GET") return handleGetUser(uid, cfg.store, cfg.config);
    if (method === "PUT") return handleUpdateUser(uid, req, cfg.store, cfg.config);
    if (method === "DELETE") return handleDeleteUser(uid, cfg.store, cfg.config);
  }

  const pwMatch = new URLPattern({ pathname: "/api/users/:uid/password" }).exec(url);
  if (pwMatch && method === "PUT") {
    const uid = pwMatch.pathname.groups["uid"]!;
    return handleChangePassword(uid, req, cfg.store, cfg.config);
  }

  // --- グループ ---
  if (url.pathname === "/api/groups") {
    if (method === "GET") return handleListGroups(cfg.store, cfg.config);
    if (method === "POST") return handleCreateGroup(req, cfg.store, cfg.config);
  }

  const groupMatch = new URLPattern({ pathname: "/api/groups/:cn" }).exec(url);
  if (groupMatch) {
    const cn = groupMatch.pathname.groups["cn"]!;
    if (method === "GET") return handleGetGroup(cn, cfg.store, cfg.config);
    if (method === "PUT") return handleUpdateGroup(cn, req, cfg.store, cfg.config);
    if (method === "DELETE") return handleDeleteGroup(cn, cfg.store, cfg.config);
  }

  const membersMatch = new URLPattern({ pathname: "/api/groups/:cn/members" }).exec(url);
  if (membersMatch && method === "POST") {
    const cn = membersMatch.pathname.groups["cn"]!;
    return handleAddMember(cn, req, cfg.store, cfg.config);
  }

  const memberMatch = new URLPattern({ pathname: "/api/groups/:cn/members/:uid" }).exec(url);
  if (memberMatch && method === "DELETE") {
    const cn = memberMatch.pathname.groups["cn"]!;
    const uid = memberMatch.pathname.groups["uid"]!;
    return handleRemoveMember(cn, uid, cfg.store, cfg.config);
  }

  // --- OU ---
  if (url.pathname === "/api/ous") {
    if (method === "GET") return handleListOUs(cfg.store, cfg.config);
    if (method === "POST") return handleCreateOU(req, cfg.store, cfg.config);
  }

  const ouMatch = new URLPattern({ pathname: "/api/ous/:ou" }).exec(url);
  if (ouMatch && method === "DELETE") {
    const ou = ouMatch.pathname.groups["ou"]!;
    return handleDeleteOU(ou, cfg.store, cfg.config);
  }

  return notFound();
}
