/**
 * ユーザー CRUD + パスワード変更
 *
 * GET    /api/users
 * GET    /api/users/:uid
 * POST   /api/users
 * PUT    /api/users/:uid
 * DELETE /api/users/:uid
 * PUT    /api/users/:uid/password
 */

import type { Config } from "../../../config/default.ts";
import type { DirectoryEntry, DirectoryStore } from "../../store/types.ts";
import { onAdd, onPasswordChange } from "../../handlers/samba_hooks.ts";
import { isSambaSamAccount } from "../../schema/samba.ts";
import { resolvePrimaryGroupSID } from "../../samba/sid.ts";
import { entryToUser, findUsers, isUser } from "../helpers/entry.ts";
import { badRequest, conflict, created, noContent, notFound, ok } from "../helpers/response.ts";

export async function handleListUsers(
  store: DirectoryStore,
  config: Config,
): Promise<Response> {
  const users = await findUsers(store, config.baseDN);
  return ok(users);
}

export async function handleGetUser(
  uid: string,
  store: DirectoryStore,
  config: Config,
): Promise<Response> {
  const entry = await findUserEntry(uid, store, config.baseDN);
  if (!entry) return notFound(`User '${uid}' not found`);
  return ok(entryToUser(entry));
}

export async function handleCreateUser(
  req: Request,
  store: DirectoryStore,
  config: Config,
): Promise<Response> {
  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return badRequest("Invalid JSON body");
  }

  const uid = String(body.uid ?? "").trim();
  const cn = String(body.cn ?? "").trim();
  const password = String(body.password ?? "").trim();
  const gidNumber = body.gidNumber !== undefined ? String(body.gidNumber).trim() : "";

  if (!uid) return badRequest("uid is required");
  if (!cn) return badRequest("cn is required");
  if (!password) return badRequest("password is required");
  if (!gidNumber) return badRequest("gidNumber is required");

  const ou = String(body.ou ?? `ou=users,${config.baseDN}`);
  const dn = `uid=${uid},${ou}`;

  // 親 OU の存在確認
  const parent = await store.get(ou.toLowerCase());
  if (!parent) return badRequest(`Parent OU '${ou}' does not exist`);

  // 重複確認
  const existing = await store.get(dn.toLowerCase());
  if (existing) return conflict(`User '${uid}' already exists`);

  const objectClasses = Array.isArray(body.objectClasses)
    ? (body.objectClasses as string[]).map((s) => String(s).toLowerCase())
    : ["top", "person", "organizationalperson", "inetorgperson", "posixaccount"];

  if (config.samba.enabled) {
    if (!objectClasses.includes("sambasamaccount")) {
      objectClasses.push("sambasamaccount");
    }
  }

  const attrs: Record<string, string[]> = {
    uid: [uid],
    cn: [cn],
    objectclass: objectClasses,
    userpassword: [password],
  };

  if (body.sn) attrs["sn"] = [String(body.sn)];
  if (body.givenName) attrs["givenname"] = [String(body.givenName)];
  if (body.mail) attrs["mail"] = [String(body.mail)];
  if (body.uidNumber) attrs["uidnumber"] = [String(body.uidNumber)];
  attrs["gidnumber"] = [gidNumber];
  if (body.homeDirectory) attrs["homedirectory"] = [String(body.homeDirectory)];
  if (body.loginShell) attrs["loginshell"] = [String(body.loginShell)];
  if (body.description) attrs["description"] = [String(body.description)];

  // posixAccount の必須属性を自動補完
  if (!attrs["uidnumber"]) {
    attrs["uidnumber"] = [String(await store.allocateUid(config.posix.uidStart))];
  }
  if (!attrs["homedirectory"]) {
    attrs["homedirectory"] = [`${config.posix.homeBase}/${uid}`];
  }
  if (!attrs["loginshell"]) {
    attrs["loginshell"] = [config.posix.defaultShell];
  }

  // Samba 属性を自動生成
  onAdd(attrs, config.samba);

  await store.set({ dn: dn.toLowerCase(), attrs });

  const entry = await store.get(dn.toLowerCase());
  return created(entryToUser(entry!));
}

export async function handleUpdateUser(
  uid: string,
  req: Request,
  store: DirectoryStore,
  config: Config,
): Promise<Response> {
  const entry = await findUserEntry(uid, store, config.baseDN);
  if (!entry) return notFound(`User '${uid}' not found`);

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return badRequest("Invalid JSON body");
  }

  const attrs = { ...entry.attrs };

  if (body.cn !== undefined) attrs["cn"] = [String(body.cn)];
  if (body.sn !== undefined) attrs["sn"] = [String(body.sn)];
  if (body.givenName !== undefined) attrs["givenname"] = [String(body.givenName)];
  if (body.mail !== undefined) attrs["mail"] = [String(body.mail)];
  if (body.uidNumber !== undefined) attrs["uidnumber"] = [String(body.uidNumber)];
  if (body.gidNumber !== undefined) {
    attrs["gidnumber"] = [String(body.gidNumber)];
    if (config.samba.enabled && isSambaSamAccount(attrs["objectclass"] ?? [])) {
      attrs["sambaprimarygroupsid"] = [resolvePrimaryGroupSID(config.samba.domainSID, attrs)];
    }
  }
  if (body.homeDirectory !== undefined) attrs["homedirectory"] = [String(body.homeDirectory)];
  if (body.loginShell !== undefined) attrs["loginshell"] = [String(body.loginShell)];
  if (body.description !== undefined) attrs["description"] = [String(body.description)];

  await store.set({ dn: entry.dn, attrs });

  const updated = await store.get(entry.dn);
  return ok(entryToUser(updated!));
}

export async function handleDeleteUser(
  uid: string,
  store: DirectoryStore,
  config: Config,
): Promise<Response> {
  const entry = await findUserEntry(uid, store, config.baseDN);
  if (!entry) return notFound(`User '${uid}' not found`);

  await store.delete(entry.dn);
  return noContent();
}

export async function handleChangePassword(
  uid: string,
  req: Request,
  store: DirectoryStore,
  config: Config,
): Promise<Response> {
  const entry = await findUserEntry(uid, store, config.baseDN);
  if (!entry) return notFound(`User '${uid}' not found`);

  let body: { password?: string };
  try {
    body = await req.json();
  } catch {
    return badRequest("Invalid JSON body");
  }

  if (!body.password) return badRequest("password is required");

  const attrs = { ...entry.attrs };
  attrs["userpassword"] = [body.password];

  // Samba NT ハッシュ更新
  const sambaUpdates = onPasswordChange(body.password, attrs, config.samba);
  Object.assign(attrs, sambaUpdates);

  await store.set({ dn: entry.dn, attrs });
  return noContent();
}

// ---------------------------------------------------------------------------
// 内部ヘルパー
// ---------------------------------------------------------------------------

async function findUserEntry(
  uid: string,
  store: DirectoryStore,
  baseDN: string,
) {
  // まず ou=users 以下を検索
  const usersOU = `ou=users,${baseDN}`;
  const candidates = await store.listSubtree(usersOU);
  const found = candidates.find(
    (e: DirectoryEntry) => isUser(e) && e.attrs["uid"]?.[0] === uid,
  );
  if (found) return found;

  // baseDN 直下にいる場合のフォールバック
  const direct = await store.get(`uid=${uid},${baseDN}`.toLowerCase());
  if (direct && isUser(direct)) return direct;

  return null;
}
