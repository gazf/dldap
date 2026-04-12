/**
 * グループ CRUD + メンバー管理
 *
 * GET    /api/groups
 * GET    /api/groups/:cn
 * POST   /api/groups
 * PUT    /api/groups/:cn
 * DELETE /api/groups/:cn
 * POST   /api/groups/:cn/members
 * DELETE /api/groups/:cn/members/:uid
 */

import type { Config } from "../../../config/default.ts";
import type { DirectoryEntry, DirectoryStore } from "../../store/types.ts";
import { entryToGroup, findGroups, isGroup } from "../helpers/entry.ts";
import {
  badRequest,
  conflict,
  created,
  noContent,
  notFound,
  ok,
} from "../helpers/response.ts";

export async function handleListGroups(
  store: DirectoryStore,
  config: Config,
): Promise<Response> {
  const groups = await findGroups(store, config.baseDN);
  return ok(groups);
}

export async function handleGetGroup(
  cn: string,
  store: DirectoryStore,
  config: Config,
): Promise<Response> {
  const entry = await findGroupEntry(cn, store, config.baseDN);
  if (!entry) return notFound(`Group '${cn}' not found`);
  return ok(entryToGroup(entry));
}

export async function handleCreateGroup(
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

  const cn = String(body.cn ?? "").trim();
  if (!cn) return badRequest("cn is required");

  const ou = String(body.ou ?? `ou=groups,${config.baseDN}`);
  const dn = `cn=${cn},${ou}`;

  const parent = await store.get(ou.toLowerCase());
  if (!parent) return badRequest(`Parent OU '${ou}' does not exist`);

  const existing = await store.get(dn.toLowerCase());
  if (existing) return conflict(`Group '${cn}' already exists`);

  const objectClasses = ["top", "posixgroup"];
  const attrs: Record<string, string[]> = {
    cn: [cn],
    objectclass: objectClasses,
    memberuid: [],
  };

  if (body.gidNumber) attrs["gidnumber"] = [String(body.gidNumber)];
  if (body.description) attrs["description"] = [String(body.description)];

  await store.set({ dn: dn.toLowerCase(), attrs });

  const entry = await store.get(dn.toLowerCase());
  return created(entryToGroup(entry!));
}

export async function handleUpdateGroup(
  cn: string,
  req: Request,
  store: DirectoryStore,
  config: Config,
): Promise<Response> {
  const entry = await findGroupEntry(cn, store, config.baseDN);
  if (!entry) return notFound(`Group '${cn}' not found`);

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return badRequest("Invalid JSON body");
  }

  const attrs = { ...entry.attrs };
  if (body.gidNumber !== undefined) attrs["gidnumber"] = [String(body.gidNumber)];
  if (body.description !== undefined) attrs["description"] = [String(body.description)];

  await store.set({ dn: entry.dn, attrs });

  const updated = await store.get(entry.dn);
  return ok(entryToGroup(updated!));
}

export async function handleDeleteGroup(
  cn: string,
  store: DirectoryStore,
  config: Config,
): Promise<Response> {
  const entry = await findGroupEntry(cn, store, config.baseDN);
  if (!entry) return notFound(`Group '${cn}' not found`);

  await store.delete(entry.dn);
  return noContent();
}

export async function handleAddMember(
  cn: string,
  req: Request,
  store: DirectoryStore,
  config: Config,
): Promise<Response> {
  const entry = await findGroupEntry(cn, store, config.baseDN);
  if (!entry) return notFound(`Group '${cn}' not found`);

  let body: { uid?: string };
  try {
    body = await req.json();
  } catch {
    return badRequest("Invalid JSON body");
  }
  if (!body.uid) return badRequest("uid is required");

  const attrs = { ...entry.attrs };
  const members = [...(attrs["memberuid"] ?? [])];
  if (!members.includes(body.uid)) {
    members.push(body.uid);
    attrs["memberuid"] = members;
    await store.set({ dn: entry.dn, attrs });
  }

  const updated = await store.get(entry.dn);
  return ok(entryToGroup(updated!));
}

export async function handleRemoveMember(
  cn: string,
  uid: string,
  store: DirectoryStore,
  config: Config,
): Promise<Response> {
  const entry = await findGroupEntry(cn, store, config.baseDN);
  if (!entry) return notFound(`Group '${cn}' not found`);

  const attrs = { ...entry.attrs };
  attrs["memberuid"] = (attrs["memberuid"] ?? []).filter((m: string) => m !== uid);
  await store.set({ dn: entry.dn, attrs });

  const updated = await store.get(entry.dn);
  return ok(entryToGroup(updated!));
}

// ---------------------------------------------------------------------------
// 内部ヘルパー
// ---------------------------------------------------------------------------

async function findGroupEntry(
  cn: string,
  store: DirectoryStore,
  baseDN: string,
) {
  const groupsOU = `ou=groups,${baseDN}`;
  const candidates = await store.listSubtree(groupsOU);
  return candidates.find(
    (e: DirectoryEntry) => isGroup(e) && e.attrs["cn"]?.[0] === cn,
  ) ?? null;
}
