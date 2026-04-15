/**
 * OU 管理
 *
 * GET    /api/ous
 * POST   /api/ous
 * DELETE /api/ous/:ou
 */

import type { Config } from "../../../config/default.ts";
import type { DirectoryStore } from "../../store/types.ts";
import { entryToOU, findOUs, isOU } from "../helpers/entry.ts";
import { badRequest, conflict, created, noContent, notFound, ok } from "../helpers/response.ts";

export async function handleListOUs(
  store: DirectoryStore,
  config: Config,
): Promise<Response> {
  const ous = await findOUs(store, config.baseDN);
  return ok(ous);
}

export async function handleCreateOU(
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

  const ou = String(body.ou ?? "").trim();
  if (!ou) return badRequest("ou is required");

  const dn = `ou=${ou},${config.baseDN}`;

  const existing = await store.get(dn.toLowerCase());
  if (existing) return conflict(`OU '${ou}' already exists`);

  const attrs: Record<string, string[]> = {
    ou: [ou],
    objectclass: ["top", "organizationalunit"],
  };
  if (body.description) attrs["description"] = [String(body.description)];

  await store.set({ dn: dn.toLowerCase(), attrs });

  const entry = await store.get(dn.toLowerCase());
  return created(entryToOU(entry!));
}

export async function handleDeleteOU(
  ou: string,
  store: DirectoryStore,
  config: Config,
): Promise<Response> {
  const dn = `ou=${ou},${config.baseDN}`;
  const entry = await store.get(dn.toLowerCase());
  if (!entry || !isOU(entry)) return notFound(`OU '${ou}' not found`);

  // 子エントリがある場合は削除拒否
  const children = await store.listChildren(dn.toLowerCase());
  if (children.length > 0) {
    return badRequest(`OU '${ou}' is not empty — delete its contents first`);
  }

  await store.delete(dn.toLowerCase());
  return noContent();
}
