/**
 * GET /api/status — サーバー状態・エントリ数
 */

import type { Config } from "../../../config/default.ts";
import type { DirectoryStore } from "../../store/types.ts";
import { isGroup, isOU, isUser } from "../helpers/entry.ts";
import { ok } from "../helpers/response.ts";

export async function handleStatus(
  store: DirectoryStore,
  config: Config,
): Promise<Response> {
  const all = await store.listSubtree(config.baseDN);
  const users = all.filter(isUser).length;
  const groups = all.filter(isGroup).length;
  const ous = all.filter(isOU).length;

  return ok({
    ok: true,
    baseDN: config.baseDN,
    adminDN: config.adminDN,
    sambaEnabled: config.samba.enabled,
    sambaDomain: config.samba.enabled ? config.samba.domain : undefined,
    counts: {
      users,
      groups,
      ous,
      total: all.length,
    },
  });
}
