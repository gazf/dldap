/**
 * GET /api/status  — サーバー状態・エントリ数
 * PUT /api/status/sid — Domain SID の更新
 */

import type { Config } from "../../../config/default.ts";
import type { DirectoryStore } from "../../store/types.ts";
import { isGroup, isOU, isUser } from "../helpers/entry.ts";
import { badRequest, ok } from "../helpers/response.ts";

const DOMAIN_SID_KEY = ["config", "samba_domain_sid"] as const;

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
    sambaSID: config.samba.enabled ? config.samba.domainSID : undefined,
    counts: {
      users,
      groups,
      ous,
      total: all.length,
    },
  });
}

export async function handleUpdateSID(
  req: Request,
  kv: Deno.Kv,
  config: Config,
): Promise<Response> {
  let body: { sid?: string };
  try {
    body = await req.json();
  } catch {
    return badRequest("Invalid JSON body");
  }

  const sid = String(body.sid ?? "").trim();
  if (!sid) return badRequest("sid is required");

  if (!isValidDomainSID(sid)) {
    return badRequest(
      "Invalid SID format. Expected S-1-5-21-X-X-X where each value is 0–2147483647",
    );
  }

  await kv.set(DOMAIN_SID_KEY, sid);
  config.samba.domainSID = sid;

  return ok({ sambaSID: sid });
}

function isValidDomainSID(sid: string): boolean {
  const match = sid.match(/^S-1-5-21-(\d+)-(\d+)-(\d+)$/);
  if (!match) return false;
  return [match[1], match[2], match[3]].every((s) => {
    const n = parseInt(s, 10);
    return !isNaN(n) && n >= 0 && n <= 2147483647;
  });
}
