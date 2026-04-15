import { ResultCode } from "../ldap/constants.ts";
import { ProtocolOp } from "../ldap/constants.ts";
import type { AddRequest, AddResponse } from "../ldap/messages.ts";
import { errorResult, successResult } from "../ldap/messages.ts";
import { normalizeDN, parentDN } from "../store/types.ts";
import type { HandlerContext } from "./context.ts";
import { onAdd, onGroupAdd } from "./samba_hooks.ts";

export async function handleAdd(
  req: AddRequest,
  ctx: HandlerContext,
): Promise<AddResponse> {
  if (!ctx.isAdmin) {
    return {
      type: ProtocolOp.AddResponse,
      result: errorResult(
        ResultCode.InsufficientAccessRights,
        "Write access requires authentication",
      ),
    };
  }

  const dn = normalizeDN(req.entry);

  // sambaDomain は dldap が仮想エントリとして管理するため書き込みをブロック
  if (ctx.config.samba.enabled) {
    const objectClasses = req.attributes
      .find((a) => a.type.toLowerCase() === "objectclass")
      ?.values.map((v) => v.toLowerCase()) ?? [];
    if (objectClasses.includes("sambadomain")) {
      return {
        type: ProtocolOp.AddResponse,
        result: errorResult(ResultCode.EntryAlreadyExists, "sambaDomain is managed by dldap"),
      };
    }
  }

  // Check if already exists
  const existing = await ctx.store.get(dn);
  if (existing) {
    return {
      type: ProtocolOp.AddResponse,
      result: errorResult(ResultCode.EntryAlreadyExists, `Entry already exists: ${dn}`),
    };
  }

  // Check parent exists (unless this is the base DN)
  const parent = parentDN(dn);
  if (parent && parent !== "") {
    const parentEntry = await ctx.store.get(parent);
    if (!parentEntry) {
      return {
        type: ProtocolOp.AddResponse,
        result: errorResult(ResultCode.NoSuchObject, `Parent does not exist: ${parent}`, parent),
      };
    }
  }

  // Build attrs map
  const attrs: Record<string, string[]> = {};
  for (const attr of req.attributes) {
    attrs[attr.type.toLowerCase()] = attr.values;
  }

  // Samba auto-population
  onAdd(attrs, ctx.config.samba);
  onGroupAdd(attrs, ctx.config.samba);

  await ctx.store.set({ dn, attrs });

  return { type: ProtocolOp.AddResponse, result: successResult() };
}
