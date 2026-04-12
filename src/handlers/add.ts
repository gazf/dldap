import { ResultCode } from "../ldap/constants.ts";
import { ProtocolOp } from "../ldap/constants.ts";
import type { AddRequest, AddResponse } from "../ldap/messages.ts";
import { errorResult, successResult } from "../ldap/messages.ts";
import { normalizeDN, parentDN } from "../store/types.ts";
import type { HandlerContext } from "./context.ts";
import { onAdd } from "./samba_hooks.ts";

export async function handleAdd(
  req: AddRequest,
  ctx: HandlerContext,
): Promise<AddResponse> {
  if (!ctx.isAdmin) {
    return {
      type: ProtocolOp.AddResponse,
      result: errorResult(ResultCode.InsufficientAccessRights, "Write access requires authentication"),
    };
  }

  const dn = normalizeDN(req.entry);

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

  await ctx.store.set({ dn, attrs });

  return { type: ProtocolOp.AddResponse, result: successResult() };
}
