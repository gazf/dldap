import { ResultCode } from "../ldap/constants.ts";
import { ProtocolOp } from "../ldap/constants.ts";
import type { DelRequest, DelResponse } from "../ldap/messages.ts";
import { errorResult, successResult } from "../ldap/messages.ts";
import { normalizeDN } from "../store/types.ts";
import type { HandlerContext } from "./context.ts";

export async function handleDelete(
  req: DelRequest,
  ctx: HandlerContext,
): Promise<DelResponse> {
  if (!ctx.isAdmin) {
    return {
      type: ProtocolOp.DelResponse,
      result: errorResult(
        ResultCode.InsufficientAccessRights,
        "Write access requires authentication",
      ),
    };
  }

  const dn = normalizeDN(req.entry);

  // Check for children (non-leaf check)
  const children = await ctx.store.listChildren(dn);
  if (children.length > 0) {
    return {
      type: ProtocolOp.DelResponse,
      result: errorResult(ResultCode.NotAllowedOnNonLeaf, `Entry has children: ${dn}`),
    };
  }

  const deleted = await ctx.store.delete(dn);
  if (!deleted) {
    return {
      type: ProtocolOp.DelResponse,
      result: errorResult(ResultCode.NoSuchObject, `No such object: ${dn}`, dn),
    };
  }

  return { type: ProtocolOp.DelResponse, result: successResult() };
}
