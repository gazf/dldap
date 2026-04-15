import { ResultCode } from "../ldap/constants.ts";
import { ProtocolOp } from "../ldap/constants.ts";
import type { ModifyDNRequest, ModifyDNResponse } from "../ldap/messages.ts";
import { errorResult, successResult } from "../ldap/messages.ts";
import { normalizeDN, parentDN } from "../store/types.ts";
import type { HandlerContext } from "./context.ts";

export async function handleModifyDN(
  req: ModifyDNRequest,
  ctx: HandlerContext,
): Promise<ModifyDNResponse> {
  if (!ctx.isAdmin) {
    return {
      type: ProtocolOp.ModifyDNResponse,
      result: errorResult(
        ResultCode.InsufficientAccessRights,
        "Write access requires authentication",
      ),
    };
  }

  const oldDN = normalizeDN(req.entry);

  // Determine new parent
  const newParent = req.newSuperior ? normalizeDN(req.newSuperior) : parentDN(oldDN);

  const newDN = newParent ? `${req.newRDN},${newParent}` : req.newRDN;
  const newDNNorm = normalizeDN(newDN);

  // Target must not already exist
  const existing = await ctx.store.get(newDNNorm);
  if (existing) {
    return {
      type: ProtocolOp.ModifyDNResponse,
      result: errorResult(ResultCode.EntryAlreadyExists, `Target DN already exists: ${newDNNorm}`),
    };
  }

  try {
    await ctx.store.rename(oldDN, newDNNorm);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes("not found")) {
      return {
        type: ProtocolOp.ModifyDNResponse,
        result: errorResult(ResultCode.NoSuchObject, `No such object: ${oldDN}`, oldDN),
      };
    }
    throw e;
  }

  // Update the RDN attribute in the entry if deleteOldRDN
  if (req.deleteOldRDN) {
    const entry = await ctx.store.get(newDNNorm);
    if (entry) {
      // Parse old RDN attribute type=value
      const [oldRDNType, oldRDNValue] = parseRDN(oldDN.split(",")[0]);
      const [newRDNType, newRDNValue] = parseRDN(req.newRDN);

      const attrs = { ...entry.attrs };
      // Remove old RDN value
      if (oldRDNType && attrs[oldRDNType]) {
        attrs[oldRDNType] = attrs[oldRDNType].filter(
          (v) => v.toLowerCase() !== oldRDNValue.toLowerCase(),
        );
        if (attrs[oldRDNType].length === 0) delete attrs[oldRDNType];
      }
      // Add new RDN value
      if (newRDNType) {
        if (!attrs[newRDNType]) attrs[newRDNType] = [];
        if (!attrs[newRDNType].includes(newRDNValue)) {
          attrs[newRDNType].push(newRDNValue);
        }
      }
      await ctx.store.set({ dn: newDNNorm, attrs });
    }
  }

  return { type: ProtocolOp.ModifyDNResponse, result: successResult() };
}

function parseRDN(rdn: string): [string, string] {
  const eq = rdn.indexOf("=");
  if (eq === -1) return ["", rdn];
  return [rdn.slice(0, eq).toLowerCase().trim(), rdn.slice(eq + 1).trim()];
}
