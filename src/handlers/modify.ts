import { ModifyOp, ResultCode } from "../ldap/constants.ts";
import { ProtocolOp } from "../ldap/constants.ts";
import type { ModifyRequest, ModifyResponse } from "../ldap/messages.ts";
import { errorResult, successResult } from "../ldap/messages.ts";
import { normalizeDN } from "../store/types.ts";
import type { HandlerContext } from "./context.ts";
import { onPasswordChange } from "./samba_hooks.ts";

export async function handleModify(
  req: ModifyRequest,
  ctx: HandlerContext,
): Promise<ModifyResponse> {
  if (!ctx.isAdmin) {
    return {
      type: ProtocolOp.ModifyResponse,
      result: errorResult(ResultCode.InsufficientAccessRights, "Write access requires authentication"),
    };
  }

  const dn = normalizeDN(req.object);
  const entry = await ctx.store.get(dn);

  if (!entry) {
    return {
      type: ProtocolOp.ModifyResponse,
      result: errorResult(ResultCode.NoSuchObject, `No such object: ${dn}`, dn),
    };
  }

  const attrs = { ...entry.attrs };
  for (const [k, v] of Object.entries(attrs)) {
    attrs[k] = [...v];
  }

  for (const change of req.changes) {
    const attrType = change.modification.type.toLowerCase();
    const newValues = change.modification.values;

    switch (change.operation) {
      case ModifyOp.Add: {
        if (!attrs[attrType]) {
          attrs[attrType] = [...newValues];
        } else {
          for (const v of newValues) {
            if (!attrs[attrType].includes(v)) {
              attrs[attrType].push(v);
            }
          }
        }
        break;
      }
      case ModifyOp.Delete: {
        if (newValues.length === 0) {
          // Delete the entire attribute
          delete attrs[attrType];
        } else {
          if (attrs[attrType]) {
            attrs[attrType] = attrs[attrType].filter((v) => !newValues.includes(v));
            if (attrs[attrType].length === 0) delete attrs[attrType];
          }
        }
        break;
      }
      case ModifyOp.Replace: {
        if (newValues.length === 0) {
          delete attrs[attrType];
        } else {
          attrs[attrType] = [...newValues];
        }
        break;
      }
    }

    // Samba: auto-update NT/LM hash when userPassword changes
    if (attrType === "userpassword" && attrs["userpassword"]) {
      const newPwd = attrs["userpassword"][0];
      const sambaUpdates = onPasswordChange(newPwd, attrs, ctx.config.samba);
      for (const [k, v] of Object.entries(sambaUpdates)) {
        attrs[k] = v;
      }
    }
  }

  await ctx.store.set({ dn, attrs });
  return { type: ProtocolOp.ModifyResponse, result: successResult() };
}
