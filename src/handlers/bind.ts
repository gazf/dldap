import { ResultCode } from "../ldap/constants.ts";
import { ProtocolOp } from "../ldap/constants.ts";
import type { BindRequest, BindResponse } from "../ldap/messages.ts";
import { errorResult, successResult } from "../ldap/messages.ts";
import { normalizeDN } from "../store/types.ts";
import type { HandlerContext } from "./context.ts";

export async function handleBind(
  req: BindRequest,
  ctx: HandlerContext,
): Promise<{ response: BindResponse; boundDN: string; isAdmin: boolean }> {
  // Version check
  if (req.version !== 3) {
    return {
      response: {
        type: ProtocolOp.BindResponse,
        result: errorResult(ResultCode.ProtocolError, "Only LDAP v3 supported"),
      },
      boundDN: "",
      isAdmin: false,
    };
  }

  // Anonymous bind
  if (req.dn === "" && req.password === "") {
    return {
      response: { type: ProtocolOp.BindResponse, result: successResult() },
      boundDN: "",
      isAdmin: false,
    };
  }

  const dn = normalizeDN(req.dn);

  // Admin bind
  if (dn === normalizeDN(ctx.config.adminDN)) {
    if (req.password === ctx.config.adminPassword) {
      return {
        response: { type: ProtocolOp.BindResponse, result: successResult() },
        boundDN: dn,
        isAdmin: true,
      };
    }
    return {
      response: {
        type: ProtocolOp.BindResponse,
        result: errorResult(ResultCode.InvalidCredentials, "Invalid credentials"),
      },
      boundDN: "",
      isAdmin: false,
    };
  }

  // Regular user bind — look up the entry and check userPassword
  const entry = await ctx.store.get(dn);
  if (!entry) {
    return {
      response: {
        type: ProtocolOp.BindResponse,
        result: errorResult(ResultCode.InvalidCredentials, "Invalid credentials"),
      },
      boundDN: "",
      isAdmin: false,
    };
  }

  const passwords = entry.attrs["userpassword"] ?? [];
  const match = passwords.some((p) => {
    // Support {CLEARTEXT} prefix and plain text
    if (p.startsWith("{CLEARTEXT}")) return p.slice(11) === req.password;
    return p === req.password;
  });

  if (!match) {
    return {
      response: {
        type: ProtocolOp.BindResponse,
        result: errorResult(ResultCode.InvalidCredentials, "Invalid credentials"),
      },
      boundDN: "",
      isAdmin: false,
    };
  }

  return {
    response: { type: ProtocolOp.BindResponse, result: successResult() },
    boundDN: dn,
    isAdmin: false,
  };
}
