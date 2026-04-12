/**
 * Per-connection message loop for the LDAP server.
 *
 * Reads data from a TCP connection, accumulates it in a buffer,
 * parses complete LDAPMessages, dispatches to handlers, and sends responses.
 */

import type { Config } from "../config/default.ts";
import { encodeLdapMessage } from "./ldap/encoder.ts";
import { parseMessages } from "./ldap/parser.ts";
import { ProtocolOp, ResultCode } from "./ldap/constants.ts";
import type { LdapMessage } from "./ldap/messages.ts";
import { errorResult } from "./ldap/messages.ts";
import type { DirectoryStore } from "./store/types.ts";
import type { HandlerContext } from "./handlers/context.ts";
import { handleBind } from "./handlers/bind.ts";
import { handleSearch } from "./handlers/search.ts";
import { handleAdd } from "./handlers/add.ts";
import { handleModify } from "./handlers/modify.ts";
import { handleDelete } from "./handlers/delete.ts";
import { handleModifyDN } from "./handlers/modifydn.ts";

export async function handleConnection(
  conn: Deno.TcpConn,
  config: Config,
  store: DirectoryStore,
): Promise<void> {
  const ctx: HandlerContext = {
    config,
    store,
    boundDN: "",
    isAdmin: false,
  };

  const buf = new Uint8Array(65536);
  let accumulated = new Uint8Array(0);

  try {
    while (true) {
      let bytesRead: number;
      try {
        const result = await conn.read(buf);
        if (result === null) break; // Connection closed
        bytesRead = result;
      } catch {
        break;
      }

      // Append to accumulation buffer
      const newData = buf.slice(0, bytesRead);
      const merged = new Uint8Array(accumulated.length + newData.length);
      merged.set(accumulated);
      merged.set(newData, accumulated.length);
      accumulated = merged;

      // Parse and dispatch complete messages
      let parsed: ReturnType<typeof parseMessages>;
      try {
        parsed = parseMessages(accumulated);
      } catch (e) {
        console.error("Parse error:", e);
        break;
      }

      accumulated = accumulated.slice(parsed.bytesConsumed);

      for (const msg of parsed.messages) {
        const shouldClose = await dispatch(msg, ctx, conn);
        if (shouldClose) return;
      }
    }
  } finally {
    try {
      conn.close();
    } catch {
      // Already closed
    }
  }
}

/**
 * Dispatch a single LDAP message and send the response.
 * Returns true if the connection should be closed.
 */
async function dispatch(
  msg: LdapMessage,
  ctx: HandlerContext,
  conn: Deno.TcpConn,
): Promise<boolean> {
  const op = msg.protocolOp;

  try {
    switch (op.type) {
      case ProtocolOp.BindRequest: {
        const result = await handleBind(op, ctx);
        ctx.boundDN = result.boundDN;
        ctx.isAdmin = result.isAdmin;
        await send(conn, msg.messageId, result.response);
        break;
      }

      case ProtocolOp.UnbindRequest:
        // RFC 4511: server should close after receiving UnbindRequest
        return true;

      case ProtocolOp.SearchRequest: {
        const result = await handleSearch(op, ctx);
        for (const entry of result.entries) {
          await send(conn, msg.messageId, entry);
        }
        await send(conn, msg.messageId, result.done);
        break;
      }

      case ProtocolOp.AddRequest: {
        const response = await handleAdd(op, ctx);
        await send(conn, msg.messageId, response);
        break;
      }

      case ProtocolOp.ModifyRequest: {
        const response = await handleModify(op, ctx);
        await send(conn, msg.messageId, response);
        break;
      }

      case ProtocolOp.DelRequest: {
        const response = await handleDelete(op, ctx);
        await send(conn, msg.messageId, response);
        break;
      }

      case ProtocolOp.ModifyDNRequest: {
        const response = await handleModifyDN(op, ctx);
        await send(conn, msg.messageId, response);
        break;
      }

      case ProtocolOp.AbandonRequest:
        // Nothing to do — we process synchronously
        break;

      case ProtocolOp.ExtendedRequest: {
        // Minimal: respond with unsupported
        await send(conn, msg.messageId, {
          type: ProtocolOp.ExtendedResponse,
          result: errorResult(ResultCode.UnwillingToPerform, "Extended operation not supported"),
        });
        break;
      }

      default:
        console.warn(`Unhandled protocol op: ${(op as any).type}`);
    }
  } catch (e) {
    console.error("Handler error:", e);
  }

  return false;
}

async function send(
  conn: Deno.TcpConn,
  messageId: number,
  protocolOp: LdapMessage["protocolOp"],
): Promise<void> {
  const msg: LdapMessage = { messageId, protocolOp };
  const encoded = encodeLdapMessage(msg);
  await conn.write(encoded);
}
