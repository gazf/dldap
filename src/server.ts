/**
 * LDAP TCP server.
 */

import type { Config } from "../config/default.ts";
import type { DirectoryStore } from "./store/types.ts";
import { handleConnection } from "./connection.ts";

export interface Server {
  /** Start listening and accepting connections. Resolves when the server is closed. */
  serve(): Promise<void>;
  /** Gracefully close the server. */
  close(): void;
}

export function createServer(config: Config, store: DirectoryStore): Server {
  let listener: Deno.Listener | null = null;
  let closed = false;

  return {
    async serve() {
      listener = Deno.listen({
        hostname: config.host,
        port: config.port,
        transport: "tcp",
      });

      console.log(`dldaps listening on ${config.host}:${config.port}`);
      console.log(`Base DN: ${config.baseDN}`);
      console.log(`Samba support: ${config.samba.enabled ? "enabled" : "disabled"}`);

      for await (const conn of listener) {
        // Handle each connection concurrently
        handleConnection(conn as Deno.TcpConn, config, store).catch((e) => {
          console.error("Connection error:", e);
        });
      }
    },

    close() {
      if (!closed) {
        closed = true;
        listener?.close();
      }
    },
  };
}
