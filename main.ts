/**
 * dldaps — Deno LDAP server with Samba support.
 *
 * Usage:
 *   deno run --allow-net --allow-read --allow-write --unstable-kv main.ts [options]
 *
 * Options (environment variables):
 *   LDAP_PORT          Port to listen on (default: 389)
 *   LDAP_HOST          Host to bind (default: 0.0.0.0)
 *   LDAP_BASE_DN       Base DN (default: dc=example,dc=com)
 *   LDAP_ADMIN_DN      Admin DN (default: cn=admin,dc=example,dc=com)
 *   LDAP_ADMIN_PW      Admin password (required)
 *   LDAP_KV_PATH       Deno KV file path (default: ./dldaps.kv)
 *   SAMBA_ENABLED      Enable Samba support (default: true)
 *   SAMBA_DOMAIN       NetBIOS domain name (default: WORKGROUP)
 *   SAMBA_AUTO_HASH    Auto-generate NT hash on password change (default: true)
 *   SAMBA_LM_HASH      Enable LM hash generation (default: false)
 */

import { defaultConfig, type Config } from "./config/default.ts";
import { KvStore } from "./src/store/kv.ts";
import { createServer } from "./src/server.ts";
import { ensureDomainSID } from "./src/samba/sid.ts";

function loadConfig(): Config {
  const cfg = structuredClone(defaultConfig);

  if (Deno.env.get("LDAP_PORT")) cfg.port = parseInt(Deno.env.get("LDAP_PORT")!, 10);
  if (Deno.env.get("LDAP_HOST")) cfg.host = Deno.env.get("LDAP_HOST")!;
  if (Deno.env.get("LDAP_BASE_DN")) cfg.baseDN = Deno.env.get("LDAP_BASE_DN")!;
  if (Deno.env.get("LDAP_ADMIN_DN")) cfg.adminDN = Deno.env.get("LDAP_ADMIN_DN")!;

  const adminPw = Deno.env.get("LDAP_ADMIN_PW");
  if (!adminPw) throw new Error("LDAP_ADMIN_PW environment variable is required");
  cfg.adminPassword = adminPw;
  if (Deno.env.get("LDAP_KV_PATH")) cfg.kvPath = Deno.env.get("LDAP_KV_PATH")!;

  const sambaEnabled = Deno.env.get("SAMBA_ENABLED");
  if (sambaEnabled !== undefined) cfg.samba.enabled = sambaEnabled !== "false";

  if (Deno.env.get("SAMBA_DOMAIN")) cfg.samba.domain = Deno.env.get("SAMBA_DOMAIN")!;

  const autoHash = Deno.env.get("SAMBA_AUTO_HASH");
  if (autoHash !== undefined) cfg.samba.autoHash = autoHash === "true";

  const lmHash = Deno.env.get("SAMBA_LM_HASH");
  if (lmHash !== undefined) cfg.samba.lmHashEnabled = lmHash === "true";

  return cfg;
}

async function ensureBaseDN(store: KvStore, config: Config): Promise<void> {
  const existing = await store.get(config.baseDN.toLowerCase());
  if (existing) return;

  // Parse dc=example,dc=com → { dc: ["example"] }
  const parts = config.baseDN.split(",").map((s) => s.trim());
  const attrs: Record<string, string[]> = { objectclass: ["top", "domain"] };

  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq !== -1) {
      const type = part.slice(0, eq).toLowerCase();
      const value = part.slice(eq + 1);
      if (!attrs[type]) attrs[type] = [];
      attrs[type].push(value);
    }
  }

  await store.set({ dn: config.baseDN.toLowerCase(), attrs });
  console.log(`Created base DN: ${config.baseDN}`);
}

async function main(): Promise<void> {
  const config = loadConfig();

  const store = await KvStore.open(config.kvPath);
  config.samba.domainSID = await ensureDomainSID(store.rawKv());
  await ensureBaseDN(store, config);

  const server = createServer(config, store);

  // Graceful shutdown on SIGINT/SIGTERM
  const shutdown = () => {
    console.log("\nShutting down...");
    server.close();
    store.close().then(() => Deno.exit(0));
  };

  Deno.addSignalListener("SIGINT", shutdown);
  try {
    Deno.addSignalListener("SIGTERM", shutdown);
  } catch {
    // SIGTERM may not be available on all platforms
  }

  await server.serve();
}

main().catch((e) => {
  console.error("Fatal:", e);
  Deno.exit(1);
});
