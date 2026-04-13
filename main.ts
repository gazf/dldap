/**
 * dldaps — Deno LDAP server with Samba support + REST API.
 *
 * Usage:
 *   deno run --allow-net --allow-read --allow-write --unstable-kv main.ts [options]
 *
 * LDAP options (environment variables):
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
 *
 * API options (environment variables):
 *   API_PORT                 Port to listen on (default: 8080)
 *   API_HOST                 Host to bind (default: 0.0.0.0)
 *   CORS_ORIGIN              CORS allowed origin (default: *)
 *   API_SESSION_TTL_SECONDS  Session TTL in seconds (default: 3600)
 */

import { defaultConfig, type Config } from "./config/default.ts";
import { KvStore } from "./src/store/kv.ts";
import { createServer } from "./src/server.ts";
import { ensureDomainSID } from "./src/samba/sid.ts";
import { route, type RouterConfig } from "./src/api/router.ts";
import { withCors } from "./src/api/middleware.ts";
import { onGroupAdd } from "./src/handlers/samba_hooks.ts";

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

  if (Deno.env.get("POSIX_UID_START")) cfg.posix.uidStart = parseInt(Deno.env.get("POSIX_UID_START")!, 10);
  if (Deno.env.get("POSIX_GID_START")) cfg.posix.gidStart = parseInt(Deno.env.get("POSIX_GID_START")!, 10);
  if (Deno.env.get("POSIX_HOME_BASE")) cfg.posix.homeBase = Deno.env.get("POSIX_HOME_BASE")!;
  if (Deno.env.get("POSIX_DEFAULT_SHELL")) cfg.posix.defaultShell = Deno.env.get("POSIX_DEFAULT_SHELL")!;

  return cfg;
}

async function ensureSambaGroups(store: KvStore, config: Config): Promise<void> {
  if (!config.samba.enabled) return;

  const iter = store.rawKv().list<{ dn: string; attrs: Record<string, string[]> }>({ prefix: ["entry"] });
  let count = 0;
  for await (const item of iter) {
    const entry = item.value;
    if (!entry?.attrs) continue;

    const ocs = entry.attrs["objectclass"] ?? [];
    if (!ocs.some((oc) => oc.toLowerCase() === "posixgroup")) continue;
    if (ocs.some((oc) => oc.toLowerCase() === "sambagroupmapping")) continue;

    const attrs = { ...entry.attrs };
    onGroupAdd(attrs, config.samba);
    await store.set({ dn: entry.dn, attrs });
    count++;
  }

  if (count > 0) {
    console.log(`sambaGroupMapping: added to ${count} existing group(s)`);
  }
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

  // API 固有の設定
  const apiPort = parseInt(Deno.env.get("API_PORT") ?? "8080", 10);
  const apiHost = Deno.env.get("API_HOST") ?? "0.0.0.0";
  const corsOrigin = Deno.env.get("CORS_ORIGIN") ?? "*";
  const sessionTTL = parseInt(Deno.env.get("API_SESSION_TTL_SECONDS") ?? "3600", 10);

  // 共有 KvStore・初期化（1 回のみ）
  const store = await KvStore.open(config.kvPath);
  const kv = store.rawKv();
  config.samba.domainSID = await ensureDomainSID(kv);
  await ensureBaseDN(store, config);
  await store.syncPosixCounters(config.posix.uidStart, config.posix.gidStart);
  await ensureSambaGroups(store, config);

  // LDAP サーバー
  const ldapServer = createServer(config, store);

  // API サーバー
  const routerCfg: RouterConfig = { store, config, kv, sessionTTL, corsOrigin };
  const apiServer = Deno.serve({ port: apiPort, hostname: apiHost }, async (req) => {
    try {
      const res = await route(req, routerCfg);
      return withCors(res, corsOrigin);
    } catch (e) {
      console.error("Unhandled error:", e);
      return withCors(
        new Response(JSON.stringify({ error: "Internal server error" }), {
          status: 500,
          headers: { "Content-Type": "application/json" },
        }),
        corsOrigin,
      );
    }
  });

  console.log(`dldaps API listening on ${apiHost}:${apiPort}`);
  console.log(`Base DN: ${config.baseDN}`);

  // Graceful shutdown
  const shutdown = () => {
    console.log("\nShutting down...");
    ldapServer.close();
    apiServer.shutdown().then(() => store.close()).then(() => Deno.exit(0));
  };

  Deno.addSignalListener("SIGINT", shutdown);
  try {
    Deno.addSignalListener("SIGTERM", shutdown);
  } catch {
    // SIGTERM may not be available on all platforms
  }

  // LDAP と API を同時起動
  await Promise.all([ldapServer.serve(), apiServer.finished]);
}

main().catch((e) => {
  console.error("Fatal:", e);
  Deno.exit(1);
});
