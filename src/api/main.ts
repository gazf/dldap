/**
 * dldaps REST API サーバー エントリーポイント。
 *
 * 環境変数:
 *   API_PORT                 ポート番号 (default: 8080)
 *   API_HOST                 バインドアドレス (default: 0.0.0.0)
 *   API_CORS_ORIGIN          CORS 許可オリジン (default: *)
 *   API_SESSION_TTL_SECONDS  セッション有効期限秒 (default: 3600)
 *   LDAP_KV_PATH             Deno KV ファイルパス
 *   LDAP_BASE_DN
 *   LDAP_ADMIN_DN
 *   LDAP_ADMIN_PW
 *   SAMBA_ENABLED
 *   SAMBA_DOMAIN
 *   SAMBA_DOMAIN_SID
 *   SAMBA_AUTO_HASH
 *   SAMBA_LM_HASH
 */

import { defaultConfig, type Config } from "../../config/default.ts";
import { KvStore } from "../store/kv.ts";
import { generateDomainSID } from "../samba/sid.ts";
import { route, type RouterConfig } from "./router.ts";
import { withCors } from "./middleware.ts";

function loadConfig(): Config {
  const cfg = structuredClone(defaultConfig);

  if (Deno.env.get("LDAP_BASE_DN")) cfg.baseDN = Deno.env.get("LDAP_BASE_DN")!;
  if (Deno.env.get("LDAP_ADMIN_DN")) cfg.adminDN = Deno.env.get("LDAP_ADMIN_DN")!;

  const adminPw = Deno.env.get("LDAP_ADMIN_PW");
  if (!adminPw) throw new Error("LDAP_ADMIN_PW environment variable is required");
  cfg.adminPassword = adminPw;
  if (Deno.env.get("LDAP_KV_PATH")) cfg.kvPath = Deno.env.get("LDAP_KV_PATH")!;

  const sambaEnabled = Deno.env.get("SAMBA_ENABLED");
  if (sambaEnabled !== undefined) cfg.samba.enabled = sambaEnabled !== "false";

  if (Deno.env.get("SAMBA_DOMAIN")) cfg.samba.domain = Deno.env.get("SAMBA_DOMAIN")!;

  const domainSID = Deno.env.get("SAMBA_DOMAIN_SID");
  if (domainSID) {
    cfg.samba.domainSID = domainSID;
  } else if (cfg.samba.domainSID === defaultConfig.samba.domainSID) {
    cfg.samba.domainSID = generateDomainSID();
  }

  const autoHash = Deno.env.get("SAMBA_AUTO_HASH");
  if (autoHash !== undefined) cfg.samba.autoHash = autoHash === "true";

  const lmHash = Deno.env.get("SAMBA_LM_HASH");
  if (lmHash !== undefined) cfg.samba.lmHashEnabled = lmHash === "true";

  return cfg;
}

async function main(): Promise<void> {
  const config = loadConfig();
  const port = parseInt(Deno.env.get("API_PORT") ?? "8080", 10);
  const host = Deno.env.get("API_HOST") ?? "0.0.0.0";
  const corsOrigin = Deno.env.get("API_CORS_ORIGIN") ?? "*";
  const sessionTTL = parseInt(Deno.env.get("API_SESSION_TTL_SECONDS") ?? "3600", 10);

  const store = await KvStore.open(config.kvPath);
  const kv = store.rawKv();

  const routerCfg: RouterConfig = { store, config, kv, sessionTTL, corsOrigin };

  const server = Deno.serve({ port, hostname: host }, async (req) => {
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

  console.log(`dldaps API listening on ${host}:${port}`);
  console.log(`Base DN: ${config.baseDN}`);

  const shutdown = () => {
    console.log("\nShutting down API...");
    server.shutdown().then(() => store.close()).then(() => Deno.exit(0));
  };

  Deno.addSignalListener("SIGINT", shutdown);
  try {
    Deno.addSignalListener("SIGTERM", shutdown);
  } catch {
    // Windows では SIGTERM 未対応
  }

  await server.finished;
}

main().catch((e) => {
  console.error("Fatal:", e);
  Deno.exit(1);
});
