/**
 * REST API の HTTP レベル integration テスト。
 *
 * 実際に Deno.serve でサーバーを起動し、fetch で叩く。
 * ポートは OS に自動割り当て（port: 0）させることで並列実行時の衝突を回避。
 */

import { assertEquals, assertExists } from "jsr:@std/assert";
import { KvStore } from "../src/store/kv.ts";
import { route, type RouterConfig } from "../src/api/router.ts";
import { withCors } from "../src/api/middleware.ts";
import { defaultConfig } from "../config/default.ts";

// ---------------------------------------------------------------------------
// テストサーバーのセットアップ
// ---------------------------------------------------------------------------

interface TestServer {
  baseUrl: string;
  store: KvStore;
  cleanup: () => Promise<void>;
}

interface ServerOptions {
  sambaEnabled?: boolean;
  sessionTTL?: number;
}

async function makeServer(opts: ServerOptions = {}): Promise<TestServer> {
  const tmpPath = await Deno.makeTempFile({ suffix: ".kv" });
  const store = await KvStore.open(tmpPath);
  const kv = store.rawKv();

  const sambaEnabled = opts.sambaEnabled ?? false;
  const config = {
    ...defaultConfig,
    adminPassword: "admin",
    samba: {
      ...defaultConfig.samba,
      enabled: sambaEnabled,
      autoHash: sambaEnabled,
      domainSID: "S-1-5-21-1-2-3",
    },
  };

  // ベース DN と標準 OU を事前作成
  await store.set({
    dn: "dc=example,dc=com",
    attrs: { objectclass: ["top", "domain"], dc: ["example"] },
  });
  await store.set({
    dn: "ou=users,dc=example,dc=com",
    attrs: { objectclass: ["top", "organizationalunit"], ou: ["users"] },
  });
  await store.set({
    dn: "ou=groups,dc=example,dc=com",
    attrs: { objectclass: ["top", "organizationalunit"], ou: ["groups"] },
  });

  const sessionTTL = opts.sessionTTL ?? 3600;
  const routerCfg: RouterConfig = { store, config, kv, sessionTTL, corsOrigin: "*" };

  const server = Deno.serve({ port: 0, hostname: "127.0.0.1" }, async (req) => {
    const res = await route(req, routerCfg);
    return withCors(res, "*");
  });

  const { port } = server.addr as Deno.NetAddr;
  const baseUrl = `http://127.0.0.1:${port}`;

  const cleanup = async () => {
    await server.shutdown();
    await store.close();
    await Deno.remove(tmpPath).catch(() => {});
  };

  return { baseUrl, store, cleanup };
}

// ---------------------------------------------------------------------------
// ヘルパー
// ---------------------------------------------------------------------------

/** トークンを取得してボディを消費する */
async function getToken(baseUrl: string, password = "admin"): Promise<string> {
  const res = await fetch(`${baseUrl}/api/auth`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  });
  const body = await res.json();
  return body.token as string;
}

function authHeaders(token: string): HeadersInit {
  return { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" };
}

/** ステータスのみ確認してボディを破棄する */
async function statusOf(res: Response): Promise<number> {
  await res.body?.cancel();
  return res.status;
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

Deno.test("POST /api/auth: 正しいパスワードでトークンが発行される", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const res = await fetch(`${baseUrl}/api/auth`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: "admin" }),
    });
    assertEquals(res.status, 200);
    const body = await res.json();
    assertExists(body.token);
  } finally {
    await cleanup();
  }
});

Deno.test("POST /api/auth: 誤ったパスワードは 401", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const res = await fetch(`${baseUrl}/api/auth`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: "wrong" }),
    });
    assertEquals(await statusOf(res), 401);
  } finally {
    await cleanup();
  }
});

Deno.test("DELETE /api/auth: ログアウトでトークンが無効化される", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);

    const del = await fetch(`${baseUrl}/api/auth`, {
      method: "DELETE",
      headers: authHeaders(token),
    });
    assertEquals(await statusOf(del), 204);

    // 無効化後は 401
    const res = await fetch(`${baseUrl}/api/status`, { headers: authHeaders(token) });
    assertEquals(await statusOf(res), 401);
  } finally {
    await cleanup();
  }
});

Deno.test("認証なしリクエストは 401", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const res = await fetch(`${baseUrl}/api/status`);
    assertEquals(await statusOf(res), 401);
  } finally {
    await cleanup();
  }
});

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

Deno.test("GET /api/status: サーバー状態が返る", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const res = await fetch(`${baseUrl}/api/status`, { headers: authHeaders(token) });
    assertEquals(res.status, 200);
    const body = await res.json();
    assertEquals(body.ok, true);
    assertEquals(body.baseDN, "dc=example,dc=com");
    assertExists(body.counts);
  } finally {
    await cleanup();
  }
});

// ---------------------------------------------------------------------------
// OUs
// ---------------------------------------------------------------------------

Deno.test("GET /api/ous: OU 一覧が返る", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const res = await fetch(`${baseUrl}/api/ous`, { headers: authHeaders(token) });
    assertEquals(res.status, 200);
    const body = await res.json();
    const ouNames = body.map((o: { ou: string }) => o.ou);
    assertEquals(ouNames.includes("users"), true);
    assertEquals(ouNames.includes("groups"), true);
  } finally {
    await cleanup();
  }
});

Deno.test("POST /api/ous: OU が作成できる", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const res = await fetch(`${baseUrl}/api/ous`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ ou: "engineering", description: "Engineering team" }),
    });
    assertEquals(res.status, 201);
    const body = await res.json();
    assertEquals(body.ou, "engineering");
    assertEquals(body.description, "Engineering team");
  } finally {
    await cleanup();
  }
});

Deno.test("POST /api/ous: 重複 OU は 409", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const first = await fetch(`${baseUrl}/api/ous`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ ou: "engineering" }),
    });
    await first.body?.cancel();

    const res = await fetch(`${baseUrl}/api/ous`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ ou: "engineering" }),
    });
    assertEquals(await statusOf(res), 409);
  } finally {
    await cleanup();
  }
});

Deno.test("DELETE /api/ous/:ou: 空の OU は削除できる", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const created = await fetch(`${baseUrl}/api/ous`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ ou: "temp" }),
    });
    await created.body?.cancel();

    const res = await fetch(`${baseUrl}/api/ous/temp`, {
      method: "DELETE",
      headers: authHeaders(token),
    });
    assertEquals(await statusOf(res), 204);
  } finally {
    await cleanup();
  }
});

Deno.test("DELETE /api/ous/:ou: 子エントリがある OU は削除できない", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    // users OU にユーザーを追加
    const created = await fetch(`${baseUrl}/api/users`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ uid: "frank", cn: "Frank", password: "pass" }),
    });
    await created.body?.cancel();

    const res = await fetch(`${baseUrl}/api/ous/users`, {
      method: "DELETE",
      headers: authHeaders(token),
    });
    assertEquals(await statusOf(res), 400);
  } finally {
    await cleanup();
  }
});

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

Deno.test("POST /api/users: ユーザーが作成できる", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const res = await fetch(`${baseUrl}/api/users`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ uid: "alice", cn: "Alice Smith", password: "secret" }),
    });
    assertEquals(res.status, 201);
    const body = await res.json();
    assertEquals(body.uid, "alice");
    assertEquals(body.cn, "Alice Smith");
  } finally {
    await cleanup();
  }
});

Deno.test("POST /api/users: uid がない場合は 400", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const res = await fetch(`${baseUrl}/api/users`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ cn: "Alice", password: "secret" }),
    });
    assertEquals(await statusOf(res), 400);
  } finally {
    await cleanup();
  }
});

Deno.test("POST /api/users: 重複 uid は 409", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const payload = JSON.stringify({ uid: "alice", cn: "Alice", password: "secret" });

    const first = await fetch(`${baseUrl}/api/users`, {
      method: "POST",
      headers: authHeaders(token),
      body: payload,
    });
    await first.body?.cancel();

    const res = await fetch(`${baseUrl}/api/users`, {
      method: "POST",
      headers: authHeaders(token),
      body: payload,
    });
    assertEquals(await statusOf(res), 409);
  } finally {
    await cleanup();
  }
});

Deno.test("GET /api/users/:uid: ユーザーが取得できる", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const created = await fetch(`${baseUrl}/api/users`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ uid: "bob", cn: "Bob", password: "pass" }),
    });
    await created.body?.cancel();

    const res = await fetch(`${baseUrl}/api/users/bob`, { headers: authHeaders(token) });
    assertEquals(res.status, 200);
    const body = await res.json();
    assertEquals(body.uid, "bob");
  } finally {
    await cleanup();
  }
});

Deno.test("GET /api/users/:uid: 存在しないユーザーは 404", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const res = await fetch(`${baseUrl}/api/users/nobody`, { headers: authHeaders(token) });
    assertEquals(await statusOf(res), 404);
  } finally {
    await cleanup();
  }
});

Deno.test("PUT /api/users/:uid: ユーザー属性を更新できる", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const created = await fetch(`${baseUrl}/api/users`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ uid: "carol", cn: "Carol", password: "pass" }),
    });
    await created.body?.cancel();

    const res = await fetch(`${baseUrl}/api/users/carol`, {
      method: "PUT",
      headers: authHeaders(token),
      body: JSON.stringify({ cn: "Carol Updated", mail: "carol@example.com" }),
    });
    assertEquals(res.status, 200);
    const body = await res.json();
    assertEquals(body.cn, "Carol Updated");
    assertEquals(body.mail, "carol@example.com");
  } finally {
    await cleanup();
  }
});

Deno.test("PUT /api/users/:uid/password: パスワードを変更できる", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const created = await fetch(`${baseUrl}/api/users`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ uid: "dave", cn: "Dave", password: "old" }),
    });
    await created.body?.cancel();

    const res = await fetch(`${baseUrl}/api/users/dave/password`, {
      method: "PUT",
      headers: authHeaders(token),
      body: JSON.stringify({ password: "newpass" }),
    });
    assertEquals(await statusOf(res), 204);
  } finally {
    await cleanup();
  }
});

Deno.test("DELETE /api/users/:uid: ユーザーを削除できる", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const created = await fetch(`${baseUrl}/api/users`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ uid: "eve", cn: "Eve", password: "pass" }),
    });
    await created.body?.cancel();

    const del = await fetch(`${baseUrl}/api/users/eve`, {
      method: "DELETE",
      headers: authHeaders(token),
    });
    assertEquals(await statusOf(del), 204);

    const res = await fetch(`${baseUrl}/api/users/eve`, { headers: authHeaders(token) });
    assertEquals(await statusOf(res), 404);
  } finally {
    await cleanup();
  }
});

Deno.test("GET /api/users: ユーザー一覧が返る", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const c1 = await fetch(`${baseUrl}/api/users`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ uid: "user1", cn: "User One", password: "pass" }),
    });
    await c1.body?.cancel();
    const c2 = await fetch(`${baseUrl}/api/users`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ uid: "user2", cn: "User Two", password: "pass" }),
    });
    await c2.body?.cancel();

    const res = await fetch(`${baseUrl}/api/users`, { headers: authHeaders(token) });
    assertEquals(res.status, 200);
    const body = await res.json();
    assertEquals(body.length, 2);
  } finally {
    await cleanup();
  }
});

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

Deno.test("POST /api/groups: グループが作成できる", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const res = await fetch(`${baseUrl}/api/groups`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ cn: "staff", gidNumber: "2000" }),
    });
    assertEquals(res.status, 201);
    const body = await res.json();
    assertEquals(body.cn, "staff");
    assertEquals(body.gidNumber, 2000);  // DTO は number 型
  } finally {
    await cleanup();
  }
});

Deno.test("POST /api/groups: 重複 cn は 409", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const first = await fetch(`${baseUrl}/api/groups`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ cn: "staff" }),
    });
    await first.body?.cancel();

    const res = await fetch(`${baseUrl}/api/groups`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ cn: "staff" }),
    });
    assertEquals(await statusOf(res), 409);
  } finally {
    await cleanup();
  }
});

Deno.test("POST /api/groups/:cn/members: メンバーを追加できる", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const created = await fetch(`${baseUrl}/api/groups`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ cn: "devs" }),
    });
    await created.body?.cancel();

    const res = await fetch(`${baseUrl}/api/groups/devs/members`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ uid: "alice" }),
    });
    assertEquals(res.status, 200);
    const body = await res.json();
    assertEquals(body.members.includes("alice"), true);
  } finally {
    await cleanup();
  }
});

Deno.test("DELETE /api/groups/:cn/members/:uid: メンバーを削除できる", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const created = await fetch(`${baseUrl}/api/groups`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ cn: "devs" }),
    });
    await created.body?.cancel();

    const added = await fetch(`${baseUrl}/api/groups/devs/members`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ uid: "alice" }),
    });
    await added.body?.cancel();

    const res = await fetch(`${baseUrl}/api/groups/devs/members/alice`, {
      method: "DELETE",
      headers: authHeaders(token),
    });
    assertEquals(res.status, 200);
    const body = await res.json();
    assertEquals(body.members.includes("alice"), false);
  } finally {
    await cleanup();
  }
});

Deno.test("DELETE /api/groups/:cn: グループを削除できる", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const created = await fetch(`${baseUrl}/api/groups`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ cn: "temp" }),
    });
    await created.body?.cancel();

    const del = await fetch(`${baseUrl}/api/groups/temp`, {
      method: "DELETE",
      headers: authHeaders(token),
    });
    assertEquals(await statusOf(del), 204);

    const res = await fetch(`${baseUrl}/api/groups/temp`, { headers: authHeaders(token) });
    assertEquals(await statusOf(res), 404);
  } finally {
    await cleanup();
  }
});

Deno.test("PUT /api/groups/:cn: グループ属性を更新できる", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const created = await fetch(`${baseUrl}/api/groups`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ cn: "ops", gidNumber: "3000" }),
    });
    await created.body?.cancel();

    const res = await fetch(`${baseUrl}/api/groups/ops`, {
      method: "PUT",
      headers: authHeaders(token),
      body: JSON.stringify({ gidNumber: "3001", description: "Operations" }),
    });
    assertEquals(res.status, 200);
    const body = await res.json();
    assertEquals(body.gidNumber, 3001);
    assertEquals(body.description, "Operations");
  } finally {
    await cleanup();
  }
});

// ---------------------------------------------------------------------------
// Groups — 追加カバレッジ
// ---------------------------------------------------------------------------

Deno.test("GET /api/groups: グループ一覧が返る", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const c1 = await fetch(`${baseUrl}/api/groups`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ cn: "alpha" }),
    });
    await c1.body?.cancel();
    const c2 = await fetch(`${baseUrl}/api/groups`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ cn: "beta" }),
    });
    await c2.body?.cancel();

    const res = await fetch(`${baseUrl}/api/groups`, { headers: authHeaders(token) });
    assertEquals(res.status, 200);
    const body = await res.json();
    assertEquals(body.length, 2);
  } finally {
    await cleanup();
  }
});

Deno.test("GET /api/groups/:cn: グループが取得できる", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const created = await fetch(`${baseUrl}/api/groups`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ cn: "admins", gidNumber: "100" }),
    });
    await created.body?.cancel();

    const res = await fetch(`${baseUrl}/api/groups/admins`, { headers: authHeaders(token) });
    assertEquals(res.status, 200);
    const body = await res.json();
    assertEquals(body.cn, "admins");
    assertEquals(body.gidNumber, 100);
  } finally {
    await cleanup();
  }
});

Deno.test("GET /api/groups/:cn: 存在しないグループは 404", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const res = await fetch(`${baseUrl}/api/groups/nobody`, { headers: authHeaders(token) });
    assertEquals(await statusOf(res), 404);
  } finally {
    await cleanup();
  }
});

// ---------------------------------------------------------------------------
// Users — バリデーション
// ---------------------------------------------------------------------------

Deno.test("POST /api/users: cn がない場合は 400", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const res = await fetch(`${baseUrl}/api/users`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ uid: "noname", password: "pass" }),
    });
    assertEquals(await statusOf(res), 400);
  } finally {
    await cleanup();
  }
});

Deno.test("POST /api/users: password がない場合は 400", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const res = await fetch(`${baseUrl}/api/users`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ uid: "nopass", cn: "No Pass" }),
    });
    assertEquals(await statusOf(res), 400);
  } finally {
    await cleanup();
  }
});

// ---------------------------------------------------------------------------
// Samba 属性の自動生成
// ---------------------------------------------------------------------------

Deno.test("POST /api/users: Samba 有効時に sambaSID と sambaNTPassword が生成される", async () => {
  const { baseUrl, store, cleanup } = await makeServer({ sambaEnabled: true });
  try {
    const token = await getToken(baseUrl);
    const res = await fetch(`${baseUrl}/api/users`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ uid: "sambauser", cn: "Samba User", password: "testpass" }),
    });
    assertEquals(res.status, 201);
    await res.body?.cancel();

    // KV から直接確認
    const entry = await store.get("uid=sambauser,ou=users,dc=example,dc=com");
    assertExists(entry);
    assertExists(entry.attrs["sambasid"]);
    assertExists(entry.attrs["sambantpassword"]);
    assertExists(entry.attrs["sambaacctflags"]);
  } finally {
    await cleanup();
  }
});

// ---------------------------------------------------------------------------
// パスワード変更の反映確認
// ---------------------------------------------------------------------------

Deno.test("PUT /api/users/:uid/password: 変更後のパスワードが KV に格納される", async () => {
  const { baseUrl, store, cleanup } = await makeServer();
  try {
    const token = await getToken(baseUrl);
    const created = await fetch(`${baseUrl}/api/users`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ uid: "pwtest", cn: "PW Test", password: "oldpass" }),
    });
    await created.body?.cancel();

    const changed = await fetch(`${baseUrl}/api/users/pwtest/password`, {
      method: "PUT",
      headers: authHeaders(token),
      body: JSON.stringify({ password: "newpass" }),
    });
    assertEquals(await statusOf(changed), 204);

    const entry = await store.get("uid=pwtest,ou=users,dc=example,dc=com");
    assertExists(entry);
    assertEquals(entry.attrs["userpassword"]?.[0], "newpass");
  } finally {
    await cleanup();
  }
});

// ---------------------------------------------------------------------------
// セッション TTL 切れ
// ---------------------------------------------------------------------------

Deno.test("セッション TTL 切れのトークンは 401", async () => {
  const { baseUrl, cleanup } = await makeServer({ sessionTTL: 1 });
  try {
    const token = await getToken(baseUrl);

    // TTL=1秒なので 1.1 秒待機
    await new Promise((resolve) => setTimeout(resolve, 1100));

    const res = await fetch(`${baseUrl}/api/status`, { headers: authHeaders(token) });
    assertEquals(await statusOf(res), 401);
  } finally {
    await cleanup();
  }
});

// ---------------------------------------------------------------------------
// Auth — バリデーション
// ---------------------------------------------------------------------------

Deno.test("POST /api/auth: password フィールドがない場合は 400", async () => {
  const { baseUrl, cleanup } = await makeServer();
  try {
    const res = await fetch(`${baseUrl}/api/auth`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assertEquals(await statusOf(res), 400);
  } finally {
    await cleanup();
  }
});
