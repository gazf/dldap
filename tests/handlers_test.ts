/**
 * LDAP ハンドラーのテスト。
 *
 * Focus: ハンドラーが「何をすべきか」を検証する。
 * - Bind: 認証の正当性（正しいパスワード/誤ったパスワード/匿名）
 * - Search: スコープ別の結果（base/one/sub）
 * - Add: 重複エントリの拒否、Samba 属性の自動生成
 * - Modify: 属性の追加/削除/置換、パスワード変更時の NT ハッシュ更新
 * - Delete: リーフでないエントリの削除拒否
 * - ModifyDN: エントリの移動
 */

import { assertEquals, assertExists } from "@std/assert";
import { KvStore } from "../src/store/kv.ts";
import type { HandlerContext } from "../src/handlers/context.ts";
import { handleBind } from "../src/handlers/bind.ts";
import { handleSearch } from "../src/handlers/search.ts";
import { handleAdd } from "../src/handlers/add.ts";
import { handleModify } from "../src/handlers/modify.ts";
import { handleDelete } from "../src/handlers/delete.ts";
import { handleModifyDN } from "../src/handlers/modifydn.ts";
import { FilterTag, ProtocolOp, ResultCode, SearchScope } from "../src/ldap/constants.ts";
import { defaultConfig } from "../config/default.ts";
import { ModifyOp } from "../src/ldap/constants.ts";

// テスト用コンテキストのファクトリ
async function makeCtx(
  isAdmin = true,
): Promise<{ ctx: HandlerContext; store: KvStore; cleanup: () => Promise<void> }> {
  const tmpPath = await Deno.makeTempFile({ suffix: ".kv" });
  const store = await KvStore.open(tmpPath);

  // ベース DN と OU を事前に作成
  await store.set({
    dn: "dc=example,dc=com",
    attrs: { objectclass: ["top", "domain"], dc: ["example"] },
  });
  await store.set({
    dn: "ou=users,dc=example,dc=com",
    attrs: { objectclass: ["organizationalUnit"], ou: ["users"] },
  });

  const ctx: HandlerContext = {
    config: {
      ...defaultConfig,
      adminPassword: "admin",
      samba: { ...defaultConfig.samba, enabled: true, autoHash: true, lmHashEnabled: false },
    },
    store,
    boundDN: isAdmin ? "cn=admin,dc=example,dc=com" : "",
    isAdmin,
  };

  const cleanup = async () => {
    await store.close();
    await Deno.remove(tmpPath).catch(() => {});
  };

  return { ctx, store, cleanup };
}

// --- Bind ---

Deno.test("Bind: 匿名バインドは常に成功する", async () => {
  const { ctx, store: _store, cleanup } = await makeCtx(false);
  try {
    const result = await handleBind(
      { type: ProtocolOp.BindRequest, version: 3, dn: "", password: "" },
      ctx,
    );
    assertEquals(result.response.result.resultCode, ResultCode.Success);
    assertEquals(result.boundDN, "");
    assertEquals(result.isAdmin, false);
  } finally {
    await cleanup();
  }
});

Deno.test("Bind: 管理者DNと正しいパスワードで成功", async () => {
  const { ctx, store: _store, cleanup } = await makeCtx(false);
  try {
    const result = await handleBind(
      {
        type: ProtocolOp.BindRequest,
        version: 3,
        dn: "cn=admin,dc=example,dc=com",
        password: "admin",
      },
      ctx,
    );
    assertEquals(result.response.result.resultCode, ResultCode.Success);
    assertEquals(result.isAdmin, true);
  } finally {
    await cleanup();
  }
});

Deno.test("Bind: 管理者DNと誤ったパスワードは失敗", async () => {
  const { ctx, store: _store, cleanup } = await makeCtx(false);
  try {
    const result = await handleBind(
      {
        type: ProtocolOp.BindRequest,
        version: 3,
        dn: "cn=admin,dc=example,dc=com",
        password: "wrong",
      },
      ctx,
    );
    assertEquals(result.response.result.resultCode, ResultCode.InvalidCredentials);
    assertEquals(result.isAdmin, false);
  } finally {
    await cleanup();
  }
});

Deno.test("Bind: 一般ユーザーのパスワード認証", async () => {
  const { ctx, store, cleanup } = await makeCtx(true);
  try {
    await store.set({
      dn: "uid=alice,dc=example,dc=com",
      attrs: { uid: ["alice"], userpassword: ["alicepass"] },
    });

    const guestCtx: HandlerContext = { ...ctx, boundDN: "", isAdmin: false };
    const result = await handleBind(
      {
        type: ProtocolOp.BindRequest,
        version: 3,
        dn: "uid=alice,dc=example,dc=com",
        password: "alicepass",
      },
      guestCtx,
    );
    assertEquals(result.response.result.resultCode, ResultCode.Success);
  } finally {
    await cleanup();
  }
});

Deno.test("Bind: LDAPv3 以外のバージョンはプロトコルエラー", async () => {
  const { ctx, store: _store, cleanup } = await makeCtx(false);
  try {
    const result = await handleBind(
      { type: ProtocolOp.BindRequest, version: 2, dn: "", password: "" },
      ctx,
    );
    assertEquals(result.response.result.resultCode, ResultCode.ProtocolError);
  } finally {
    await cleanup();
  }
});

// --- Search ---

Deno.test("Search BaseObject: ベース DN のエントリ自身のみ返す", async () => {
  const { ctx, store: _store, cleanup } = await makeCtx();
  try {
    const result = await handleSearch(
      {
        type: ProtocolOp.SearchRequest,
        baseObject: "dc=example,dc=com",
        scope: SearchScope.BaseObject,
        derefAliases: 0,
        sizeLimit: 0,
        timeLimit: 0,
        typesOnly: false,
        filter: { type: FilterTag.Present, attribute: "objectClass" },
        attributes: [],
      },
      ctx,
    );
    assertEquals(result.entries.length, 1);
    assertEquals(result.entries[0].objectName, "dc=example,dc=com");
  } finally {
    await cleanup();
  }
});

Deno.test("Search SingleLevel: 直接の子のみ返す（孫は含まない）", async () => {
  const { ctx, store, cleanup } = await makeCtx();
  try {
    await store.set({
      dn: "uid=john,ou=users,dc=example,dc=com",
      attrs: { objectclass: ["posixAccount"], uid: ["john"] },
    });

    const result = await handleSearch(
      {
        type: ProtocolOp.SearchRequest,
        baseObject: "dc=example,dc=com",
        scope: SearchScope.SingleLevel,
        derefAliases: 0,
        sizeLimit: 0,
        timeLimit: 0,
        typesOnly: false,
        filter: { type: FilterTag.Present, attribute: "objectClass" },
        attributes: [],
      },
      ctx,
    );

    const dns = result.entries.map((e) => e.objectName).sort();
    // john は孫なので含まない。samba 有効時は sambaDomain 仮想エントリが追加される
    assertEquals(
      dns,
      ["ou=users,dc=example,dc=com", "sambadomainname=workgroup,dc=example,dc=com"].sort(),
    );
  } finally {
    await cleanup();
  }
});

Deno.test("Search WholeSubtree: 全子孫を返す", async () => {
  const { ctx, store, cleanup } = await makeCtx();
  try {
    await store.set({
      dn: "uid=john,ou=users,dc=example,dc=com",
      attrs: { objectclass: ["posixAccount"], uid: ["john"] },
    });
    await store.set({
      dn: "uid=jane,ou=users,dc=example,dc=com",
      attrs: { objectclass: ["posixAccount"], uid: ["jane"] },
    });

    const result = await handleSearch(
      {
        type: ProtocolOp.SearchRequest,
        baseObject: "dc=example,dc=com",
        scope: SearchScope.WholeSubtree,
        derefAliases: 0,
        sizeLimit: 0,
        timeLimit: 0,
        typesOnly: false,
        filter: { type: FilterTag.EqualityMatch, attribute: "objectClass", value: "posixAccount" },
        attributes: [],
      },
      ctx,
    );

    const dns = result.entries.map((e) => e.objectName).sort();
    assertEquals(dns, [
      "uid=jane,ou=users,dc=example,dc=com",
      "uid=john,ou=users,dc=example,dc=com",
    ]);
  } finally {
    await cleanup();
  }
});

Deno.test("Search: sizeLimit が設定されている場合はそれ以上返さない", async () => {
  const { ctx, store, cleanup } = await makeCtx();
  try {
    for (let i = 0; i < 5; i++) {
      await store.set({
        dn: `uid=user${i},ou=users,dc=example,dc=com`,
        attrs: { objectclass: ["posixAccount"], uid: [`user${i}`] },
      });
    }

    const result = await handleSearch(
      {
        type: ProtocolOp.SearchRequest,
        baseObject: "ou=users,dc=example,dc=com",
        scope: SearchScope.WholeSubtree,
        derefAliases: 0,
        sizeLimit: 3,
        timeLimit: 0,
        typesOnly: false,
        filter: { type: FilterTag.Present, attribute: "objectClass" },
        attributes: [],
      },
      ctx,
    );

    assertEquals(result.entries.length, 3);
    assertEquals(result.done.result.resultCode, ResultCode.SizeLimitExceeded);
  } finally {
    await cleanup();
  }
});

// --- Add ---

Deno.test("Add: 正常に追加される", async () => {
  const { ctx, store, cleanup } = await makeCtx();
  try {
    const response = await handleAdd(
      {
        type: ProtocolOp.AddRequest,
        entry: "uid=bob,ou=users,dc=example,dc=com",
        attributes: [
          { type: "objectClass", values: ["top", "posixAccount"] },
          { type: "uid", values: ["bob"] },
          { type: "cn", values: ["Bob"] },
          { type: "uidNumber", values: ["1002"] },
          { type: "gidNumber", values: ["100"] },
          { type: "homeDirectory", values: ["/home/bob"] },
        ],
      },
      ctx,
    );
    assertEquals(response.result.resultCode, ResultCode.Success);

    const entry = await store.get("uid=bob,ou=users,dc=example,dc=com");
    assertExists(entry);
  } finally {
    await cleanup();
  }
});

Deno.test("Add: 同じ DN のエントリは追加できない", async () => {
  const { ctx, store: _store, cleanup } = await makeCtx();
  try {
    const req = {
      type: ProtocolOp.AddRequest as const,
      entry: "uid=dup,ou=users,dc=example,dc=com",
      attributes: [{ type: "objectClass", values: ["top"] }],
    };

    await handleAdd(req, ctx);
    const second = await handleAdd(req, ctx);
    assertEquals(second.result.resultCode, ResultCode.EntryAlreadyExists);
  } finally {
    await cleanup();
  }
});

Deno.test("Add: 親が存在しない場合は NoSuchObject", async () => {
  const { ctx, store: _store, cleanup } = await makeCtx();
  try {
    const response = await handleAdd(
      {
        type: ProtocolOp.AddRequest,
        entry: "uid=orphan,ou=nonexistent,dc=example,dc=com",
        attributes: [{ type: "objectClass", values: ["top"] }],
      },
      ctx,
    );
    assertEquals(response.result.resultCode, ResultCode.NoSuchObject);
  } finally {
    await cleanup();
  }
});

Deno.test("Add: sambaSamAccount 追加時に NT ハッシュが自動生成される", async () => {
  const { ctx, store, cleanup } = await makeCtx();
  try {
    await handleAdd(
      {
        type: ProtocolOp.AddRequest,
        entry: "uid=sambauser,ou=users,dc=example,dc=com",
        attributes: [
          { type: "objectClass", values: ["top", "posixAccount", "sambaSamAccount"] },
          { type: "uid", values: ["sambauser"] },
          { type: "cn", values: ["Samba User"] },
          { type: "uidNumber", values: ["2001"] },
          { type: "gidNumber", values: ["100"] },
          { type: "homeDirectory", values: ["/home/sambauser"] },
          { type: "userPassword", values: ["samba123"] },
        ],
      },
      ctx,
    );

    const entry = await store.get("uid=sambauser,ou=users,dc=example,dc=com");
    assertExists(entry);

    // Samba 属性が自動生成されていること
    assertExists(entry.attrs["sambantpassword"]);
    assertExists(entry.attrs["sambasid"]);
    assertExists(entry.attrs["sambaacctflags"]);
    assertExists(entry.attrs["sambaprimarygroupsid"]);

    // NT ハッシュが既知の正解値と一致すること
    // 検証: printf 'samba123' | iconv -t utf-16le | openssl dgst -md4 -provider legacy
    assertEquals(entry.attrs["sambantpassword"][0], "C7C85138A66BCAFEE43767D1DED6DE52");
  } finally {
    await cleanup();
  }
});

Deno.test("Add: 認証なしでは InsufficientAccessRights", async () => {
  const { ctx, store: _store, cleanup } = await makeCtx(false);
  try {
    const response = await handleAdd(
      {
        type: ProtocolOp.AddRequest,
        entry: "uid=hacker,dc=example,dc=com",
        attributes: [{ type: "objectClass", values: ["top"] }],
      },
      ctx,
    );
    assertEquals(response.result.resultCode, ResultCode.InsufficientAccessRights);
  } finally {
    await cleanup();
  }
});

// --- Modify ---

Deno.test("Modify Replace: 属性値を置換できる", async () => {
  const { ctx, store, cleanup } = await makeCtx();
  try {
    await store.set({
      dn: "uid=mod,dc=example,dc=com",
      attrs: { objectclass: ["posixAccount"], cn: ["Old Name"] },
    });

    await handleModify(
      {
        type: ProtocolOp.ModifyRequest,
        object: "uid=mod,dc=example,dc=com",
        changes: [{
          operation: ModifyOp.Replace,
          modification: { type: "cn", values: ["New Name"] },
        }],
      },
      ctx,
    );

    const updated = await store.get("uid=mod,dc=example,dc=com");
    assertEquals(updated?.attrs["cn"], ["New Name"]);
  } finally {
    await cleanup();
  }
});

Deno.test("Modify Add: 既存属性に値を追加できる", async () => {
  const { ctx, store, cleanup } = await makeCtx();
  try {
    await store.set({
      dn: "uid=mod2,dc=example,dc=com",
      attrs: { objectclass: ["posixAccount"], mail: ["first@example.com"] },
    });

    await handleModify(
      {
        type: ProtocolOp.ModifyRequest,
        object: "uid=mod2,dc=example,dc=com",
        changes: [{
          operation: ModifyOp.Add,
          modification: { type: "mail", values: ["second@example.com"] },
        }],
      },
      ctx,
    );

    const updated = await store.get("uid=mod2,dc=example,dc=com");
    assertEquals(updated?.attrs["mail"]?.sort(), ["first@example.com", "second@example.com"]);
  } finally {
    await cleanup();
  }
});

Deno.test("Modify Delete: 特定の値を削除できる", async () => {
  const { ctx, store, cleanup } = await makeCtx();
  try {
    await store.set({
      dn: "uid=mod3,dc=example,dc=com",
      attrs: { objectclass: ["posixAccount"], mail: ["a@example.com", "b@example.com"] },
    });

    await handleModify(
      {
        type: ProtocolOp.ModifyRequest,
        object: "uid=mod3,dc=example,dc=com",
        changes: [{
          operation: ModifyOp.Delete,
          modification: { type: "mail", values: ["a@example.com"] },
        }],
      },
      ctx,
    );

    const updated = await store.get("uid=mod3,dc=example,dc=com");
    assertEquals(updated?.attrs["mail"], ["b@example.com"]);
  } finally {
    await cleanup();
  }
});

Deno.test("Modify: userPassword 変更で NT ハッシュが自動更新される", async () => {
  const { ctx, store, cleanup } = await makeCtx();
  try {
    await store.set({
      dn: "uid=pwuser,dc=example,dc=com",
      attrs: {
        objectclass: ["posixAccount", "sambaSamAccount"],
        uid: ["pwuser"],
        sambasid: ["S-1-5-21-1-2-3-1001"],
        userpassword: ["oldpassword"],
        sambantpassword: ["OLD_HASH"],
      },
    });

    await handleModify(
      {
        type: ProtocolOp.ModifyRequest,
        object: "uid=pwuser,dc=example,dc=com",
        changes: [{
          operation: ModifyOp.Replace,
          modification: { type: "userPassword", values: ["newpassword"] },
        }],
      },
      ctx,
    );

    const updated = await store.get("uid=pwuser,dc=example,dc=com");
    // OLD_HASH から更新されているはず
    const newHash = updated?.attrs["sambantpassword"]?.[0];
    assertExists(newHash);
    assertEquals(newHash !== "OLD_HASH", true);
    // 新しいパスワードの NT ハッシュと一致するはず
    const { ntHash } = await import("../src/samba/hash.ts");
    assertEquals(newHash, ntHash("newpassword"));
  } finally {
    await cleanup();
  }
});

// --- Delete ---

Deno.test("Delete: リーフエントリを削除できる", async () => {
  const { ctx, store, cleanup } = await makeCtx();
  try {
    await store.set({ dn: "uid=leaf,ou=users,dc=example,dc=com", attrs: {} });

    const response = await handleDelete(
      { type: ProtocolOp.DelRequest, entry: "uid=leaf,ou=users,dc=example,dc=com" },
      ctx,
    );
    assertEquals(response.result.resultCode, ResultCode.Success);
    assertEquals(await store.get("uid=leaf,ou=users,dc=example,dc=com"), null);
  } finally {
    await cleanup();
  }
});

Deno.test("Delete: 子を持つエントリは削除できない（NotAllowedOnNonLeaf）", async () => {
  const { ctx, store, cleanup } = await makeCtx();
  try {
    // ou=users は子 (john) を持っている
    const _response = await handleDelete(
      { type: ProtocolOp.DelRequest, entry: "ou=users,dc=example,dc=com" },
      ctx,
    );
    // 子がいなければ成功するが、john を追加してから試す
    await store.set({ dn: "uid=john,ou=users,dc=example,dc=com", attrs: {} });

    const response2 = await handleDelete(
      { type: ProtocolOp.DelRequest, entry: "ou=users,dc=example,dc=com" },
      ctx,
    );
    assertEquals(response2.result.resultCode, ResultCode.NotAllowedOnNonLeaf);
  } finally {
    await cleanup();
  }
});

// --- ModifyDN ---

Deno.test("ModifyDN: エントリを別の OU に移動できる", async () => {
  const { ctx, store, cleanup } = await makeCtx();
  try {
    await store.set({
      dn: "ou=archive,dc=example,dc=com",
      attrs: { objectclass: ["organizationalUnit"], ou: ["archive"] },
    });
    await store.set({
      dn: "uid=move,ou=users,dc=example,dc=com",
      attrs: { uid: ["move"], cn: ["Move Me"] },
    });

    await handleModifyDN(
      {
        type: ProtocolOp.ModifyDNRequest,
        entry: "uid=move,ou=users,dc=example,dc=com",
        newRDN: "uid=move",
        deleteOldRDN: false,
        newSuperior: "ou=archive,dc=example,dc=com",
      },
      ctx,
    );

    assertEquals(await store.get("uid=move,ou=users,dc=example,dc=com"), null);
    const moved = await store.get("uid=move,ou=archive,dc=example,dc=com");
    assertExists(moved);
    assertEquals(moved.attrs["cn"], ["Move Me"]);
  } finally {
    await cleanup();
  }
});

Deno.test("ModifyDN: 移動先が既存エントリと衝突すると EntryAlreadyExists", async () => {
  const { ctx, store, cleanup } = await makeCtx();
  try {
    await store.set({ dn: "uid=a,ou=users,dc=example,dc=com", attrs: {} });
    await store.set({ dn: "uid=b,ou=users,dc=example,dc=com", attrs: {} });

    const response = await handleModifyDN(
      {
        type: ProtocolOp.ModifyDNRequest,
        entry: "uid=a,ou=users,dc=example,dc=com",
        newRDN: "uid=b",
        deleteOldRDN: false,
        newSuperior: "ou=users,dc=example,dc=com",
      },
      ctx,
    );
    assertEquals(response.result.resultCode, ResultCode.EntryAlreadyExists);
  } finally {
    await cleanup();
  }
});

// ---------------------------------------------------------------------------
// Search — フィルターの組み合わせ
// ---------------------------------------------------------------------------

Deno.test("Search AND フィルター: 両条件を満たすエントリのみ返す", async () => {
  const { ctx, store, cleanup } = await makeCtx();
  try {
    await store.set({
      dn: "uid=alice,ou=users,dc=example,dc=com",
      attrs: { objectclass: ["posixAccount"], uid: ["alice"], mail: ["alice@example.com"] },
    });
    await store.set({
      dn: "uid=bob,ou=users,dc=example,dc=com",
      attrs: { objectclass: ["posixAccount"], uid: ["bob"] },
    });

    const result = await handleSearch({
      type: ProtocolOp.SearchRequest,
      baseObject: "ou=users,dc=example,dc=com",
      scope: SearchScope.WholeSubtree,
      derefAliases: 0,
      sizeLimit: 0,
      timeLimit: 0,
      typesOnly: false,
      filter: {
        type: FilterTag.And,
        filters: [
          { type: FilterTag.EqualityMatch, attribute: "objectClass", value: "posixAccount" },
          { type: FilterTag.Present, attribute: "mail" },
        ],
      },
      attributes: [],
    }, ctx);

    assertEquals(result.entries.length, 1);
    assertEquals(result.entries[0].objectName, "uid=alice,ou=users,dc=example,dc=com");
  } finally {
    await cleanup();
  }
});

Deno.test("Search OR フィルター: いずれかの条件を満たすエントリを返す", async () => {
  const { ctx, store, cleanup } = await makeCtx();
  try {
    await store.set({
      dn: "uid=alice,ou=users,dc=example,dc=com",
      attrs: { objectclass: ["posixAccount"], uid: ["alice"] },
    });
    await store.set({
      dn: "uid=bob,ou=users,dc=example,dc=com",
      attrs: { objectclass: ["posixAccount"], uid: ["bob"] },
    });
    await store.set({
      dn: "uid=carol,ou=users,dc=example,dc=com",
      attrs: { objectclass: ["posixAccount"], uid: ["carol"] },
    });

    const result = await handleSearch({
      type: ProtocolOp.SearchRequest,
      baseObject: "ou=users,dc=example,dc=com",
      scope: SearchScope.WholeSubtree,
      derefAliases: 0,
      sizeLimit: 0,
      timeLimit: 0,
      typesOnly: false,
      filter: {
        type: FilterTag.Or,
        filters: [
          { type: FilterTag.EqualityMatch, attribute: "uid", value: "alice" },
          { type: FilterTag.EqualityMatch, attribute: "uid", value: "bob" },
        ],
      },
      attributes: [],
    }, ctx);

    const uids = result.entries.map((e) => e.objectName).sort();
    assertEquals(uids, [
      "uid=alice,ou=users,dc=example,dc=com",
      "uid=bob,ou=users,dc=example,dc=com",
    ]);
  } finally {
    await cleanup();
  }
});

Deno.test("Search NOT フィルター: 条件を満たさないエントリのみ返す", async () => {
  const { ctx, store, cleanup } = await makeCtx();
  try {
    await store.set({
      dn: "uid=alice,ou=users,dc=example,dc=com",
      attrs: { objectclass: ["posixAccount"], uid: ["alice"] },
    });
    await store.set({
      dn: "uid=admin,ou=users,dc=example,dc=com",
      attrs: { objectclass: ["posixAccount"], uid: ["admin"] },
    });

    const result = await handleSearch({
      type: ProtocolOp.SearchRequest,
      baseObject: "ou=users,dc=example,dc=com",
      scope: SearchScope.WholeSubtree,
      derefAliases: 0,
      sizeLimit: 0,
      timeLimit: 0,
      typesOnly: false,
      filter: {
        type: FilterTag.Not,
        filter: { type: FilterTag.EqualityMatch, attribute: "uid", value: "admin" },
      },
      attributes: [],
    }, ctx);

    // WholeSubtree はベース自身（ou=users）も含むため、uid=admin 以外の2件が返る
    const dns = result.entries.map((e) => e.objectName);
    assertEquals(dns.includes("uid=alice,ou=users,dc=example,dc=com"), true);
    assertEquals(dns.includes("uid=admin,ou=users,dc=example,dc=com"), false);
  } finally {
    await cleanup();
  }
});

Deno.test("Search Substrings フィルター: 前方一致・部分一致・後方一致", async () => {
  const { ctx, store, cleanup } = await makeCtx();
  try {
    await store.set({
      dn: "uid=alice,ou=users,dc=example,dc=com",
      attrs: { objectclass: ["posixAccount"], cn: ["Alice Smith"] },
    });
    await store.set({
      dn: "uid=bob,ou=users,dc=example,dc=com",
      attrs: { objectclass: ["posixAccount"], cn: ["Bob Jones"] },
    });
    await store.set({
      dn: "uid=alan,ou=users,dc=example,dc=com",
      attrs: { objectclass: ["posixAccount"], cn: ["Alan White"] },
    });

    // 前方一致: cn=Al*
    const r1 = await handleSearch({
      type: ProtocolOp.SearchRequest,
      baseObject: "ou=users,dc=example,dc=com",
      scope: SearchScope.WholeSubtree,
      derefAliases: 0,
      sizeLimit: 0,
      timeLimit: 0,
      typesOnly: false,
      filter: { type: FilterTag.Substrings, attribute: "cn", initial: "al" },
      attributes: [],
    }, ctx);
    assertEquals(r1.entries.map((e) => e.objectName).sort(), [
      "uid=alan,ou=users,dc=example,dc=com",
      "uid=alice,ou=users,dc=example,dc=com",
    ]);

    // 後方一致: cn=*ith
    const r2 = await handleSearch({
      type: ProtocolOp.SearchRequest,
      baseObject: "ou=users,dc=example,dc=com",
      scope: SearchScope.WholeSubtree,
      derefAliases: 0,
      sizeLimit: 0,
      timeLimit: 0,
      typesOnly: false,
      filter: { type: FilterTag.Substrings, attribute: "cn", final: "ith" },
      attributes: [],
    }, ctx);
    assertEquals(r2.entries.length, 1);
    assertEquals(r2.entries[0].objectName, "uid=alice,ou=users,dc=example,dc=com");
  } finally {
    await cleanup();
  }
});

// ---------------------------------------------------------------------------
// Modify — 追加カバレッジ
// ---------------------------------------------------------------------------

Deno.test("Modify: 存在しないエントリへの変更は NoSuchObject", async () => {
  const { ctx, cleanup } = await makeCtx();
  try {
    const response = await handleModify({
      type: ProtocolOp.ModifyRequest,
      object: "uid=ghost,dc=example,dc=com",
      changes: [{ operation: ModifyOp.Replace, modification: { type: "cn", values: ["Ghost"] } }],
    }, ctx);
    assertEquals(response.result.resultCode, ResultCode.NoSuchObject);
  } finally {
    await cleanup();
  }
});

Deno.test("Modify Delete: 空の値配列で属性を全削除できる", async () => {
  const { ctx, store, cleanup } = await makeCtx();
  try {
    await store.set({
      dn: "uid=delattr,dc=example,dc=com",
      attrs: { objectclass: ["posixAccount"], description: ["remove me"] },
    });

    await handleModify({
      type: ProtocolOp.ModifyRequest,
      object: "uid=delattr,dc=example,dc=com",
      changes: [{ operation: ModifyOp.Delete, modification: { type: "description", values: [] } }],
    }, ctx);

    const updated = await store.get("uid=delattr,dc=example,dc=com");
    assertEquals(updated?.attrs["description"], undefined);
  } finally {
    await cleanup();
  }
});

// ---------------------------------------------------------------------------
// Delete — 追加カバレッジ
// ---------------------------------------------------------------------------

Deno.test("Delete: 存在しないエントリは NoSuchObject", async () => {
  const { ctx, cleanup } = await makeCtx();
  try {
    const response = await handleDelete(
      { type: ProtocolOp.DelRequest, entry: "uid=ghost,dc=example,dc=com" },
      ctx,
    );
    assertEquals(response.result.resultCode, ResultCode.NoSuchObject);
  } finally {
    await cleanup();
  }
});

// ---------------------------------------------------------------------------
// ModifyDN — 追加カバレッジ
// ---------------------------------------------------------------------------

Deno.test("ModifyDN: 存在しないエントリは NoSuchObject", async () => {
  const { ctx, cleanup } = await makeCtx();
  try {
    const response = await handleModifyDN({
      type: ProtocolOp.ModifyDNRequest,
      entry: "uid=ghost,ou=users,dc=example,dc=com",
      newRDN: "uid=ghost2",
      deleteOldRDN: false,
      newSuperior: undefined,
    }, ctx);
    assertEquals(response.result.resultCode, ResultCode.NoSuchObject);
  } finally {
    await cleanup();
  }
});

Deno.test("Add: posixGroup 追加時に sambaGroupMapping が自動付与される", async () => {
  const { ctx, store, cleanup } = await makeCtx();
  try {
    const response = await handleAdd(
      {
        type: ProtocolOp.AddRequest,
        entry: "cn=devs,ou=users,dc=example,dc=com",
        attributes: [
          { type: "objectClass", values: ["top", "posixGroup"] },
          { type: "cn", values: ["devs"] },
          { type: "gidNumber", values: ["1001"] },
        ],
      },
      ctx,
    );
    assertEquals(response.result.resultCode, ResultCode.Success);

    const entry = await store.get("cn=devs,ou=users,dc=example,dc=com");
    assertExists(entry);

    // sambaGroupMapping objectClass が追加されていること
    const ocs = entry.attrs["objectclass"] ?? [];
    assertEquals(ocs.some((oc: string) => oc.toLowerCase() === "sambagroupmapping"), true);

    // sambaSID が設定されていること（gidNumber=1001 → RID=1001*2+1001=3003）
    assertExists(entry.attrs["sambasid"]);
    assertEquals(entry.attrs["sambasid"][0].endsWith("-3003"), true);

    // sambaGroupType が "2"（Domain Group）であること
    assertEquals(entry.attrs["sambagrouptype"], ["2"]);

    // displayName が cn から設定されていること
    assertEquals(entry.attrs["displayname"], ["devs"]);
  } finally {
    await cleanup();
  }
});

Deno.test("ModifyDN: deleteOldRDN=true で旧 RDN 属性値が削除される", async () => {
  const { ctx, store, cleanup } = await makeCtx();
  try {
    await store.set({
      dn: "uid=oldname,ou=users,dc=example,dc=com",
      attrs: { objectclass: ["posixAccount"], uid: ["oldname"], cn: ["Old Name"] },
    });

    await handleModifyDN({
      type: ProtocolOp.ModifyDNRequest,
      entry: "uid=oldname,ou=users,dc=example,dc=com",
      newRDN: "uid=newname",
      deleteOldRDN: true,
      newSuperior: undefined,
    }, ctx);

    const entry = await store.get("uid=newname,ou=users,dc=example,dc=com");
    assertExists(entry);
    // 新しい RDN 属性値が追加されている
    assertEquals(entry.attrs["uid"]?.includes("newname"), true);
    // 古い RDN 属性値が削除されている
    assertEquals(entry.attrs["uid"]?.includes("oldname"), false);
  } finally {
    await cleanup();
  }
});

// ---------------------------------------------------------------------------
// Bind — 追加カバレッジ
// ---------------------------------------------------------------------------

Deno.test("Bind: 存在しないユーザー DN は InvalidCredentials", async () => {
  const { ctx, cleanup } = await makeCtx(false);
  try {
    const result = await handleBind({
      type: ProtocolOp.BindRequest,
      version: 3,
      dn: "uid=ghost,dc=example,dc=com",
      password: "anypass",
    }, ctx);
    assertEquals(result.response.result.resultCode, ResultCode.InvalidCredentials);
  } finally {
    await cleanup();
  }
});
