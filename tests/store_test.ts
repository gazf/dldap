/**
 * Deno KV ストアのテスト。
 *
 * Focus: ディレクトリツリーとしての正しい動作。
 * CRUD の正確さだけでなく、「親子関係」「サブツリー検索」「上書き防止」など
 * LDAP ディレクトリとして期待される動作を検証する。
 */

import { assertEquals, assertExists } from "jsr:@std/assert";
import { KvStore } from "../src/store/kv.ts";

async function withStore(fn: (store: KvStore) => Promise<void>): Promise<void> {
  // テストごとに一時ファイルを使い、KV ストアを分離する
  const tmpPath = await Deno.makeTempFile({ suffix: ".kv" });
  const store = await KvStore.open(tmpPath);
  try {
    await fn(store);
  } finally {
    await store.close();
    await Deno.remove(tmpPath).catch(() => {});
  }
}

// --- 基本 CRUD ---

Deno.test("KV Store: エントリの set/get", async () => {
  await withStore(async (store) => {
    await store.set({
      dn: "uid=john,ou=users,dc=example,dc=com",
      attrs: { uid: ["john"], cn: ["John Doe"] },
    });

    const entry = await store.get("uid=john,ou=users,dc=example,dc=com");
    assertExists(entry);
    assertEquals(entry.dn, "uid=john,ou=users,dc=example,dc=com");
    assertEquals(entry.attrs["uid"], ["john"]);
  });
});

Deno.test("KV Store: 存在しない DN は null を返す", async () => {
  await withStore(async (store) => {
    const entry = await store.get("uid=nobody,dc=example,dc=com");
    assertEquals(entry, null);
  });
});

Deno.test("KV Store: DN は正規化（小文字）されて保存される", async () => {
  await withStore(async (store) => {
    await store.set({
      dn: "UID=John,DC=Example,DC=Com",
      attrs: { uid: ["John"] },
    });

    // 大文字でも取得できる
    const entry = await store.get("UID=John,DC=Example,DC=Com");
    assertExists(entry);
    // 内部的には小文字で保存されている
    assertEquals(entry.dn, "uid=john,dc=example,dc=com");
  });
});

Deno.test("KV Store: 属性名は小文字に正規化される", async () => {
  await withStore(async (store) => {
    await store.set({
      dn: "uid=john,dc=example,dc=com",
      attrs: { UID: ["john"], CN: ["John"], ObjectClass: ["posixAccount"] },
    });

    const entry = await store.get("uid=john,dc=example,dc=com");
    assertExists(entry);
    assertEquals(entry.attrs["uid"], ["john"]);
    assertEquals(entry.attrs["cn"], ["John"]);
    assertEquals(entry.attrs["objectclass"], ["posixAccount"]);
  });
});

Deno.test("KV Store: delete でエントリを削除できる", async () => {
  await withStore(async (store) => {
    await store.set({ dn: "uid=temp,dc=example,dc=com", attrs: {} });
    const deleted = await store.delete("uid=temp,dc=example,dc=com");
    assertEquals(deleted, true);
    assertEquals(await store.get("uid=temp,dc=example,dc=com"), null);
  });
});

Deno.test("KV Store: 存在しない DN を delete すると false", async () => {
  await withStore(async (store) => {
    const deleted = await store.delete("uid=ghost,dc=example,dc=com");
    assertEquals(deleted, false);
  });
});

// --- listChildren ---

Deno.test("KV Store: listChildren は直接の子のみ返す（孫は含まない）", async () => {
  await withStore(async (store) => {
    await store.set({ dn: "dc=example,dc=com", attrs: {} });
    await store.set({ dn: "ou=users,dc=example,dc=com", attrs: {} });
    await store.set({ dn: "ou=groups,dc=example,dc=com", attrs: {} });
    await store.set({ dn: "uid=john,ou=users,dc=example,dc=com", attrs: {} }); // 孫

    const children = await store.listChildren("dc=example,dc=com");
    const dns = children.map((e) => e.dn).sort();

    assertEquals(dns, [
      "ou=groups,dc=example,dc=com",
      "ou=users,dc=example,dc=com",
    ]);
  });
});

Deno.test("KV Store: listChildren は存在しない親でも空配列を返す", async () => {
  await withStore(async (store) => {
    const children = await store.listChildren("ou=nonexistent,dc=example,dc=com");
    assertEquals(children, []);
  });
});

// --- listSubtree ---

Deno.test("KV Store: listSubtree はベースエントリ自身を含まない", async () => {
  await withStore(async (store) => {
    await store.set({ dn: "ou=users,dc=example,dc=com", attrs: {} });
    await store.set({ dn: "uid=john,ou=users,dc=example,dc=com", attrs: {} });

    const subtree = await store.listSubtree("ou=users,dc=example,dc=com");
    assertEquals(subtree.length, 1);
    assertEquals(subtree[0].dn, "uid=john,ou=users,dc=example,dc=com");
  });
});

Deno.test("KV Store: listSubtree は全子孫を含む", async () => {
  await withStore(async (store) => {
    await store.set({ dn: "dc=example,dc=com", attrs: {} });
    await store.set({ dn: "ou=users,dc=example,dc=com", attrs: {} });
    await store.set({ dn: "ou=groups,dc=example,dc=com", attrs: {} });
    await store.set({ dn: "uid=john,ou=users,dc=example,dc=com", attrs: {} });
    await store.set({ dn: "uid=jane,ou=users,dc=example,dc=com", attrs: {} });

    const subtree = await store.listSubtree("dc=example,dc=com");
    const dns = subtree.map((e) => e.dn).sort();
    assertEquals(dns, [
      "ou=groups,dc=example,dc=com",
      "ou=users,dc=example,dc=com",
      "uid=jane,ou=users,dc=example,dc=com",
      "uid=john,ou=users,dc=example,dc=com",
    ]);
  });
});

// --- rename ---

Deno.test("KV Store: rename はエントリを新しい DN に移動する", async () => {
  await withStore(async (store) => {
    await store.set({
      dn: "uid=john,ou=old,dc=example,dc=com",
      attrs: { uid: ["john"], cn: ["John"] },
    });

    await store.rename(
      "uid=john,ou=old,dc=example,dc=com",
      "uid=john,ou=new,dc=example,dc=com",
    );

    assertEquals(await store.get("uid=john,ou=old,dc=example,dc=com"), null);
    const moved = await store.get("uid=john,ou=new,dc=example,dc=com");
    assertExists(moved);
    assertEquals(moved.attrs["uid"], ["john"]);
  });
});

Deno.test("KV Store: rename 後は古い DN で子リストに現れない", async () => {
  await withStore(async (store) => {
    await store.set({ dn: "ou=old,dc=example,dc=com", attrs: {} });
    await store.set({ dn: "ou=new,dc=example,dc=com", attrs: {} });
    await store.set({ dn: "uid=john,ou=old,dc=example,dc=com", attrs: {} });

    await store.rename(
      "uid=john,ou=old,dc=example,dc=com",
      "uid=john,ou=new,dc=example,dc=com",
    );

    const oldChildren = await store.listChildren("ou=old,dc=example,dc=com");
    assertEquals(oldChildren.length, 0);

    const newChildren = await store.listChildren("ou=new,dc=example,dc=com");
    assertEquals(newChildren.length, 1);
    assertEquals(newChildren[0].dn, "uid=john,ou=new,dc=example,dc=com");
  });
});
