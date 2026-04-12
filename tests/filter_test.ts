/**
 * LDAP フィルター評価エンジンのテスト。
 *
 * Focus: フィルターの各種組み合わせが正しくエントリに対して評価されるか。
 * LDAP クライアントが発行するクエリが意図通りの結果を返すかどうかに直結する。
 */

import { assertEquals } from "jsr:@std/assert";
import { matchesFilter } from "../src/handlers/filter.ts";
import { FilterTag } from "../src/ldap/constants.ts";
import type { DirectoryEntry } from "../src/store/types.ts";

function entry(dn: string, attrs: Record<string, string[]>): DirectoryEntry {
  return { dn: dn.toLowerCase(), attrs };
}

const john = entry("uid=john,ou=users,dc=example,dc=com", {
  objectclass: ["top", "posixAccount", "sambaSamAccount"],
  uid: ["john"],
  cn: ["John Doe"],
  sn: ["Doe"],
  uidnumber: ["1001"],
  gidnumber: ["100"],
  homedirectory: ["/home/john"],
  mail: ["john@example.com"],
  sambaacctflags: ["[U          ]"],
});

// --- Presence フィルター ---

Deno.test("フィルター Present: 存在する属性にマッチ", () => {
  assertEquals(matchesFilter(john, { type: FilterTag.Present, attribute: "uid" }), true);
});

Deno.test("フィルター Present: 存在しない属性にはマッチしない", () => {
  assertEquals(matchesFilter(john, { type: FilterTag.Present, attribute: "telephonenumber" }), false);
});

Deno.test("フィルター Present: objectClass は常に存在する", () => {
  // LDAP 仕様: すべてのエントリは objectClass を持つ
  assertEquals(matchesFilter(john, { type: FilterTag.Present, attribute: "objectClass" }), true);
});

// --- Equality フィルター ---

Deno.test("フィルター Equality: 完全一致", () => {
  assertEquals(
    matchesFilter(john, { type: FilterTag.EqualityMatch, attribute: "uid", value: "john" }),
    true,
  );
});

Deno.test("フィルター Equality: 大文字小文字を区別しない", () => {
  // LDAP の属性比較は基本的に case-insensitive
  assertEquals(
    matchesFilter(john, { type: FilterTag.EqualityMatch, attribute: "uid", value: "JOHN" }),
    true,
  );
});

Deno.test("フィルター Equality: 不一致", () => {
  assertEquals(
    matchesFilter(john, { type: FilterTag.EqualityMatch, attribute: "uid", value: "jane" }),
    false,
  );
});

Deno.test("フィルター Equality: objectClass で検索", () => {
  assertEquals(
    matchesFilter(john, { type: FilterTag.EqualityMatch, attribute: "objectClass", value: "posixAccount" }),
    true,
  );
  assertEquals(
    matchesFilter(john, { type: FilterTag.EqualityMatch, attribute: "objectClass", value: "groupOfNames" }),
    false,
  );
});

// --- Substrings フィルター ---

Deno.test("フィルター Substrings: initial（前方一致）", () => {
  assertEquals(
    matchesFilter(john, { type: FilterTag.Substrings, attribute: "cn", initial: "John" }),
    true,
  );
  assertEquals(
    matchesFilter(john, { type: FilterTag.Substrings, attribute: "cn", initial: "Jane" }),
    false,
  );
});

Deno.test("フィルター Substrings: final（後方一致）", () => {
  assertEquals(
    matchesFilter(john, { type: FilterTag.Substrings, attribute: "cn", final: "Doe" }),
    true,
  );
  assertEquals(
    matchesFilter(john, { type: FilterTag.Substrings, attribute: "cn", final: "Smith" }),
    false,
  );
});

Deno.test("フィルター Substrings: any（中間一致）", () => {
  assertEquals(
    matchesFilter(john, { type: FilterTag.Substrings, attribute: "cn", any: ["hn D"] }),
    true,
  );
});

Deno.test("フィルター Substrings: initial + final の組み合わせ（*(アスタリスク)パターン）", () => {
  // cn=John*Doe に相当
  assertEquals(
    matchesFilter(john, { type: FilterTag.Substrings, attribute: "cn", initial: "John", final: "Doe" }),
    true,
  );
});

Deno.test("フィルター Substrings: mail のドメイン部分一致", () => {
  assertEquals(
    matchesFilter(john, { type: FilterTag.Substrings, attribute: "mail", any: ["example.com"] }),
    true,
  );
});

// --- AND / OR / NOT フィルター ---

Deno.test("フィルター AND: 両条件が真のとき真", () => {
  assertEquals(
    matchesFilter(john, {
      type: FilterTag.And,
      filters: [
        { type: FilterTag.EqualityMatch, attribute: "uid", value: "john" },
        { type: FilterTag.EqualityMatch, attribute: "objectClass", value: "posixAccount" },
      ],
    }),
    true,
  );
});

Deno.test("フィルター AND: 片方が偽のとき偽", () => {
  assertEquals(
    matchesFilter(john, {
      type: FilterTag.And,
      filters: [
        { type: FilterTag.EqualityMatch, attribute: "uid", value: "john" },
        { type: FilterTag.EqualityMatch, attribute: "uid", value: "jane" }, // 偽
      ],
    }),
    false,
  );
});

Deno.test("フィルター OR: 片方が真のとき真", () => {
  assertEquals(
    matchesFilter(john, {
      type: FilterTag.Or,
      filters: [
        { type: FilterTag.EqualityMatch, attribute: "uid", value: "john" },
        { type: FilterTag.EqualityMatch, attribute: "uid", value: "jane" }, // 偽
      ],
    }),
    true,
  );
});

Deno.test("フィルター OR: 両方偽のとき偽", () => {
  assertEquals(
    matchesFilter(john, {
      type: FilterTag.Or,
      filters: [
        { type: FilterTag.EqualityMatch, attribute: "uid", value: "alice" },
        { type: FilterTag.EqualityMatch, attribute: "uid", value: "bob" },
      ],
    }),
    false,
  );
});

Deno.test("フィルター NOT: 偽を反転して真", () => {
  assertEquals(
    matchesFilter(john, {
      type: FilterTag.Not,
      filter: { type: FilterTag.EqualityMatch, attribute: "uid", value: "jane" },
    }),
    true,
  );
});

Deno.test("フィルター NOT: 真を反転して偽", () => {
  assertEquals(
    matchesFilter(john, {
      type: FilterTag.Not,
      filter: { type: FilterTag.EqualityMatch, attribute: "uid", value: "john" },
    }),
    false,
  );
});

Deno.test("フィルター: 複合ネスト (&(objectClass=posixAccount)(|(uid=john)(uid=jane)))", () => {
  assertEquals(
    matchesFilter(john, {
      type: FilterTag.And,
      filters: [
        { type: FilterTag.EqualityMatch, attribute: "objectClass", value: "posixAccount" },
        {
          type: FilterTag.Or,
          filters: [
            { type: FilterTag.EqualityMatch, attribute: "uid", value: "john" },
            { type: FilterTag.EqualityMatch, attribute: "uid", value: "jane" },
          ],
        },
      ],
    }),
    true,
  );
});

// --- Greater/Less ---

Deno.test("フィルター GreaterOrEqual: uidNumber >= 1000", () => {
  assertEquals(
    matchesFilter(john, { type: FilterTag.GreaterOrEqual, attribute: "uidnumber", value: "1000" }),
    true,
  );
  assertEquals(
    matchesFilter(john, { type: FilterTag.GreaterOrEqual, attribute: "uidnumber", value: "1002" }),
    false,
  );
});

Deno.test("フィルター LessOrEqual: uidNumber <= 2000", () => {
  assertEquals(
    matchesFilter(john, { type: FilterTag.LessOrEqual, attribute: "uidnumber", value: "2000" }),
    true,
  );
});
