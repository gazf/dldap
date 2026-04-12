/**
 * SID 生成・管理のテスト。
 *
 * Focus: SID が Samba の期待するフォーマットと計算式に従っているか。
 * SID が誤ると Windows クライアントとの相互運用性が壊れる。
 */

import { assertEquals, assertMatch } from "jsr:@std/assert";
import {
  buildSID,
  ensureDomainSID,
  generateDomainSID,
  userRID,
  groupRID,
  resolveUserSID,
  resolveGroupSID,
  resolvePrimaryGroupSID,
  WELL_KNOWN_RIDS,
} from "../src/samba/sid.ts";

const DOMAIN_SID = "S-1-5-21-111111111-222222222-333333333";

// --- フォーマット ---

Deno.test("SID: generateDomainSID は正しいフォーマットを生成する", () => {
  const sid = generateDomainSID();
  // S-1-5-21-{sub1}-{sub2}-{sub3} の形式
  assertMatch(sid, /^S-1-5-21-\d+-\d+-\d+$/);
});

Deno.test("SID: generateDomainSID は毎回異なる値を生成する（ランダム性）", () => {
  const sids = new Set(Array.from({ length: 10 }, generateDomainSID));
  // 10 回生成してすべて異なることを確認（衝突確率は天文学的に低い）
  assertEquals(sids.size, 10);
});

// --- RID 計算 ---

Deno.test("SID: userRID は uidNumber * 2 + 1000", () => {
  assertEquals(userRID(0), 1000);
  assertEquals(userRID(1), 1002);
  assertEquals(userRID(500), 2000);
  assertEquals(userRID(1001), 3002);
});

Deno.test("SID: groupRID は gidNumber * 2 + 1001", () => {
  assertEquals(groupRID(0), 1001);
  assertEquals(groupRID(1), 1003);
  assertEquals(groupRID(100), 1201);
});

Deno.test("SID: userRID と groupRID は衝突しない（奇偶が異なる）", () => {
  // userRID は偶数 (1000, 1002, ...)、groupRID は奇数 (1001, 1003, ...)
  for (let i = 0; i < 10; i++) {
    assertEquals(userRID(i) % 2, 0);
    assertEquals(groupRID(i) % 2, 1);
  }
});

// --- buildSID ---

Deno.test("SID: buildSID でドメイン SID に RID を付加できる", () => {
  assertEquals(buildSID(DOMAIN_SID, 1001), `${DOMAIN_SID}-1001`);
  assertEquals(buildSID(DOMAIN_SID, 500), `${DOMAIN_SID}-500`);
});

// --- resolveUserSID ---

Deno.test("SID: resolveUserSID は uidNumber があればそれを使う", () => {
  const attrs = { uidnumber: ["1001"] };
  const sid = resolveUserSID(DOMAIN_SID, attrs);
  assertEquals(sid, `${DOMAIN_SID}-${userRID(1001)}`);
});

Deno.test("SID: resolveGroupSID は gidNumber があればそれを使う", () => {
  const attrs = { gidnumber: ["100"] };
  const sid = resolveGroupSID(DOMAIN_SID, attrs);
  assertEquals(sid, `${DOMAIN_SID}-${groupRID(100)}`);
});

// --- resolvePrimaryGroupSID ---

Deno.test("SID: resolvePrimaryGroupSID は gidNumber から計算する", () => {
  const attrs = { gidnumber: ["100"] };
  const sid = resolvePrimaryGroupSID(DOMAIN_SID, attrs);
  assertEquals(sid, `${DOMAIN_SID}-${groupRID(100)}`);
});

Deno.test("SID: resolvePrimaryGroupSID は gidNumber がなければ Domain Users (513) を使う", () => {
  const sid = resolvePrimaryGroupSID(DOMAIN_SID, {});
  assertEquals(sid, `${DOMAIN_SID}-${WELL_KNOWN_RIDS.DOMAIN_USERS}`);
});

// --- ensureDomainSID ---

Deno.test(
  "SID: ensureDomainSID は初回呼び出しで SID を生成して KV に保存する",
  { permissions: { read: true, write: true } },
  async () => {
    const tmpPath = await Deno.makeTempFile({ suffix: ".kv" });
    const kv = await Deno.openKv(tmpPath);
    try {
      const sid = await ensureDomainSID(kv);
      assertMatch(sid, /^S-1-5-21-\d+-\d+-\d+$/);

      // KV に保存されていることを確認
      const stored = await kv.get<string>(["config", "samba_domain_sid"]);
      assertEquals(stored.value, sid);
    } finally {
      kv.close();
      await Deno.remove(tmpPath).catch(() => {});
    }
  },
);

Deno.test(
  "SID: ensureDomainSID は2回目以降は同じ SID を返す",
  { permissions: { read: true, write: true } },
  async () => {
    const tmpPath = await Deno.makeTempFile({ suffix: ".kv" });
    const kv = await Deno.openKv(tmpPath);
    try {
      const sid1 = await ensureDomainSID(kv);
      const sid2 = await ensureDomainSID(kv);
      assertEquals(sid1, sid2);
    } finally {
      kv.close();
      await Deno.remove(tmpPath).catch(() => {});
    }
  },
);
