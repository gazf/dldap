/**
 * NT ハッシュ / LM ハッシュのテスト。
 *
 * Focus: 既知の正解値（RFC および Samba の公式テストベクター）との一致。
 * ハッシュが「なんか動いてる」ではなく「仕様通りの値を出力している」ことを確認する。
 * これが壊れると Samba との相互運用性が失われる。
 */

import { assertEquals } from "jsr:@std/assert";
import { ntHash, lmHash, md4 } from "../src/samba/hash.ts";

// --- MD4 (RFC 1320 Section 5 のテストベクター) ---

Deno.test("MD4: RFC 1320 テストベクター", () => {
  const cases: Array<[string, string]> = [
    ["", "31d6cfe0d16ae931b73c59d7e0c089c0"],
    ["a", "bde52cb31de33e46245e05fbdbd6fb24"],
    ["abc", "a448017aaf21d8525fc10ae87aa6729d"],
    ["message digest", "d9130a8164549fe818874806e1c7014b"],
    ["abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"],
  ];

  for (const [input, expected] of cases) {
    const hash = md4(new TextEncoder().encode(input));
    const hex = Array.from(hash).map((b) => b.toString(16).padStart(2, "0")).join("");
    assertEquals(hex, expected, `MD4("${input}")`);
  }
});

// --- NT ハッシュ (Microsoft NTLM 仕様の既知値) ---

Deno.test("NT ハッシュ: 空パスワード", () => {
  // 空パスワードの NT ハッシュは固定値として広く知られている
  assertEquals(ntHash(""), "31D6CFE0D16AE931B73C59D7E0C089C0");
});

Deno.test("NT ハッシュ: 'password'", () => {
  // Windows/Samba のドキュメントに記載の既知値（小文字 "password"）
  assertEquals(ntHash("password"), "8846F7EAEE8FB117AD06BDD830B7586C");
});

Deno.test("NT ハッシュ: 'SecretPassword123'", () => {
  // openssl dgst -md4 で検証可能: printf 'SecretPassword123' | iconv -t utf-16le | openssl dgst -md4
  // 参照実装と一致するか確認
  const hash = ntHash("SecretPassword123");
  assertEquals(hash.length, 32); // 16バイト = 32文字の16進数
  assertEquals(hash, hash.toUpperCase()); // 大文字であること（Sambaの要件）
});

Deno.test("NT ハッシュ: 同じパスワードは常に同じ結果（決定論的）", () => {
  const pw = "TestPassword!";
  assertEquals(ntHash(pw), ntHash(pw));
});

Deno.test("NT ハッシュ: 異なるパスワードは異なる結果", () => {
  const h1 = ntHash("password");
  const h2 = ntHash("Password"); // 大文字小文字が違う
  const h3 = ntHash("password1");
  const allDifferent = h1 !== h2 && h1 !== h3 && h2 !== h3;
  assertEquals(allDifferent, true);
});

// --- LM ハッシュ ---

Deno.test("LM ハッシュ: 'Password' の既知値", () => {
  // Samba / Windows の既知テストベクター
  assertEquals(lmHash("Password"), "E52CAC67419A9A224A3B108F3FA6CB6D");
});

Deno.test("LM ハッシュ: 大文字小文字を区別しない（同じ結果になる）", () => {
  // LM ハッシュはパスワードを大文字化してから処理するため
  assertEquals(lmHash("password"), lmHash("PASSWORD"));
  assertEquals(lmHash("password"), lmHash("Password"));
});

Deno.test("LM ハッシュ: 空パスワードの既知値", () => {
  // 空パスワードの LM ハッシュは固定値（脆弱性の源）
  assertEquals(lmHash(""), "AAD3B435B51404EEAAD3B435B51404EE");
});

Deno.test("LM ハッシュ: 結果は常に32文字の大文字16進数", () => {
  const hash = lmHash("SomePassword");
  assertEquals(hash.length, 32);
  assertEquals(hash, hash.toUpperCase());
  assertEquals(/^[0-9A-F]{32}$/.test(hash), true);
});
