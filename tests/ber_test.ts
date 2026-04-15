/**
 * BER encoder/decoder tests.
 *
 * Focus: BER のラウンドトリップが正しく機能するか。
 * LDAP で実際に使われる型（INTEGER, OCTET STRING, SEQUENCE 等）が
 * 仕様通りにエンコード/デコードされることを確認する。
 */

import { assertEquals, assertThrows } from "@std/assert";
import {
  decodeAll,
  decodeBer,
  decodeBoolean,
  decodeChildren,
  decodeInteger,
  decodeOctetStringAsString,
} from "../src/ber/decoder.ts";
import {
  concat,
  encodeBoolean,
  encodeConstructed,
  encodeInteger,
  encodeOctetString,
  TAG_BOOLEAN,
  TAG_INTEGER,
  TAG_OCTET_STRING,
  TAG_SEQUENCE,
} from "../src/ber/encoder.ts";

// --- INTEGER ---

Deno.test("BER INTEGER: 0 のエンコードとデコード", () => {
  const enc = encodeInteger(TAG_INTEGER, 0);
  const { element } = decodeBer(enc);
  assertEquals(decodeInteger(element), 0);
});

Deno.test("BER INTEGER: 正の小さな値", () => {
  for (const n of [1, 127, 128, 255, 256, 65535, 2147483647]) {
    const enc = encodeInteger(TAG_INTEGER, n);
    const { element } = decodeBer(enc);
    assertEquals(decodeInteger(element), n, `value=${n}`);
  }
});

Deno.test("BER INTEGER: 負の値", () => {
  for (const n of [-1, -128, -129, -256]) {
    const enc = encodeInteger(TAG_INTEGER, n);
    const { element } = decodeBer(enc);
    assertEquals(decodeInteger(element), n, `value=${n}`);
  }
});

// --- OCTET STRING ---

Deno.test("BER OCTET STRING: ASCII 文字列のラウンドトリップ", () => {
  const original = "cn=admin,dc=example,dc=com";
  const enc = encodeOctetString(TAG_OCTET_STRING, original);
  const { element } = decodeBer(enc);
  assertEquals(decodeOctetStringAsString(element), original);
});

Deno.test("BER OCTET STRING: 空文字列", () => {
  const enc = encodeOctetString(TAG_OCTET_STRING, "");
  const { element } = decodeBer(enc);
  assertEquals(decodeOctetStringAsString(element), "");
});

Deno.test("BER OCTET STRING: 128バイト以上（長形式長さ）", () => {
  const long = "x".repeat(200);
  const enc = encodeOctetString(TAG_OCTET_STRING, long);
  const { element } = decodeBer(enc);
  assertEquals(decodeOctetStringAsString(element), long);
});

// --- BOOLEAN ---

Deno.test("BER BOOLEAN: true/false のラウンドトリップ", () => {
  for (const v of [true, false]) {
    const enc = encodeBoolean(TAG_BOOLEAN, v);
    const { element } = decodeBer(enc);
    assertEquals(decodeBoolean(element), v);
  }
});

// --- SEQUENCE (constructed) ---

Deno.test("BER SEQUENCE: 複数の子要素を持つ構造のラウンドトリップ", () => {
  const child1 = encodeInteger(TAG_INTEGER, 42);
  const child2 = encodeOctetString(TAG_OCTET_STRING, "hello");
  const seq = encodeConstructed(TAG_SEQUENCE, child1, child2);

  const { element } = decodeBer(seq);
  assertEquals(element.constructed, true);
  assertEquals(element.tag, TAG_SEQUENCE);

  const children = decodeChildren(element);
  assertEquals(children.length, 2);
  assertEquals(decodeInteger(children[0]), 42);
  assertEquals(decodeOctetStringAsString(children[1]), "hello");
});

Deno.test("BER SEQUENCE: ネストした構造", () => {
  const inner = encodeConstructed(
    TAG_SEQUENCE,
    encodeInteger(TAG_INTEGER, 1),
    encodeInteger(TAG_INTEGER, 2),
  );
  const outer = encodeConstructed(TAG_SEQUENCE, inner, encodeOctetString(TAG_OCTET_STRING, "end"));

  const { element } = decodeBer(outer);
  const children = decodeChildren(element);
  assertEquals(children.length, 2);

  const innerChildren = decodeChildren(children[0]);
  assertEquals(innerChildren.length, 2);
  assertEquals(decodeInteger(innerChildren[0]), 1);
  assertEquals(decodeInteger(innerChildren[1]), 2);
});

// --- decodeAll ---

Deno.test("BER decodeAll: 連続した複数要素のデコード", () => {
  const buf = concat(
    encodeInteger(TAG_INTEGER, 10),
    encodeOctetString(TAG_OCTET_STRING, "abc"),
    encodeInteger(TAG_INTEGER, 20),
  );
  const elements = decodeAll(buf);
  assertEquals(elements.length, 3);
  assertEquals(decodeInteger(elements[0]), 10);
  assertEquals(decodeOctetStringAsString(elements[1]), "abc");
  assertEquals(decodeInteger(elements[2]), 20);
});

// --- エラーケース ---

Deno.test("BER decode: バッファ不足でエラー", () => {
  // タグのみ、長さとバリューがない
  const truncated = new Uint8Array([0x04, 0x05, 0x61]); // OCTET STRING 5 bytes but only 1 given
  assertThrows(
    () => decodeBer(truncated),
    Error,
    "exceeds buffer",
  );
});

Deno.test("BER bytesRead: デコードしたバイト数が正確", () => {
  const enc = encodeInteger(TAG_INTEGER, 100);
  const extra = new Uint8Array([0xff, 0xff]); // extra bytes after the element
  const buf = concat(enc, extra);

  const { bytesRead } = decodeBer(buf);
  assertEquals(bytesRead, enc.length);
});
