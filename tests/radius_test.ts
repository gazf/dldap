/**
 * Tests for RADIUS protocol implementation.
 *
 * Covers:
 *   - MD5 (RFC 1321 test vectors)
 *   - PAP password decryption
 *   - MSCHAPv2 ChallengeHash / ChallengeResponse (RFC 2759 §9.2 test vector)
 *   - RADIUS packet parse/encode round-trip
 */

import { assertEquals } from "jsr:@std/assert";
import { md5, decryptPapPassword, hmacMd5 } from "../src/radius/crypto.ts";
import { challengeHash, challengeResponse, verifyNTResponse } from "../src/radius/mschapv2.ts";
import { parsePacket, encodePacket } from "../src/radius/packet.ts";
import { RadiusCode, Attr } from "../src/radius/constants.ts";
import { desEcb, str_to_key } from "../src/radius/des.ts";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fromHex(h: string): Uint8Array {
  h = h.replace(/\s+/g, "");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toHex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// MD5 — RFC 1321 §A.5 test vectors
// ---------------------------------------------------------------------------

Deno.test("MD5: empty string", () => {
  const result = toHex(md5(new Uint8Array(0)));
  assertEquals(result, "d41d8cd98f00b204e9800998ecf8427e");
});

Deno.test('MD5: "a"', () => {
  const result = toHex(md5(new TextEncoder().encode("a")));
  assertEquals(result, "0cc175b9c0f1b6a831c399e269772661");
});

Deno.test('MD5: "abc"', () => {
  const result = toHex(md5(new TextEncoder().encode("abc")));
  assertEquals(result, "900150983cd24fb0d6963f7d28e17f72");
});

Deno.test('MD5: "message digest"', () => {
  const result = toHex(md5(new TextEncoder().encode("message digest")));
  assertEquals(result, "f96b697d7cb7938d525a2f31aaf161d0");
});

Deno.test('MD5: "The quick brown fox..."', () => {
  const result = toHex(
    md5(new TextEncoder().encode("The quick brown fox jumps over the lazy dog")),
  );
  assertEquals(result, "9e107d9d372bb6826bd81d3542a419d6");
});

// ---------------------------------------------------------------------------
// PAP password decryption round-trip
// ---------------------------------------------------------------------------

Deno.test("PAP: encrypt and decrypt password", () => {
  const secret = new TextEncoder().encode("mysecret");
  const requestAuth = new Uint8Array(16);
  crypto.getRandomValues(requestAuth);
  const password = "testpassword";

  // Encrypt (simulating client behavior)
  const padLen = Math.ceil(password.length / 16) * 16;
  const plain = new Uint8Array(padLen);
  new TextEncoder().encodeInto(password, plain);

  const cipher = new Uint8Array(padLen);
  let prev = requestAuth;
  for (let i = 0; i < padLen; i += 16) {
    const seed = new Uint8Array(secret.length + prev.length);
    seed.set(secret);
    seed.set(prev, secret.length);
    const hash = md5(seed);
    for (let j = 0; j < 16; j++) cipher[i + j] = plain[i + j] ^ hash[j];
    prev = cipher.slice(i, i + 16);
  }

  const decrypted = decryptPapPassword(cipher, secret, requestAuth);
  assertEquals(decrypted, password);
});

// Simpler PAP test with known values
Deno.test("PAP: decrypt known ciphertext", () => {
  // Derived manually: secret="secret", requestAuth=all zeros, password="password"
  const secret = new TextEncoder().encode("secret");
  const requestAuth = new Uint8Array(16); // all zeros
  const password = "password";

  // Encrypt
  const plain = new Uint8Array(16);
  new TextEncoder().encodeInto(password, plain);
  const seed = new Uint8Array(secret.length + 16);
  seed.set(secret);
  seed.set(requestAuth, secret.length);
  const hash = md5(seed);
  const cipher = plain.map((b, i) => b ^ hash[i]);

  const decrypted = decryptPapPassword(cipher, secret, requestAuth);
  assertEquals(decrypted, password);
});

// ---------------------------------------------------------------------------
// DES ECB — known test vectors
// ---------------------------------------------------------------------------

Deno.test("DES ECB: Schneier test vector (key=133457799BBCDFF1)", () => {
  // From Schneier "Applied Cryptography" Appendix B:
  // Key = 133457799BBCDFF1, Plaintext = 0123456789ABCDEF → 85E813540F0AB405
  const key = fromHex("133457799BBCDFF1");
  const pt  = fromHex("0123456789ABCDEF");
  const ct  = desEcb(pt, key);
  assertEquals(toHex(ct), "85e813540f0ab405");
});

Deno.test("DES ECB: RFC 2759 Block 0 (str_to_key)", () => {
  // str_to_key(44 EB BA 8D 53 12 B8) then DES with challenge D02E4386BCE91226
  const key7 = fromHex("44EBBA8D5312B8");
  const pt   = fromHex("D02E4386BCE91226");
  const ct   = desEcb(pt, str_to_key(key7));
  assertEquals(toHex(ct), "82309ecd8d708b5e");
});

Deno.test("str_to_key: RFC 2759 Block 1 key expansion", () => {
  // Verify str_to_key(D6 11 47 44 11 F5 69) = D6 08 50 E8 40 8E D4 D2
  const key7 = fromHex("D61147441 1F569".replace(/\s/g, ""));
  const key8 = str_to_key(key7);
  assertEquals(toHex(key8), "d60850e8408ed4d2");
});

Deno.test("DES ECB: raw key D60850E8408ED4D2", () => {
  // Direct DES without str_to_key, to isolate whether DES or str_to_key is wrong
  const key = fromHex("D60850E8408ED4D2");
  const pt  = fromHex("D02E4386BCE91226");
  const ct  = desEcb(pt, key);
  assertEquals(toHex(ct), "a08faa3953e14023");
});

Deno.test("DES ECB: RFC 2759 Block 1 (str_to_key)", () => {
  // str_to_key(D6 11 47 44 11 F5 69) then DES with challenge D02E4386BCE91226
  const key7 = fromHex("D61147441 1F569".replace(/\s/g, ""));
  const pt   = fromHex("D02E4386BCE91226");
  const ct   = desEcb(pt, str_to_key(key7));
  assertEquals(toHex(ct), "a08faa3953e14023");
});

// ---------------------------------------------------------------------------
// MSCHAPv2 — RFC 2759 §9.2 test vector
// ---------------------------------------------------------------------------

// From RFC 2759 §9.2:
// UserName = "User"
// UserPassword = "clientPass"
// AuthenticatorChallenge = 5B 5D 7C 7D 7B 3F 2F 3E 3C 2C 60 21 32 26 26 28
// PeerChallenge =          21 40 23 24 25 5E 26 2A 28 29 5F 2B 3A 33 7C 7E
// NT-Response (expected) = 82 30 9E CD 8D 70 8B 5E A0 8F AA 39 53 E1 40 23
//                          68 47 29 9F 5F 14 D2 05

Deno.test("MSCHAPv2: ChallengeHash matches RFC 2759 §9.2", async () => {
  const authChallenge = fromHex("5B5D7C7D7B3F2F3E3C2C60213226 2628".replace(/\s/g, ""));
  const peerChallenge = fromHex("21402324255E262A28295F2B3A337C7E");
  // RFC 2759 §9.2 ChallengeHash = D0 2E 43 86 BC E9 12 26
  const expected = fromHex("D02E4386BCE91226");

  const result = await challengeHash(peerChallenge, authChallenge, "User");
  assertEquals(toHex(result), toHex(expected));
});

Deno.test("MSCHAPv2: NT-Response matches RFC 2759 §9.2", async () => {
  const authChallenge = fromHex("5B5D7C7D7B3F2F3E3C2C602132262628");
  const peerChallenge = fromHex("21402324255E262A28295F2B3A337C7E");
  const userName = "User";
  // NT hash of "clientPass" = MD4(UTF-16LE("clientPass"))
  // = 44 EB BA 8D 53 12 B8 D6 11 47 44 11 F5 69 89 AE
  const ntHash = fromHex("44EBBA8D5312B8D611474411F56989AE");

  const ch = await challengeHash(peerChallenge, authChallenge, userName);
  const ntResponse = challengeResponse(ch, ntHash);

  // Expected from RFC 2759 §9.2
  const expected = fromHex("82309ECD8D708B5EA08FAA3953E140236847299F5F14D205");
  assertEquals(toHex(ntResponse), toHex(expected));
});

Deno.test("MSCHAPv2: verifyNTResponse accepts correct response", async () => {
  const authChallenge = fromHex("5B5D7C7D7B3F2F3E3C2C602132262628");
  const peerChallenge = fromHex("21402324255E262A28295F2B3A337C7E");
  const ntHash = fromHex("44EBBA8D5312B8D611474411F56989AE");
  const ntResponse = fromHex("82309ECD8D708B5EA08FAA3953E140236847299F5F14D205");

  const ok = await verifyNTResponse(authChallenge, peerChallenge, "User", ntHash, ntResponse);
  assertEquals(ok, true);
});

Deno.test("MSCHAPv2: verifyNTResponse rejects wrong response", async () => {
  const authChallenge = fromHex("5B5D7C7D7B3F2F3E3C2C602132262628");
  const peerChallenge = fromHex("21402324255E262A28295F2B3A337C7E");
  const ntHash = fromHex("44EBBA8D5312B8D611474411F56989AE");
  const wrongResponse = new Uint8Array(24); // all zeros

  const ok = await verifyNTResponse(authChallenge, peerChallenge, "User", ntHash, wrongResponse);
  assertEquals(ok, false);
});

// ---------------------------------------------------------------------------
// RADIUS packet round-trip
// ---------------------------------------------------------------------------

Deno.test("RADIUS packet: parse/encode round-trip", () => {
  // Minimal Access-Request with User-Name
  const userName = new TextEncoder().encode("alice");
  const attrLen = 2 + userName.length;
  const totalLen = 20 + attrLen;

  const buf = new Uint8Array(totalLen);
  buf[0] = RadiusCode.AccessRequest;
  buf[1] = 42; // identifier
  buf[2] = (totalLen >>> 8) & 0xff;
  buf[3] = totalLen & 0xff;
  // authenticator: all zeros (bytes 4..19)
  buf[20] = Attr.UserName;
  buf[21] = attrLen;
  buf.set(userName, 22);

  const pkt = parsePacket(buf);
  assertEquals(pkt.code, RadiusCode.AccessRequest);
  assertEquals(pkt.identifier, 42);
  assertEquals(pkt.attributes.length, 1);
  assertEquals(pkt.attributes[0].type, Attr.UserName);
  assertEquals(new TextDecoder().decode(pkt.attributes[0].value), "alice");

  // Re-encode and compare
  const encoded = encodePacket(pkt);
  assertEquals(toHex(encoded), toHex(buf));
});

Deno.test("RADIUS packet: Access-Reject with ReplyMessage", () => {
  const reply = new TextEncoder().encode("Bad password");
  const pkt = {
    code: RadiusCode.AccessReject,
    identifier: 7,
    authenticator: new Uint8Array(16),
    attributes: [{ type: Attr.ReplyMessage, value: reply }],
  };
  const encoded = encodePacket(pkt);
  const parsed = parsePacket(encoded);
  assertEquals(parsed.code, RadiusCode.AccessReject);
  assertEquals(parsed.identifier, 7);
  assertEquals(new TextDecoder().decode(parsed.attributes[0].value), "Bad password");
});
