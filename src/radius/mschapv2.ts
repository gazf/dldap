/**
 * MS-CHAPv2 cryptographic operations (RFC 2759).
 *
 * Uses:
 *   - desEncrypt() from src/samba/hash.ts (already pure TypeScript)
 *   - SHA-1 via Deno's Web Crypto (crypto.subtle.digest)
 */

import { desEcb, str_to_key } from "./des.ts";

// ---------------------------------------------------------------------------
// SHA-1 helper (async, uses Web Crypto)
// ---------------------------------------------------------------------------

async function sha1(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest(
    "SHA-1",
    data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer,
  );
  return new Uint8Array(buf);
}

// ---------------------------------------------------------------------------
// ChallengeHash (RFC 2759 §8.2)
// ChallengeHash = SHA1(PeerChallenge || AuthChallenge || UserName)[0:8]
// ---------------------------------------------------------------------------

export async function challengeHash(
  peerChallenge: Uint8Array,
  authChallenge: Uint8Array,
  userName: string,
): Promise<Uint8Array> {
  const userBytes = new TextEncoder().encode(userName);
  const buf = new Uint8Array(16 + 16 + userBytes.length);
  buf.set(peerChallenge);
  buf.set(authChallenge, 16);
  buf.set(userBytes, 32);
  const hash = await sha1(buf);
  return hash.slice(0, 8);
}

// ---------------------------------------------------------------------------
// ChallengeResponse (RFC 2759 §8.5)
// NTResponse = DES(ChallengeHash, NTHash[0:7])
//            ||DES(ChallengeHash, NTHash[7:14])
//            ||DES(ChallengeHash, NTHash[14:21])  (NTHash padded to 21B)
// ---------------------------------------------------------------------------

export function challengeResponse(
  challengeHash8: Uint8Array,
  ntHash16: Uint8Array,
): Uint8Array {
  // Pad NT hash to 21 bytes
  const padded = new Uint8Array(21);
  padded.set(ntHash16);

  const result = new Uint8Array(24);
  result.set(desEcb(challengeHash8, str_to_key(padded.slice(0, 7))), 0);
  result.set(desEcb(challengeHash8, str_to_key(padded.slice(7, 14))), 8);
  result.set(desEcb(challengeHash8, str_to_key(padded.slice(14, 21))), 16);
  return result;
}

// ---------------------------------------------------------------------------
// Verify NT-Response (server-side)
// ---------------------------------------------------------------------------

export async function verifyNTResponse(
  authChallenge: Uint8Array,
  peerChallenge: Uint8Array,
  userName: string,
  ntHash: Uint8Array,
  receivedNTResponse: Uint8Array,
): Promise<boolean> {
  const ch = await challengeHash(peerChallenge, authChallenge, userName);
  const expected = challengeResponse(ch, ntHash);

  // Timing-safe comparison
  if (expected.length !== receivedNTResponse.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ receivedNTResponse[i];
  return diff === 0;
}

// ---------------------------------------------------------------------------
// GenerateAuthenticatorResponse (RFC 2759 §8.7)
// Returns "S=<hex40>" string for inclusion in EAP-MSCHAPv2 Success message
// ---------------------------------------------------------------------------

// Magic constants from RFC 2759 §8.7
const MAGIC1 = new Uint8Array([
  0x4d,
  0x61,
  0x67,
  0x69,
  0x63,
  0x20,
  0x73,
  0x65,
  0x72,
  0x76,
  0x65,
  0x72,
  0x20,
  0x74,
  0x6f,
  0x20,
  0x63,
  0x6c,
  0x69,
  0x65,
  0x6e,
  0x74,
  0x20,
  0x73,
  0x69,
  0x67,
  0x6e,
  0x69,
  0x6e,
  0x67,
  0x20,
  0x63,
  0x6f,
  0x6e,
  0x73,
  0x74,
  0x61,
  0x6e,
  0x74,
]);

const MAGIC2 = new Uint8Array([
  0x50,
  0x61,
  0x64,
  0x20,
  0x74,
  0x6f,
  0x20,
  0x6d,
  0x61,
  0x6b,
  0x65,
  0x20,
  0x69,
  0x74,
  0x20,
  0x64,
  0x6f,
  0x20,
  0x6d,
  0x6f,
  0x72,
  0x65,
  0x20,
  0x74,
  0x68,
  0x61,
  0x6e,
  0x20,
  0x6f,
  0x6e,
  0x65,
  0x20,
  0x69,
  0x74,
  0x65,
  0x72,
  0x61,
  0x74,
  0x69,
  0x6f,
  0x6e,
]);

export async function generateAuthenticatorResponse(
  ntHash: Uint8Array,
  ntResponse: Uint8Array,
  peerChallenge: Uint8Array,
  authChallenge: Uint8Array,
  userName: string,
): Promise<string> {
  // HashNTPasswordHash
  const ntHashHash = await sha1(ntHash);
  const ntHashHash16 = ntHashHash.slice(0, 16); // only first 16 bytes used

  // Digest1 = SHA1(HashNTPasswordHash || NTResponse || Magic1)
  const d1input = new Uint8Array(16 + 24 + MAGIC1.length);
  d1input.set(ntHashHash16);
  d1input.set(ntResponse, 16);
  d1input.set(MAGIC1, 40);
  const digest1 = await sha1(d1input);

  // ChallengeHash
  const ch = await challengeHash(peerChallenge, authChallenge, userName);

  // Digest2 = SHA1(Digest1 || ChallengeHash || Magic2)
  const d2input = new Uint8Array(20 + 8 + MAGIC2.length);
  d2input.set(digest1);
  d2input.set(ch, 20);
  d2input.set(MAGIC2, 28);
  const digest2 = await sha1(d2input);

  const hex = Array.from(digest2).map((b) => b.toString(16).padStart(2, "0")).join("")
    .toUpperCase();
  return `S=${hex}`;
}

// ---------------------------------------------------------------------------
// MSK derivation (RFC 3079 §3.3 / RFC 2759 §8.7 extension)
// GetMasterKey → GetAsymmetricStartKey → MSK
// ---------------------------------------------------------------------------

const MKEY_MAGIC1 = new Uint8Array([
  0x54,
  0x68,
  0x69,
  0x73,
  0x20,
  0x69,
  0x73,
  0x20,
  0x74,
  0x68,
  0x65,
  0x20,
  0x4d,
  0x50,
  0x50,
  0x45,
  0x20,
  0x4d,
  0x61,
  0x73,
  0x74,
  0x65,
  0x72,
  0x20,
  0x4b,
  0x65,
  0x79,
]);

const MKEY_MAGIC2 = new Uint8Array([
  0x4f,
  0x6e,
  0x20,
  0x74,
  0x68,
  0x65,
  0x20,
  0x63,
  0x6c,
  0x69,
  0x65,
  0x6e,
  0x74,
  0x20,
  0x73,
  0x69,
  0x64,
  0x65,
  0x2c,
  0x20,
  0x74,
  0x68,
  0x69,
  0x73,
  0x20,
  0x69,
  0x73,
  0x20,
  0x74,
  0x68,
  0x65,
  0x20,
  0x73,
  0x65,
  0x6e,
  0x64,
  0x20,
  0x6b,
  0x65,
  0x79,
  0x3b,
  0x20,
  0x6f,
  0x6e,
  0x20,
  0x74,
  0x68,
  0x65,
  0x20,
  0x73,
  0x65,
  0x72,
  0x76,
  0x65,
  0x72,
  0x20,
  0x73,
  0x69,
  0x64,
  0x65,
  0x2c,
  0x20,
  0x69,
  0x74,
  0x20,
  0x69,
  0x73,
  0x20,
  0x74,
  0x68,
  0x65,
  0x20,
  0x72,
  0x65,
  0x63,
  0x65,
  0x69,
  0x76,
  0x65,
  0x20,
  0x6b,
  0x65,
  0x79,
  0x2e,
]);

const MKEY_MAGIC3 = new Uint8Array([
  0x4f,
  0x6e,
  0x20,
  0x74,
  0x68,
  0x65,
  0x20,
  0x63,
  0x6c,
  0x69,
  0x65,
  0x6e,
  0x74,
  0x20,
  0x73,
  0x69,
  0x64,
  0x65,
  0x2c,
  0x20,
  0x74,
  0x68,
  0x69,
  0x73,
  0x20,
  0x69,
  0x73,
  0x20,
  0x74,
  0x68,
  0x65,
  0x20,
  0x72,
  0x65,
  0x63,
  0x65,
  0x69,
  0x76,
  0x65,
  0x20,
  0x6b,
  0x65,
  0x79,
  0x3b,
  0x20,
  0x6f,
  0x6e,
  0x20,
  0x74,
  0x68,
  0x65,
  0x20,
  0x73,
  0x65,
  0x72,
  0x76,
  0x65,
  0x72,
  0x20,
  0x73,
  0x69,
  0x64,
  0x65,
  0x2c,
  0x20,
  0x69,
  0x74,
  0x20,
  0x69,
  0x73,
  0x20,
  0x74,
  0x68,
  0x65,
  0x20,
  0x73,
  0x65,
  0x6e,
  0x64,
  0x20,
  0x6b,
  0x65,
  0x79,
  0x2e,
]);

const SHS_PAD1 = new Uint8Array(40).fill(0x00);
const SHS_PAD2 = new Uint8Array(40).fill(0xf2);

async function getMasterKey(
  ntHash: Uint8Array,
  ntResponse: Uint8Array,
): Promise<Uint8Array> {
  // HashNTPasswordHash (SHA1 of NT hash, take first 16 bytes)
  const ntHashHash = (await sha1(ntHash)).slice(0, 16);

  const buf = new Uint8Array(16 + 24 + MKEY_MAGIC1.length);
  buf.set(ntHashHash);
  buf.set(ntResponse, 16);
  buf.set(MKEY_MAGIC1, 40);
  const masterKey = await sha1(buf);
  return masterKey.slice(0, 16);
}

async function getAsymmetricStartKey(
  masterKey: Uint8Array,
  magic: Uint8Array,
): Promise<Uint8Array> {
  const buf = new Uint8Array(16 + 40 + magic.length + 40);
  buf.set(masterKey);
  buf.set(SHS_PAD1, 16);
  buf.set(magic, 56);
  buf.set(SHS_PAD2, 56 + magic.length);
  const hash = await sha1(buf);
  return hash.slice(0, 16);
}

/**
 * Derive the 32-byte MSK (Master Session Key) for EAP-MSCHAPv2.
 * MSK = SendKey (16B) || RecvKey (16B)
 * From the RADIUS server's perspective:
 *   SendKey = server send = client recv  → use MKEY_MAGIC3
 *   RecvKey = server recv = client send  → use MKEY_MAGIC2
 */
export async function deriveMSK(
  ntHash: Uint8Array,
  ntResponse: Uint8Array,
): Promise<Uint8Array> {
  const masterKey = await getMasterKey(ntHash, ntResponse);
  const sendKey = await getAsymmetricStartKey(masterKey, MKEY_MAGIC3);
  const recvKey = await getAsymmetricStartKey(masterKey, MKEY_MAGIC2);
  const msk = new Uint8Array(32);
  msk.set(sendKey);
  msk.set(recvKey, 16);
  return msk;
}
