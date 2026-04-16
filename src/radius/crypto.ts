/**
 * RADIUS cryptographic primitives (RFC 2865, RFC 2548).
 *
 * - md5(): pure TypeScript MD5 (RFC 1321) — Web Crypto does not expose MD5
 * - hmacMd5(): HMAC-MD5 for Message-Authenticator (attr 80)
 * - decryptPapPassword(): PAP User-Password decryption
 * - computeResponseAuthenticator(): RADIUS response authenticator
 * - verifyMessageAuthenticator(): validate Message-Authenticator
 * - encryptMppeKey(): MS-MPPE-Send/Recv-Key encryption (RFC 2548 §2.4)
 */

// ---------------------------------------------------------------------------
// MD5 (RFC 1321) — pure TypeScript
// ---------------------------------------------------------------------------

// Per-round constants T[i] = floor(abs(sin(i+1)) * 2^32)
const MD5_T = new Uint32Array([
  0xd76aa478,
  0xe8c7b756,
  0x242070db,
  0xc1bdceee,
  0xf57c0faf,
  0x4787c62a,
  0xa8304613,
  0xfd469501,
  0x698098d8,
  0x8b44f7af,
  0xffff5bb1,
  0x895cd7be,
  0x6b901122,
  0xfd987193,
  0xa679438e,
  0x49b40821,
  0xf61e2562,
  0xc040b340,
  0x265e5a51,
  0xe9b6c7aa,
  0xd62f105d,
  0x02441453,
  0xd8a1e681,
  0xe7d3fbc8,
  0x21e1cde6,
  0xc33707d6,
  0xf4d50d87,
  0x455a14ed,
  0xa9e3e905,
  0xfcefa3f8,
  0x676f02d9,
  0x8d2a4c8a,
  0xfffa3942,
  0x8771f681,
  0x6d9d6122,
  0xfde5380c,
  0xa4beea44,
  0x4bdecfa9,
  0xf6bb4b60,
  0xbebfbc70,
  0x289b7ec6,
  0xeaa127fa,
  0xd4ef3085,
  0x04881d05,
  0xd9d4d039,
  0xe6db99e5,
  0x1fa27cf8,
  0xc4ac5665,
  0xf4292244,
  0x432aff97,
  0xab9423a7,
  0xfc93a039,
  0x655b59c3,
  0x8f0ccc92,
  0xffeff47d,
  0x85845dd1,
  0x6fa87e4f,
  0xfe2ce6e0,
  0xa3014314,
  0x4e0811a1,
  0xf7537e82,
  0xbd3af235,
  0x2ad7d2bb,
  0xeb86d391,
]);

// Per-round left-shift amounts
const MD5_S = new Uint8Array([
  7,
  12,
  17,
  22,
  7,
  12,
  17,
  22,
  7,
  12,
  17,
  22,
  7,
  12,
  17,
  22,
  5,
  9,
  14,
  20,
  5,
  9,
  14,
  20,
  5,
  9,
  14,
  20,
  5,
  9,
  14,
  20,
  4,
  11,
  16,
  23,
  4,
  11,
  16,
  23,
  4,
  11,
  16,
  23,
  4,
  11,
  16,
  23,
  6,
  10,
  15,
  21,
  6,
  10,
  15,
  21,
  6,
  10,
  15,
  21,
  6,
  10,
  15,
  21,
]);

function rotl32(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

export function md5(input: Uint8Array): Uint8Array {
  // Pad message: append 0x80, zero-fill to 56 mod 64, then 64-bit LE bit-length
  const msgLen = input.length;
  const bitLen = msgLen * 8;
  const padLen = (msgLen % 64) < 56 ? 56 - (msgLen % 64) : 120 - (msgLen % 64);
  const buf = new Uint8Array(msgLen + padLen + 8);
  buf.set(input);
  buf[msgLen] = 0x80;
  // Write 64-bit little-endian bit length (lower 32 bits only; upper is 0 for sane inputs)
  const dv = new DataView(buf.buffer);
  dv.setUint32(msgLen + padLen, bitLen >>> 0, true);
  dv.setUint32(msgLen + padLen + 4, Math.floor(bitLen / 0x100000000) >>> 0, true);

  // Initial hash state
  let a0 = 0x67452301 >>> 0;
  let b0 = 0xefcdab89 >>> 0;
  let c0 = 0x98badcfe >>> 0;
  let d0 = 0x10325476 >>> 0;

  // Process 512-bit (64-byte) blocks
  for (let off = 0; off < buf.length; off += 64) {
    const M = new Uint32Array(16);
    for (let i = 0; i < 16; i++) {
      M[i] = dv.getUint32(off + i * 4, true);
    }

    let A = a0, B = b0, C = c0, D = d0;

    for (let i = 0; i < 64; i++) {
      let F: number, g: number;
      if (i < 16) {
        F = ((B & C) | (~B & D)) >>> 0;
        g = i;
      } else if (i < 32) {
        F = ((D & B) | (~D & C)) >>> 0;
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        F = (B ^ C ^ D) >>> 0;
        g = (3 * i + 5) % 16;
      } else {
        F = (C ^ (B | ~D)) >>> 0;
        g = (7 * i) % 16;
      }
      F = (F + A + MD5_T[i] + M[g]) >>> 0;
      A = D;
      D = C;
      C = B;
      B = (B + rotl32(F, MD5_S[i])) >>> 0;
    }

    a0 = (a0 + A) >>> 0;
    b0 = (b0 + B) >>> 0;
    c0 = (c0 + C) >>> 0;
    d0 = (d0 + D) >>> 0;
  }

  const out = new Uint8Array(16);
  const outDv = new DataView(out.buffer);
  outDv.setUint32(0, a0, true);
  outDv.setUint32(4, b0, true);
  outDv.setUint32(8, c0, true);
  outDv.setUint32(12, d0, true);
  return out;
}

// ---------------------------------------------------------------------------
// HMAC-MD5 (RFC 2104)
// ---------------------------------------------------------------------------

export function hmacMd5(key: Uint8Array, data: Uint8Array): Uint8Array {
  const k = key.length > 64 ? md5(key) : key;
  const kPadded = new Uint8Array(64);
  kPadded.set(k);
  const ipad = kPadded.map((b) => b ^ 0x36);
  const opad = kPadded.map((b) => b ^ 0x5c);

  const inner = new Uint8Array(64 + data.length);
  inner.set(ipad);
  inner.set(data, 64);

  const outer = new Uint8Array(64 + 16);
  outer.set(opad);
  outer.set(md5(inner), 64);

  return md5(outer);
}

// ---------------------------------------------------------------------------
// Timing-safe byte comparison
// ---------------------------------------------------------------------------

export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---------------------------------------------------------------------------
// PAP User-Password decryption (RFC 2865 §5.2)
// ---------------------------------------------------------------------------

export function decryptPapPassword(
  ciphertext: Uint8Array,
  secret: Uint8Array,
  requestAuth: Uint8Array,
): string {
  const result = new Uint8Array(ciphertext.length);
  let prev = requestAuth;

  for (let i = 0; i < ciphertext.length; i += 16) {
    const seed = new Uint8Array(secret.length + prev.length);
    seed.set(secret);
    seed.set(prev, secret.length);
    const hash = md5(seed);
    for (let j = 0; j < 16 && i + j < ciphertext.length; j++) {
      result[i + j] = ciphertext[i + j] ^ hash[j];
    }
    prev = ciphertext.slice(i, i + 16);
  }

  // Strip trailing NUL padding
  let end = result.length;
  while (end > 0 && result[end - 1] === 0) end--;
  return new TextDecoder().decode(result.slice(0, end));
}

// ---------------------------------------------------------------------------
// RADIUS Response Authenticator (RFC 2865 §3)
// ---------------------------------------------------------------------------

export function computeResponseAuthenticator(
  code: number,
  id: number,
  length: number,
  requestAuth: Uint8Array,
  responseAttrs: Uint8Array,
  secret: Uint8Array,
): Uint8Array {
  const buf = new Uint8Array(4 + 16 + responseAttrs.length + secret.length);
  buf[0] = code;
  buf[1] = id;
  buf[2] = (length >>> 8) & 0xff;
  buf[3] = length & 0xff;
  buf.set(requestAuth, 4);
  buf.set(responseAttrs, 20);
  buf.set(secret, 20 + responseAttrs.length);
  return md5(buf);
}

// ---------------------------------------------------------------------------
// Message-Authenticator (RFC 3579 §3.2, attr 80)
// ---------------------------------------------------------------------------

/**
 * Verify the Message-Authenticator attribute in an Access-Request.
 * The 16-byte value of attr 80 is replaced with zeros before computing
 * HMAC-MD5(secret, packet).
 */
export function verifyMessageAuthenticator(
  packet: Uint8Array,
  secret: Uint8Array,
): boolean {
  // Find attr 80 offset in the attribute area (starts at byte 20)
  let off = 20;
  let attrOffset = -1;
  while (off + 2 <= packet.length) {
    const type = packet[off];
    const len = packet[off + 1];
    if (len < 2 || off + len > packet.length) break;
    if (type === 80 && len === 18) {
      attrOffset = off + 2;
      break;
    }
    off += len;
  }
  if (attrOffset < 0) return true; // attr 80 not present — nothing to verify

  const received = packet.slice(attrOffset, attrOffset + 16);

  // Zero out the Message-Authenticator value in a copy
  const zeroed = new Uint8Array(packet);
  zeroed.fill(0, attrOffset, attrOffset + 16);

  const computed = hmacMd5(secret, zeroed);
  return timingSafeEqual(computed, received);
}

/**
 * Compute Message-Authenticator over a packet that already has the
 * Response Authenticator in place. The 16-byte placeholder for attr 80
 * must already be zeros in `packet`.
 */
export function computeMessageAuthenticator(
  packet: Uint8Array,
  secret: Uint8Array,
): Uint8Array {
  return hmacMd5(secret, packet);
}

// ---------------------------------------------------------------------------
// MS-MPPE key encryption (RFC 2548 §2.4)
// ---------------------------------------------------------------------------

/**
 * Encrypt a 16-byte key for use in MS-MPPE-Send-Key / MS-MPPE-Recv-Key VSA.
 *
 * Wire format (after vendor-specific header):
 *   Salt (2 bytes, high bit set) || Encrypted-Key (32 bytes)
 *
 * The 16-byte plaintext key is padded to 32 bytes (16 zero bytes appended),
 * then XOR'd with MD5 chains using the RADIUS secret + request authenticator.
 */
export function encryptMppeKey(
  key16: Uint8Array,
  requestAuth: Uint8Array,
  secret: Uint8Array,
): Uint8Array {
  // Random 2-byte salt with high bit set (RFC 2548 §2.4.2)
  const salt = new Uint8Array(2);
  crypto.getRandomValues(salt);
  salt[0] |= 0x80;

  // Plaintext: 1-byte length (16) + 16-byte key + zero padding to 32 bytes
  const plain = new Uint8Array(32);
  plain[0] = 16;
  plain.set(key16, 1);
  // remaining bytes are already 0

  // Encrypt in two 16-byte blocks
  const cipher = new Uint8Array(32);

  // Block 0: MD5(secret || requestAuth || salt)
  const seed0 = new Uint8Array(secret.length + 16 + 2);
  seed0.set(secret);
  seed0.set(requestAuth, secret.length);
  seed0.set(salt, secret.length + 16);
  const hash0 = md5(seed0);
  for (let i = 0; i < 16; i++) cipher[i] = plain[i] ^ hash0[i];

  // Block 1: MD5(secret || cipher[0..15])
  const seed1 = new Uint8Array(secret.length + 16);
  seed1.set(secret);
  seed1.set(cipher.slice(0, 16), secret.length);
  const hash1 = md5(seed1);
  for (let i = 0; i < 16; i++) cipher[16 + i] = plain[16 + i] ^ hash1[i];

  // Return: salt (2B) + ciphertext (32B)
  const out = new Uint8Array(34);
  out.set(salt);
  out.set(cipher, 2);
  return out;
}
