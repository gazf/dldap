/**
 * NT hash (MD4 of UTF-16LE password) and LM hash generation for Samba.
 *
 * MD4 is implemented in pure TypeScript because it is not available
 * in the Web Crypto API.
 */

// ---------------------------------------------------------------------------
// MD4 implementation (RFC 1320)
// ---------------------------------------------------------------------------

function F(x: number, y: number, z: number): number {
  return (x & y) | (~x & z);
}
function G(x: number, y: number, z: number): number {
  return (x & y) | (x & z) | (y & z);
}
function H(x: number, y: number, z: number): number {
  return x ^ y ^ z;
}
function rotl(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

/** Compute MD4 hash of a Uint8Array. Returns a 16-byte Uint8Array. */
export function md4(input: Uint8Array): Uint8Array {
  // Pad the message (same as MD5 padding)
  const msgLen = input.length;
  const bitLen = msgLen * 8;

  // Padding: append 0x80, then zeros, then 64-bit LE length
  const padLen = ((msgLen + 8) & ~63) + 56 - msgLen;
  const padded = new Uint8Array(msgLen + padLen + 8);
  padded.set(input);
  padded[msgLen] = 0x80;
  // Append bit length as 64-bit LE
  const view = new DataView(padded.buffer);
  view.setUint32(msgLen + padLen, bitLen & 0xffffffff, true);
  view.setUint32(msgLen + padLen + 4, Math.floor(bitLen / 0x100000000), true);

  // Initialize state
  let a = 0x67452301;
  let b = 0xefcdab89;
  let c = 0x98badcfe;
  let d = 0x10325476;

  // Process each 512-bit (64-byte) block
  for (let i = 0; i < padded.length; i += 64) {
    const X: number[] = [];
    for (let j = 0; j < 16; j++) {
      X[j] = view.getUint32(i + j * 4, true);
    }

    const aa = a, bb = b, cc = c, dd = d;

    // Round 1
    const s1 = [3, 7, 11, 19];
    for (let j = 0; j < 16; j++) {
      const k = j;
      const s = s1[j % 4];
      a = rotl((a + F(b, c, d) + X[k]) >>> 0, s);
      [a, b, c, d] = [d, a, b, c];
    }

    // Round 2
    const s2 = [3, 5, 9, 13];
    const order2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
    for (let j = 0; j < 16; j++) {
      const k = order2[j];
      const s = s2[j % 4];
      a = rotl((a + G(b, c, d) + X[k] + 0x5a827999) >>> 0, s);
      [a, b, c, d] = [d, a, b, c];
    }

    // Round 3
    const s3 = [3, 9, 11, 15];
    const order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
    for (let j = 0; j < 16; j++) {
      const k = order3[j];
      const s = s3[j % 4];
      a = rotl((a + H(b, c, d) + X[k] + 0x6ed9eba1) >>> 0, s);
      [a, b, c, d] = [d, a, b, c];
    }

    a = (a + aa) >>> 0;
    b = (b + bb) >>> 0;
    c = (c + cc) >>> 0;
    d = (d + dd) >>> 0;
  }

  const result = new Uint8Array(16);
  const rv = new DataView(result.buffer);
  rv.setUint32(0, a, true);
  rv.setUint32(4, b, true);
  rv.setUint32(8, c, true);
  rv.setUint32(12, d, true);
  return result;
}

// ---------------------------------------------------------------------------
// NT hash
// ---------------------------------------------------------------------------

/**
 * Compute the NT hash (sambaNTPassword) for a plaintext password.
 * Returns uppercase hex string (32 chars).
 */
export function ntHash(password: string): string {
  // Encode as UTF-16LE
  const utf16 = new Uint8Array(password.length * 2);
  for (let i = 0; i < password.length; i++) {
    const code = password.charCodeAt(i);
    utf16[i * 2] = code & 0xff;
    utf16[i * 2 + 1] = (code >> 8) & 0xff;
  }
  const hash = md4(utf16);
  return Array.from(hash)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

// ---------------------------------------------------------------------------
// LM hash (deprecated — insecure, provided only for legacy compatibility)
// ---------------------------------------------------------------------------

/** Expand 7-byte LM key to 8-byte DES key (inserting parity bits). */
function expandLMKey(key7: Uint8Array): Uint8Array {
  // Split 56-bit key into eight 7-bit groups, place each in bits 7-1 of an
  // output byte (LSB = parity bit = 0). Follows Samba's str_to_key().
  const s = key7;
  return new Uint8Array([
    (s[0] >> 1) << 1,
    (((s[0] & 0x01) << 6) | (s[1] >> 2)) << 1,
    (((s[1] & 0x03) << 5) | (s[2] >> 3)) << 1,
    (((s[2] & 0x07) << 4) | (s[3] >> 4)) << 1,
    (((s[3] & 0x0f) << 3) | (s[4] >> 5)) << 1,
    (((s[4] & 0x1f) << 2) | (s[5] >> 6)) << 1,
    (((s[5] & 0x3f) << 1) | (s[6] >> 7)) << 1,
    (s[6] & 0x7f) << 1,
  ]);
}

// DES tables for LM hash
const DES_PC1 = [
  57,
  49,
  41,
  33,
  25,
  17,
  9,
  1,
  58,
  50,
  42,
  34,
  26,
  18,
  10,
  2,
  59,
  51,
  43,
  35,
  27,
  19,
  11,
  3,
  60,
  52,
  44,
  36,
  63,
  55,
  47,
  39,
  31,
  23,
  15,
  7,
  62,
  54,
  46,
  38,
  30,
  22,
  14,
  6,
  61,
  53,
  45,
  37,
  29,
  21,
  13,
  5,
  28,
  20,
  12,
  4,
];
const DES_PC2 = [
  14,
  17,
  11,
  24,
  1,
  5,
  3,
  28,
  15,
  6,
  21,
  10,
  23,
  19,
  12,
  4,
  26,
  8,
  16,
  7,
  27,
  20,
  13,
  2,
  41,
  52,
  31,
  37,
  47,
  55,
  30,
  40,
  51,
  45,
  33,
  48,
  44,
  49,
  39,
  56,
  34,
  53,
  46,
  42,
  50,
  36,
  29,
  32,
];
const DES_IP = [
  58,
  50,
  42,
  34,
  26,
  18,
  10,
  2,
  60,
  52,
  44,
  36,
  28,
  20,
  12,
  4,
  62,
  54,
  46,
  38,
  30,
  22,
  14,
  6,
  64,
  56,
  48,
  40,
  32,
  24,
  16,
  8,
  57,
  49,
  41,
  33,
  25,
  17,
  9,
  1,
  59,
  51,
  43,
  35,
  27,
  19,
  11,
  3,
  61,
  53,
  45,
  37,
  29,
  21,
  13,
  5,
  63,
  55,
  47,
  39,
  31,
  23,
  15,
  7,
];
const DES_FP = [
  40,
  8,
  48,
  16,
  56,
  24,
  64,
  32,
  39,
  7,
  47,
  15,
  55,
  23,
  63,
  31,
  38,
  6,
  46,
  14,
  54,
  22,
  62,
  30,
  37,
  5,
  45,
  13,
  53,
  21,
  61,
  29,
  36,
  4,
  44,
  12,
  52,
  20,
  60,
  28,
  35,
  3,
  43,
  11,
  51,
  19,
  59,
  27,
  34,
  2,
  42,
  10,
  50,
  18,
  58,
  26,
  33,
  1,
  41,
  9,
  49,
  17,
  57,
  25,
];
const DES_E = [
  32,
  1,
  2,
  3,
  4,
  5,
  4,
  5,
  6,
  7,
  8,
  9,
  8,
  9,
  10,
  11,
  12,
  13,
  12,
  13,
  14,
  15,
  16,
  17,
  16,
  17,
  18,
  19,
  20,
  21,
  20,
  21,
  22,
  23,
  24,
  25,
  24,
  25,
  26,
  27,
  28,
  29,
  28,
  29,
  30,
  31,
  32,
  1,
];
const DES_P = [
  16,
  7,
  20,
  21,
  29,
  12,
  28,
  17,
  1,
  15,
  23,
  26,
  5,
  18,
  31,
  10,
  2,
  8,
  24,
  14,
  32,
  27,
  3,
  9,
  19,
  13,
  30,
  6,
  22,
  11,
  4,
  25,
];
const DES_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
// prettier-ignore
const DES_S: number[][] = [
  [
    14,
    4,
    13,
    1,
    2,
    15,
    11,
    8,
    3,
    10,
    6,
    12,
    5,
    9,
    0,
    7,
    0,
    15,
    7,
    4,
    14,
    2,
    13,
    1,
    10,
    6,
    12,
    11,
    9,
    5,
    3,
    8,
    4,
    1,
    14,
    8,
    13,
    6,
    2,
    11,
    15,
    12,
    9,
    7,
    3,
    10,
    5,
    0,
    15,
    12,
    8,
    2,
    4,
    9,
    1,
    7,
    5,
    11,
    3,
    14,
    10,
    0,
    6,
    13,
  ],
  [
    15,
    1,
    8,
    14,
    6,
    11,
    3,
    4,
    9,
    7,
    2,
    13,
    12,
    0,
    5,
    10,
    3,
    13,
    4,
    7,
    15,
    2,
    8,
    14,
    12,
    0,
    1,
    10,
    6,
    9,
    11,
    5,
    0,
    14,
    7,
    11,
    10,
    4,
    13,
    1,
    5,
    8,
    12,
    6,
    9,
    3,
    2,
    15,
    13,
    8,
    10,
    1,
    3,
    15,
    4,
    2,
    11,
    6,
    7,
    12,
    0,
    5,
    14,
    9,
  ],
  [
    10,
    0,
    9,
    14,
    6,
    3,
    15,
    5,
    1,
    13,
    12,
    7,
    11,
    4,
    2,
    8,
    13,
    7,
    0,
    9,
    3,
    4,
    6,
    10,
    2,
    8,
    5,
    14,
    12,
    11,
    15,
    1,
    13,
    6,
    4,
    9,
    8,
    15,
    3,
    0,
    11,
    1,
    2,
    12,
    5,
    10,
    14,
    7,
    1,
    10,
    13,
    0,
    6,
    9,
    8,
    7,
    4,
    15,
    14,
    3,
    11,
    5,
    2,
    12,
  ],
  [
    7,
    13,
    14,
    3,
    0,
    6,
    9,
    10,
    1,
    2,
    8,
    5,
    11,
    12,
    4,
    15,
    13,
    8,
    11,
    5,
    6,
    15,
    0,
    3,
    4,
    7,
    2,
    12,
    1,
    10,
    14,
    9,
    10,
    6,
    9,
    0,
    12,
    11,
    7,
    13,
    15,
    1,
    3,
    14,
    5,
    2,
    8,
    4,
    3,
    15,
    0,
    6,
    10,
    1,
    13,
    8,
    9,
    4,
    5,
    11,
    12,
    7,
    2,
    14,
  ],
  [
    2,
    12,
    4,
    1,
    7,
    10,
    11,
    6,
    8,
    5,
    3,
    15,
    13,
    0,
    14,
    9,
    14,
    11,
    2,
    12,
    4,
    7,
    13,
    1,
    5,
    0,
    15,
    10,
    3,
    9,
    8,
    6,
    4,
    2,
    1,
    11,
    10,
    13,
    7,
    8,
    15,
    9,
    12,
    5,
    6,
    3,
    0,
    14,
    11,
    8,
    12,
    7,
    1,
    14,
    2,
    13,
    6,
    15,
    0,
    9,
    10,
    4,
    5,
    3,
  ],
  [
    12,
    1,
    10,
    15,
    9,
    2,
    6,
    8,
    0,
    13,
    3,
    4,
    14,
    7,
    5,
    11,
    10,
    15,
    4,
    2,
    7,
    12,
    9,
    5,
    6,
    1,
    13,
    14,
    0,
    11,
    3,
    8,
    9,
    14,
    15,
    5,
    2,
    8,
    12,
    3,
    7,
    0,
    4,
    10,
    1,
    13,
    11,
    6,
    4,
    3,
    2,
    12,
    9,
    5,
    15,
    10,
    11,
    14,
    1,
    7,
    6,
    0,
    8,
    13,
  ],
  [
    4,
    11,
    2,
    14,
    15,
    0,
    8,
    13,
    3,
    12,
    9,
    7,
    5,
    10,
    6,
    1,
    13,
    0,
    11,
    7,
    4,
    9,
    1,
    10,
    14,
    3,
    5,
    12,
    2,
    15,
    8,
    6,
    1,
    4,
    11,
    13,
    12,
    3,
    7,
    14,
    10,
    15,
    6,
    8,
    0,
    5,
    9,
    2,
    6,
    11,
    13,
    8,
    1,
    4,
    10,
    7,
    9,
    5,
    0,
    15,
    14,
    2,
    3,
    12,
  ],
  [
    13,
    2,
    8,
    4,
    6,
    15,
    11,
    1,
    10,
    9,
    3,
    14,
    5,
    0,
    12,
    7,
    1,
    15,
    13,
    8,
    10,
    3,
    7,
    4,
    12,
    5,
    6,
    11,
    0,
    14,
    9,
    2,
    7,
    11,
    4,
    1,
    9,
    12,
    14,
    2,
    0,
    6,
    10,
    13,
    15,
    3,
    5,
    8,
    2,
    1,
    14,
    7,
    4,
    10,
    8,
    13,
    15,
    12,
    9,
    0,
    3,
    5,
    6,
    11,
  ],
];

/** Get bit i (1-indexed, MSB first) from a byte array. */
function desBit(b: Uint8Array, i: number): number {
  return (b[(i - 1) >>> 3] >>> (7 - ((i - 1) & 7))) & 1;
}

/** Apply a permutation table (1-indexed inputs) to produce outBits output bits. */
function desPerm(input: Uint8Array, table: number[], outBits: number): Uint8Array {
  const out = new Uint8Array((outBits + 7) >>> 3);
  for (let i = 0; i < outBits; i++) {
    if (desBit(input, table[i])) out[i >>> 3] |= 1 << (7 - (i & 7));
  }
  return out;
}

/** Rotate a 28-bit half-key left by n positions. */
function desRotL28(halfKey: number, n: number): number {
  return ((halfKey << n) | (halfKey >>> (28 - n))) & 0xfffffff;
}

/** DES ECB encrypt one 8-byte block with an 8-byte key. */
export function desEncrypt(block: Uint8Array, key8: Uint8Array): Uint8Array {
  // Key schedule
  const kp = desPerm(key8, DES_PC1, 56);
  // Extract C (bits 1-28) and D (bits 29-56) as integers
  let C = (kp[0] << 20) | (kp[1] << 12) | (kp[2] << 4) | (kp[3] >>> 4);
  let D = ((kp[3] & 0xf) << 24) | (kp[4] << 16) | (kp[5] << 8) | kp[6];
  C &= 0xfffffff;
  D &= 0xfffffff;

  const subkeys: Uint8Array[] = [];
  for (let r = 0; r < 16; r++) {
    C = desRotL28(C, DES_SHIFTS[r]);
    D = desRotL28(D, DES_SHIFTS[r]);
    // Merge C+D into 7 bytes (56 bits)
    const cd = new Uint8Array(7);
    cd[0] = (C >>> 20) & 0xff;
    cd[1] = (C >>> 12) & 0xff;
    cd[2] = (C >>> 4) & 0xff;
    cd[3] = ((C & 0xf) << 4) | ((D >>> 24) & 0xf);
    cd[4] = (D >>> 16) & 0xff;
    cd[5] = (D >>> 8) & 0xff;
    cd[6] = D & 0xff;
    subkeys.push(desPerm(cd, DES_PC2, 48));
  }

  // Initial permutation
  const ipd = desPerm(block, DES_IP, 64);
  // L and R as 32-bit integers
  let L = (ipd[0] << 24) | (ipd[1] << 16) | (ipd[2] << 8) | ipd[3];
  let R = (ipd[4] << 24) | (ipd[5] << 16) | (ipd[6] << 8) | ipd[7];
  L >>>= 0;
  R >>>= 0;

  for (let r = 0; r < 16; r++) {
    // E expansion: R (32 bits) → 48 bits
    const rBytes = new Uint8Array(4);
    rBytes[0] = (R >>> 24) & 0xff;
    rBytes[1] = (R >>> 16) & 0xff;
    rBytes[2] = (R >>> 8) & 0xff;
    rBytes[3] = R & 0xff;
    const eR = desPerm(rBytes, DES_E, 48);

    // XOR with subkey
    for (let j = 0; j < 6; j++) eR[j] ^= subkeys[r][j];

    // S-box substitution: 48 bits → 32 bits
    let fVal = 0;
    for (let s = 0; s < 8; s++) {
      const startBit = s * 6;
      let bits6 = 0;
      for (let b = 0; b < 6; b++) {
        bits6 = (bits6 << 1) | ((eR[(startBit + b) >>> 3] >>> (7 - ((startBit + b) & 7))) & 1);
      }
      const row = ((bits6 & 0x20) >> 4) | (bits6 & 0x01);
      const col = (bits6 >> 1) & 0x0f;
      fVal = (fVal << 4) | DES_S[s][row * 16 + col];
    }

    // P permutation
    const fBytes = new Uint8Array(4);
    fBytes[0] = (fVal >>> 24) & 0xff;
    fBytes[1] = (fVal >>> 16) & 0xff;
    fBytes[2] = (fVal >>> 8) & 0xff;
    fBytes[3] = fVal & 0xff;
    const pf = desPerm(fBytes, DES_P, 32);
    const pfVal = ((pf[0] << 24) | (pf[1] << 16) | (pf[2] << 8) | pf[3]) >>> 0;

    const newR = (L ^ pfVal) >>> 0;
    L = R;
    R = newR;
  }

  // Final permutation (with R, L swapped — last round doesn't swap)
  const rl = new Uint8Array(8);
  rl[0] = (R >>> 24) & 0xff;
  rl[1] = (R >>> 16) & 0xff;
  rl[2] = (R >>> 8) & 0xff;
  rl[3] = R & 0xff;
  rl[4] = (L >>> 24) & 0xff;
  rl[5] = (L >>> 16) & 0xff;
  rl[6] = (L >>> 8) & 0xff;
  rl[7] = L & 0xff;
  return desPerm(rl, DES_FP, 64);
}

/**
 * Compute the LM hash (sambaLMPassword) for a plaintext password.
 * SECURITY WARNING: LM hash is cryptographically weak. Disable in production.
 * Returns uppercase hex string (32 chars).
 */
export function lmHash(password: string): string {
  const MAGIC = new TextEncoder().encode("KGS!@#$%");

  // Uppercase and pad/truncate to 14 bytes
  const upper = password.toUpperCase().substring(0, 14);
  const padded = new Uint8Array(14);
  padded.set(new TextEncoder().encode(upper).slice(0, 14));

  // Expand each 7-byte half to an 8-byte DES key and encrypt the magic constant
  const half1 = desEncrypt(MAGIC, expandLMKey(padded.slice(0, 7)));
  const half2 = desEncrypt(MAGIC, expandLMKey(padded.slice(7, 14)));

  return [...half1, ...half2]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}
