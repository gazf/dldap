/**
 * BER (Basic Encoding Rules) encoder for ASN.1 structures used in LDAP.
 */

function encodeLength(len: number): Uint8Array {
  if (len < 0x80) {
    return new Uint8Array([len]);
  } else if (len < 0x100) {
    return new Uint8Array([0x81, len]);
  } else if (len < 0x10000) {
    return new Uint8Array([0x82, (len >> 8) & 0xff, len & 0xff]);
  } else {
    return new Uint8Array([
      0x83,
      (len >> 16) & 0xff,
      (len >> 8) & 0xff,
      len & 0xff,
    ]);
  }
}

function encodeTLV(tag: number, value: Uint8Array): Uint8Array {
  const lenBytes = encodeLength(value.length);
  const result = new Uint8Array(1 + lenBytes.length + value.length);
  result[0] = tag;
  result.set(lenBytes, 1);
  result.set(value, 1 + lenBytes.length);
  return result;
}

/** Concatenate multiple Uint8Arrays */
export function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

// --- Primitive encoders ---

export function encodeInteger(tag: number, value: number): Uint8Array {
  // Determine minimum bytes needed for two's complement representation
  let bytes: number[];
  if (value === 0) {
    bytes = [0];
  } else if (value > 0) {
    bytes = [];
    let v = value;
    while (v > 0) {
      bytes.unshift(v & 0xff);
      v >>>= 8;
    }
    // Ensure high bit is not set (positive number)
    if (bytes[0] & 0x80) bytes.unshift(0);
  } else {
    // Negative: two's complement
    bytes = [];
    let v = -value - 1;
    while (v > 0) {
      bytes.unshift(~(v & 0xff) & 0xff);
      v >>>= 8;
    }
    if (bytes.length === 0) bytes = [0xff];
    if (!(bytes[0] & 0x80)) bytes.unshift(0xff);
  }
  return encodeTLV(tag, new Uint8Array(bytes));
}

export function encodeOctetString(tag: number, value: Uint8Array | string): Uint8Array {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
  return encodeTLV(tag, bytes);
}

export function encodeBoolean(tag: number, value: boolean): Uint8Array {
  return encodeTLV(tag, new Uint8Array([value ? 0xff : 0x00]));
}

export function encodeEnumerated(tag: number, value: number): Uint8Array {
  return encodeInteger(tag, value);
}

export function encodeNull(tag: number): Uint8Array {
  return new Uint8Array([tag, 0x00]);
}

/** Encode a constructed element (SEQUENCE, SET, or application/context constructed) */
export function encodeConstructed(tag: number, ...children: Uint8Array[]): Uint8Array {
  const body = concat(...children);
  return encodeTLV(tag, body);
}

// --- LDAP tag constants for convenience ---

/** Universal tags */
export const TAG_INTEGER = 0x02;
export const TAG_OCTET_STRING = 0x04;
export const TAG_NULL = 0x05;
export const TAG_ENUMERATED = 0x0a;
export const TAG_SEQUENCE = 0x30;
export const TAG_SET = 0x31;
export const TAG_BOOLEAN = 0x01;
