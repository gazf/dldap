/**
 * RADIUS packet parsing and encoding (RFC 2865).
 * Supports standard TLV attributes and Vendor-Specific Attributes (RFC 2865 §5.26).
 * EAP-Message (attr 79) may span multiple attributes (RFC 3579 §3.1).
 */

import { Attr, MS_VENDOR_ID } from "./constants.ts";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RadiusAttribute {
  type: number;
  value: Uint8Array;
  /** Present for Vendor-Specific Attributes (type 26) */
  vendorId?: number;
  vendorType?: number;
}

export interface RadiusPacket {
  code: number;
  identifier: number;
  /** 16 bytes */
  authenticator: Uint8Array;
  attributes: RadiusAttribute[];
}

// ---------------------------------------------------------------------------
// Parse
// ---------------------------------------------------------------------------

export function parsePacket(buf: Uint8Array): RadiusPacket {
  if (buf.length < 20) throw new Error("RADIUS packet too short");
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const code = buf[0];
  const identifier = buf[1];
  const length = dv.getUint16(2);
  if (length < 20 || length > buf.length) {
    throw new Error(`RADIUS length field invalid: ${length}`);
  }

  const authenticator = buf.slice(4, 20);
  const attributes: RadiusAttribute[] = [];

  let off = 20;
  while (off + 2 <= length) {
    const type = buf[off];
    const len = buf[off + 1];
    if (len < 2 || off + len > length) {
      throw new Error(`Malformed attribute at offset ${off}`);
    }
    const value = buf.slice(off + 2, off + len);

    if (type === Attr.VendorSpecific && value.length >= 6) {
      // Vendor-Specific: 4B vendor-id (BE) + 1B vendor-type + 1B vendor-len + value
      const dvVsa = new DataView(value.buffer, value.byteOffset, value.byteLength);
      const vendorId = dvVsa.getUint32(0);
      const vendorType = value[4];
      const vendorLen = value[5];
      const vValue = value.slice(6, 2 + vendorLen); // vendor-len includes type+len bytes
      attributes.push({ type, value, vendorId, vendorType });
      // Store decoded VSA value in a separate attribute entry for easy access
      attributes[attributes.length - 1].value = vValue;
    } else {
      attributes.push({ type, value });
    }

    off += len;
  }

  return { code, identifier, authenticator, attributes };
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

/** Encode attributes array to bytes (excluding the 20-byte packet header) */
function encodeAttributes(attributes: RadiusAttribute[]): Uint8Array {
  let total = 0;
  const encoded: Uint8Array[] = [];

  for (const attr of attributes) {
    if (attr.vendorId !== undefined && attr.vendorType !== undefined) {
      // VSA: type(1) + len(1) + vendor-id(4) + vendor-type(1) + vendor-len(1) + value
      const vLen = 2 + attr.value.length; // vendor-type + vendor-len + value
      const attrLen = 2 + 4 + vLen;
      const buf = new Uint8Array(attrLen);
      buf[0] = Attr.VendorSpecific;
      buf[1] = attrLen;
      const dv = new DataView(buf.buffer);
      dv.setUint32(2, attr.vendorId);
      buf[6] = attr.vendorType;
      buf[7] = vLen;
      buf.set(attr.value, 8);
      encoded.push(buf);
      total += attrLen;
    } else {
      // Standard TLV: type(1) + len(1) + value
      const attrLen = 2 + attr.value.length;
      const buf = new Uint8Array(attrLen);
      buf[0] = attr.type;
      buf[1] = attrLen;
      buf.set(attr.value, 2);
      encoded.push(buf);
      total += attrLen;
    }
  }

  const result = new Uint8Array(total);
  let off = 0;
  for (const e of encoded) {
    result.set(e, off);
    off += e.length;
  }
  return result;
}

export function encodePacket(pkt: RadiusPacket): Uint8Array {
  const attrsBytes = encodeAttributes(pkt.attributes);
  const length = 20 + attrsBytes.length;
  if (length > 4096) throw new Error(`RADIUS packet too large: ${length}`);

  const buf = new Uint8Array(length);
  buf[0] = pkt.code;
  buf[1] = pkt.identifier;
  const dv = new DataView(buf.buffer);
  dv.setUint16(2, length);
  buf.set(pkt.authenticator, 4);
  buf.set(attrsBytes, 20);
  return buf;
}

// ---------------------------------------------------------------------------
// Attribute accessors
// ---------------------------------------------------------------------------

export function getAttrBytes(
  pkt: RadiusPacket,
  type: number,
  vendorType?: number,
): Uint8Array | undefined {
  const attr = pkt.attributes.find((a) =>
    a.type === type && (vendorType === undefined || a.vendorType === vendorType)
  );
  return attr?.value;
}

export function getAttrString(pkt: RadiusPacket, type: number): string | undefined {
  const v = getAttrBytes(pkt, type);
  return v ? new TextDecoder().decode(v) : undefined;
}

/**
 * Collect all EAP-Message (attr 79) attributes and concatenate them.
 * RFC 3579 §3.1: EAP packets larger than 253 bytes are fragmented.
 */
export function getEapMessage(pkt: RadiusPacket): Uint8Array | undefined {
  const parts = pkt.attributes
    .filter((a) => a.type === Attr.EapMessage)
    .map((a) => a.value);
  if (parts.length === 0) return undefined;
  const total = parts.reduce((s, p) => s + p.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.length;
  }
  return buf;
}

/**
 * Split an EAP message into one or more EAP-Message attributes (253 bytes max each).
 */
export function makeEapMessageAttrs(eapMsg: Uint8Array): RadiusAttribute[] {
  const attrs: RadiusAttribute[] = [];
  for (let off = 0; off < eapMsg.length; off += 253) {
    attrs.push({ type: Attr.EapMessage, value: eapMsg.slice(off, off + 253) });
  }
  return attrs;
}

/**
 * Create a Vendor-Specific Attribute (type 26) for Microsoft attributes (vendor 311).
 */
export function makeMsVsaAttr(vendorType: number, value: Uint8Array): RadiusAttribute {
  return { type: Attr.VendorSpecific, value, vendorId: MS_VENDOR_ID, vendorType };
}

// ---------------------------------------------------------------------------
// Helpers to build common attributes
// ---------------------------------------------------------------------------

export function makeAttr(type: number, value: Uint8Array): RadiusAttribute {
  return { type, value };
}

export function makeStringAttr(type: number, str: string): RadiusAttribute {
  return { type, value: new TextEncoder().encode(str) };
}
