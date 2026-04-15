/**
 * EAP (Extensible Authentication Protocol) packet handling (RFC 3748).
 * Focused on EAP-MSCHAPv2 (type 26).
 */

import { EapCode, EapType, MSCHAPv2Opcode } from "./constants.ts";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EapPacket {
  code: number;
  id: number;
  /** data includes EAP type byte + payload (for Request/Response); empty for Success/Failure */
  data: Uint8Array;
}

export interface MsChapv2Response {
  peerChallenge: Uint8Array; // 16 bytes
  ntResponse: Uint8Array;    // 24 bytes
  flags: number;             // 1 byte (should be 0)
  userName: string;
}

// ---------------------------------------------------------------------------
// Parse / Encode EAP packets
// ---------------------------------------------------------------------------

export function parseEapPacket(buf: Uint8Array): EapPacket {
  if (buf.length < 4) throw new Error("EAP packet too short");
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const code = buf[0];
  const id = buf[1];
  const length = dv.getUint16(2);
  if (length > buf.length) throw new Error("EAP length exceeds buffer");
  const data = buf.slice(4, length);
  return { code, id, data };
}

export function encodeEapPacket(code: number, id: number, data: Uint8Array): Uint8Array {
  const length = 4 + data.length;
  const buf = new Uint8Array(length);
  buf[0] = code;
  buf[1] = id;
  buf[2] = (length >>> 8) & 0xff;
  buf[3] = length & 0xff;
  buf.set(data, 4);
  return buf;
}

// ---------------------------------------------------------------------------
// EAP Identity Response: extract username
// data[0] = type (1), data[1..] = identity string
// ---------------------------------------------------------------------------

export function parseEapIdentity(eap: EapPacket): string {
  if (eap.data.length < 1 || eap.data[0] !== EapType.Identity) {
    throw new Error("Not an EAP Identity response");
  }
  return new TextDecoder().decode(eap.data.slice(1));
}

// ---------------------------------------------------------------------------
// EAP-MSCHAPv2 Challenge (server → client)
// data[0] = type (26), data[1] = opcode (1), data[2] = MSCHAPv2-ID,
// data[3..4] = MS-Length (BE), data[5] = Value-Size (16),
// data[6..21] = AuthChallenge (16B), data[22..] = Name
// ---------------------------------------------------------------------------

export function encodeMsChapv2Challenge(
  eapId: number,
  msChapId: number,
  authChallenge: Uint8Array, // 16 bytes
  serverName: string,
): Uint8Array {
  const nameBytes = new TextEncoder().encode(serverName);
  // EAP data: type(1) + opcode(1) + msChapId(1) + msLength(2) + valueSize(1) + challenge(16) + name
  const msLength = 4 + 1 + 16 + nameBytes.length; // opcode..name
  const data = new Uint8Array(1 + 1 + 1 + 2 + 1 + 16 + nameBytes.length);
  let off = 0;
  data[off++] = EapType.MSCHAPv2;          // EAP type
  data[off++] = MSCHAPv2Opcode.Challenge;  // opcode
  data[off++] = msChapId;                  // MSCHAPv2-ID
  data[off++] = (msLength >>> 8) & 0xff;   // MS-Length high
  data[off++] = msLength & 0xff;           // MS-Length low
  data[off++] = 16;                        // Value-Size
  data.set(authChallenge, off); off += 16; // AuthChallenge
  data.set(nameBytes, off);                // Name
  return encodeEapPacket(EapCode.Request, eapId, data);
}

// ---------------------------------------------------------------------------
// EAP-MSCHAPv2 Response (client → server) parsing
// data[0] = type(26), data[1] = opcode(2), data[2] = MSCHAPv2-ID,
// data[3..4] = MS-Length, data[5] = Value-Size (49),
// data[6..21] = PeerChallenge(16B), data[22..29] = reserved(8B),
// data[30..53] = NT-Response(24B), data[54] = Flags,
// data[55..] = UserName
// ---------------------------------------------------------------------------

export function parseMsChapv2Response(eap: EapPacket): MsChapv2Response {
  const d = eap.data;
  if (d.length < 2 || d[0] !== EapType.MSCHAPv2) {
    throw new Error("Not an EAP-MSCHAPv2 packet");
  }
  if (d[1] !== MSCHAPv2Opcode.Response) {
    throw new Error(`Unexpected MSCHAPv2 opcode: ${d[1]}`);
  }
  // d[2] = MSCHAPv2-ID, d[3..4] = MS-Length, d[5] = Value-Size (should be 49)
  if (d.length < 6 + 49) throw new Error("EAP-MSCHAPv2 Response too short");
  const off = 6;
  const peerChallenge = d.slice(off, off + 16);
  // d[off+16..off+23] = 8 reserved bytes
  const ntResponse = d.slice(off + 24, off + 48);
  const flags = d[off + 48];
  const userName = new TextDecoder().decode(d.slice(6 + 49));
  return { peerChallenge, ntResponse, flags, userName };
}

// ---------------------------------------------------------------------------
// EAP-MSCHAPv2 Success (server → client)
// data[0] = type(26), data[1] = opcode(3), data[2] = MSCHAPv2-ID,
// data[3..4] = MS-Length, data[5..] = "S=<hex40> M=<message>"
// ---------------------------------------------------------------------------

export function encodeMsChapv2Success(
  eapId: number,
  msChapId: number,
  authenticatorResponse: string, // "S=<hex40>"
): Uint8Array {
  const msgBytes = new TextEncoder().encode(authenticatorResponse);
  const msLength = 4 + msgBytes.length;
  const data = new Uint8Array(1 + 1 + 1 + 2 + msgBytes.length);
  let off = 0;
  data[off++] = EapType.MSCHAPv2;
  data[off++] = MSCHAPv2Opcode.Success;
  data[off++] = msChapId;
  data[off++] = (msLength >>> 8) & 0xff;
  data[off++] = msLength & 0xff;
  data.set(msgBytes, off);
  return encodeEapPacket(EapCode.Request, eapId, data);
}

// ---------------------------------------------------------------------------
// EAP-MSCHAPv2 Failure (server → client)
// ---------------------------------------------------------------------------

export function encodeMsChapv2Failure(
  eapId: number,
  msChapId: number,
): Uint8Array {
  const msg = new TextEncoder().encode("E=691 R=0 C=00000000000000000000000000000000 V=3");
  const msLength = 4 + msg.length;
  const data = new Uint8Array(1 + 1 + 1 + 2 + msg.length);
  let off = 0;
  data[off++] = EapType.MSCHAPv2;
  data[off++] = MSCHAPv2Opcode.Failure;
  data[off++] = msChapId;
  data[off++] = (msLength >>> 8) & 0xff;
  data[off++] = msLength & 0xff;
  data.set(msg, off);
  return encodeEapPacket(EapCode.Request, eapId, data);
}

// ---------------------------------------------------------------------------
// EAP Success / Failure (final EAP packets, no type byte)
// ---------------------------------------------------------------------------

export function encodeEapSuccess(eapId: number): Uint8Array {
  return encodeEapPacket(EapCode.Success, eapId, new Uint8Array(0));
}

export function encodeEapFailure(eapId: number): Uint8Array {
  return encodeEapPacket(EapCode.Failure, eapId, new Uint8Array(0));
}
