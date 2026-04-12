/**
 * Encode LDAP response messages into BER bytes.
 */

import {
  TAG_BOOLEAN,
  TAG_ENUMERATED,
  TAG_INTEGER,
  TAG_OCTET_STRING,
  TAG_SEQUENCE,
  TAG_SET,
  concat,
  encodeBoolean,
  encodeConstructed,
  encodeEnumerated,
  encodeInteger,
  encodeNull,
  encodeOctetString,
} from "../ber/encoder.ts";
import { ProtocolOp, appTag, ctxTag } from "./constants.ts";
import type {
  AddResponse,
  BindResponse,
  DelResponse,
  ExtendedResponse,
  LdapMessage,
  LdapResult,
  ModifyDNResponse,
  ModifyResponse,
  PartialAttribute,
  SearchResultDone,
  SearchResultEntry,
} from "./messages.ts";

export function encodeLdapMessage(msg: LdapMessage): Uint8Array {
  const msgId = encodeInteger(TAG_INTEGER, msg.messageId);
  const op = encodeOperation(msg.protocolOp);
  return encodeConstructed(TAG_SEQUENCE, msgId, op);
}

function encodeResult(result: LdapResult): Uint8Array {
  const code = encodeEnumerated(TAG_ENUMERATED, result.resultCode);
  const matched = encodeOctetString(TAG_OCTET_STRING, result.matchedDN);
  const diag = encodeOctetString(TAG_OCTET_STRING, result.diagnosticMessage);
  return concat(code, matched, diag);
}

function encodeOperation(op: LdapMessage["protocolOp"]): Uint8Array {
  switch (op.type) {
    case ProtocolOp.BindResponse:
      return encodeBindResponse(op);
    case ProtocolOp.SearchResultEntry:
      return encodeSearchResultEntry(op);
    case ProtocolOp.SearchResultDone:
      return encodeSearchResultDone(op);
    case ProtocolOp.ModifyResponse:
      return encodeSimpleResponse(appTag(ProtocolOp.ModifyResponse, true), op.result);
    case ProtocolOp.AddResponse:
      return encodeSimpleResponse(appTag(ProtocolOp.AddResponse, true), op.result);
    case ProtocolOp.DelResponse:
      return encodeSimpleResponse(appTag(ProtocolOp.DelResponse, true), op.result);
    case ProtocolOp.ModifyDNResponse:
      return encodeSimpleResponse(appTag(ProtocolOp.ModifyDNResponse, true), op.result);
    case ProtocolOp.ExtendedResponse:
      return encodeExtendedResponse(op);
    default:
      throw new Error(`Cannot encode operation type: ${(op as any).type}`);
  }
}

function encodeBindResponse(op: BindResponse): Uint8Array {
  const result = encodeResult(op.result);
  return encodeConstructed(appTag(ProtocolOp.BindResponse, true), result);
}

function encodeSearchResultEntry(op: SearchResultEntry): Uint8Array {
  const dn = encodeOctetString(TAG_OCTET_STRING, op.objectName);
  const attrs = encodeConstructed(TAG_SEQUENCE, ...op.attributes.map(encodeAttribute));
  return encodeConstructed(appTag(ProtocolOp.SearchResultEntry, true), dn, attrs);
}

function encodeAttribute(attr: PartialAttribute): Uint8Array {
  const type = encodeOctetString(TAG_OCTET_STRING, attr.type);
  const vals = encodeConstructed(TAG_SET, ...attr.values.map((v) => encodeOctetString(TAG_OCTET_STRING, v)));
  return encodeConstructed(TAG_SEQUENCE, type, vals);
}

function encodeSearchResultDone(op: SearchResultDone): Uint8Array {
  const result = encodeResult(op.result);
  return encodeConstructed(appTag(ProtocolOp.SearchResultDone, true), result);
}

function encodeSimpleResponse(tag: number, result: LdapResult): Uint8Array {
  return encodeConstructed(tag, encodeResult(result));
}

function encodeExtendedResponse(op: ExtendedResponse): Uint8Array {
  const parts: Uint8Array[] = [encodeResult(op.result)];
  if (op.responseName) {
    parts.push(encodeOctetString(ctxTag(10), op.responseName)); // [10] responseName
  }
  if (op.responseValue) {
    parts.push(encodeOctetString(ctxTag(11), op.responseValue)); // [11] responseValue
  }
  return encodeConstructed(appTag(ProtocolOp.ExtendedResponse, true), ...parts);
}
