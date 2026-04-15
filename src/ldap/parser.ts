/**
 * Parse BER-encoded bytes into LDAP message structures.
 */

import { type BerElement, decodeAll, decodeBer, decodeChildren } from "../ber/decoder.ts";
import {
  decodeBoolean,
  decodeEnumerated,
  decodeInteger,
  decodeOctetString,
  decodeOctetStringAsString,
} from "../ber/decoder.ts";
import { FilterTag, ProtocolOp } from "./constants.ts";
import type {
  AbandonRequest,
  AddRequest,
  BindRequest,
  Change,
  DelRequest,
  ExtendedRequest,
  Filter,
  LdapControl,
  LdapMessage,
  LdapOperation,
  ModifyDNRequest,
  ModifyRequest,
  PartialAttribute,
  SearchRequest,
  SubstringsFilter,
  UnbindRequest,
} from "./messages.ts";

/**
 * Parse one or more complete LDAPMessage(s) from a buffer.
 * Returns parsed messages and total bytes consumed.
 */
export function parseMessages(buf: Uint8Array): { messages: LdapMessage[]; bytesConsumed: number } {
  const messages: LdapMessage[] = [];
  let offset = 0;

  while (offset < buf.length) {
    // Peek to see if we have a complete message
    try {
      const { element, bytesRead } = decodeBer(buf, offset);
      if (element.tag !== 0x30) {
        throw new Error(`Expected SEQUENCE (0x30) at top level, got 0x${element.tag.toString(16)}`);
      }
      messages.push(parseLdapMessage(element));
      offset += bytesRead;
    } catch (e) {
      if (e instanceof RangeError || (e instanceof Error && e.message.includes("exceeds buffer"))) {
        // Incomplete message — stop, will be retried with more data
        break;
      }
      throw e;
    }
  }

  return { messages, bytesConsumed: offset };
}

function parseLdapMessage(seq: BerElement): LdapMessage {
  const children = decodeChildren(seq);
  if (children.length < 2) {
    throw new Error("LDAPMessage must have at least 2 elements");
  }

  const messageId = decodeInteger(children[0]);
  const opElement = children[1];

  // Determine protocol op from tag
  const tagClass = (opElement.tag & 0xc0) >> 6;
  const tagNumber = opElement.tag & 0x1f;

  if (tagClass !== 1) {
    // Application class
    throw new Error(`Expected application tag, got class ${tagClass}`);
  }

  const protocolOp = parseProtocolOp(tagNumber, opElement);

  // Parse optional controls [0] CONTEXT
  let controls: LdapControl[] | undefined;
  if (children.length > 2) {
    const ctrlElement = children[2];
    if ((ctrlElement.tag & 0xe0) === 0xa0) {
      // Context constructed [0]
      controls = parseControls(ctrlElement);
    }
  }

  return { messageId, protocolOp, controls };
}

function parseProtocolOp(tagNumber: number, el: BerElement): LdapOperation {
  switch (tagNumber) {
    case ProtocolOp.BindRequest:
      return parseBindRequest(el);
    case ProtocolOp.UnbindRequest:
      return { type: ProtocolOp.UnbindRequest } as UnbindRequest;
    case ProtocolOp.SearchRequest:
      return parseSearchRequest(el);
    case ProtocolOp.ModifyRequest:
      return parseModifyRequest(el);
    case ProtocolOp.AddRequest:
      return parseAddRequest(el);
    case ProtocolOp.DelRequest:
      return {
        type: ProtocolOp.DelRequest,
        entry: new TextDecoder().decode(el.value),
      } as DelRequest;
    case ProtocolOp.ModifyDNRequest:
      return parseModifyDNRequest(el);
    case ProtocolOp.AbandonRequest:
      return {
        type: ProtocolOp.AbandonRequest,
        messageId: decodeInteger(el),
      } as AbandonRequest;
    case ProtocolOp.ExtendedRequest:
      return parseExtendedRequest(el);
    // Responses (used when parsing server messages in tests/clients)
    case ProtocolOp.BindResponse:
    case ProtocolOp.ModifyResponse:
    case ProtocolOp.AddResponse:
    case ProtocolOp.DelResponse:
    case ProtocolOp.ModifyDNResponse:
    case ProtocolOp.SearchResultDone:
      return parseSimpleResponse(tagNumber, el);
    case ProtocolOp.SearchResultEntry:
      return parseSearchResultEntry(el);
    default:
      throw new Error(`Unsupported protocol op: ${tagNumber}`);
  }
}

function parseSimpleResponse(type: number, el: BerElement): any {
  const children = decodeChildren(el);
  const resultCode = decodeEnumerated(children[0]);
  const matchedDN = decodeOctetStringAsString(children[1]);
  const diagnosticMessage = decodeOctetStringAsString(children[2]);
  return { type, result: { resultCode, matchedDN, diagnosticMessage } };
}

function parseSearchResultEntry(el: BerElement): any {
  const children = decodeChildren(el);
  const objectName = decodeOctetStringAsString(children[0]);
  const attributes: Array<{ type: string; values: string[] }> = [];
  for (const attrSeq of decodeChildren(children[1])) {
    const [typeEl, valsEl] = decodeChildren(attrSeq);
    const type = decodeOctetStringAsString(typeEl);
    const values = decodeAll(valsEl.value).map(decodeOctetStringAsString);
    attributes.push({ type, values });
  }
  return { type: ProtocolOp.SearchResultEntry, objectName, attributes };
}

function parseBindRequest(el: BerElement): BindRequest {
  const children = decodeChildren(el);
  const version = decodeInteger(children[0]);
  const dn = decodeOctetStringAsString(children[1]);

  // Authentication choice: [0] simple (context primitive) or [3] sasl
  const authEl = children[2];
  const authTag = authEl.tag & 0x1f;
  if (authTag !== 0) {
    throw new Error(`Only simple authentication supported, got auth tag ${authTag}`);
  }
  const password = new TextDecoder().decode(authEl.value);

  return { type: ProtocolOp.BindRequest, version, dn, password };
}

function parseSearchRequest(el: BerElement): SearchRequest {
  const children = decodeChildren(el);
  const baseObject = decodeOctetStringAsString(children[0]);
  const scope = decodeEnumerated(children[1]);
  const derefAliases = decodeEnumerated(children[2]);
  const sizeLimit = decodeInteger(children[3]);
  const timeLimit = decodeInteger(children[4]);
  const typesOnly = decodeBoolean(children[5]);
  const filter = parseFilter(children[6]);

  // Attributes list (SEQUENCE OF)
  const attrChildren = decodeChildren(children[7]);
  const attributes = attrChildren.map(decodeOctetStringAsString);

  return {
    type: ProtocolOp.SearchRequest,
    baseObject,
    scope,
    derefAliases,
    sizeLimit,
    timeLimit,
    typesOnly,
    filter,
    attributes,
  };
}

function parseFilter(el: BerElement): Filter {
  const tagClass = (el.tag & 0xc0) >> 6;
  const tagNumber = el.tag & 0x1f;

  if (tagClass !== 2) {
    // Context class
    throw new Error(`Expected context tag for filter, got class ${tagClass}`);
  }

  switch (tagNumber) {
    case FilterTag.And: {
      const filters = decodeAll(el.value).map(parseFilter);
      return { type: FilterTag.And, filters };
    }
    case FilterTag.Or: {
      const filters = decodeAll(el.value).map(parseFilter);
      return { type: FilterTag.Or, filters };
    }
    case FilterTag.Not: {
      const inner = decodeBer(el.value, 0).element;
      return { type: FilterTag.Not, filter: parseFilter(inner) };
    }
    case FilterTag.EqualityMatch: {
      const [attr, val] = decodeChildren(el);
      return {
        type: FilterTag.EqualityMatch,
        attribute: decodeOctetStringAsString(attr),
        value: decodeOctetStringAsString(val),
      };
    }
    case FilterTag.Substrings: {
      const [attrEl, subsEl] = decodeChildren(el);
      const attribute = decodeOctetStringAsString(attrEl);
      const sub: SubstringsFilter = { type: FilterTag.Substrings, attribute };
      for (const s of decodeAll(subsEl.value)) {
        const subTag = s.tag & 0x1f;
        const str = decodeOctetStringAsString(s);
        if (subTag === 0) sub.initial = str;
        else if (subTag === 1) (sub.any ??= []).push(str);
        else if (subTag === 2) sub.final = str;
      }
      return sub;
    }
    case FilterTag.GreaterOrEqual: {
      const [attr, val] = decodeChildren(el);
      return {
        type: FilterTag.GreaterOrEqual,
        attribute: decodeOctetStringAsString(attr),
        value: decodeOctetStringAsString(val),
      };
    }
    case FilterTag.LessOrEqual: {
      const [attr, val] = decodeChildren(el);
      return {
        type: FilterTag.LessOrEqual,
        attribute: decodeOctetStringAsString(attr),
        value: decodeOctetStringAsString(val),
      };
    }
    case FilterTag.Present: {
      return {
        type: FilterTag.Present,
        attribute: new TextDecoder().decode(el.value),
      };
    }
    case FilterTag.ApproxMatch: {
      const [attr, val] = decodeChildren(el);
      return {
        type: FilterTag.ApproxMatch,
        attribute: decodeOctetStringAsString(attr),
        value: decodeOctetStringAsString(val),
      };
    }
    default:
      throw new Error(`Unsupported filter tag: ${tagNumber}`);
  }
}

function parseModifyRequest(el: BerElement): ModifyRequest {
  const children = decodeChildren(el);
  const object = decodeOctetStringAsString(children[0]);
  const changes: Change[] = [];

  for (const changeSeq of decodeChildren(children[1])) {
    const [opEl, modSeq] = decodeChildren(changeSeq);
    const operation = decodeEnumerated(opEl);
    const [typeEl, valsEl] = decodeChildren(modSeq);
    const type = decodeOctetStringAsString(typeEl);
    const values = decodeAll(valsEl.value).map(decodeOctetStringAsString);
    changes.push({ operation, modification: { type, values } });
  }

  return { type: ProtocolOp.ModifyRequest, object, changes };
}

function parseAddRequest(el: BerElement): AddRequest {
  const children = decodeChildren(el);
  const entry = decodeOctetStringAsString(children[0]);
  const attributes: PartialAttribute[] = [];

  for (const attrSeq of decodeChildren(children[1])) {
    const [typeEl, valsEl] = decodeChildren(attrSeq);
    const type = decodeOctetStringAsString(typeEl);
    const values = decodeAll(valsEl.value).map(decodeOctetStringAsString);
    attributes.push({ type, values });
  }

  return { type: ProtocolOp.AddRequest, entry, attributes };
}

function parseModifyDNRequest(el: BerElement): ModifyDNRequest {
  const children = decodeChildren(el);
  const entry = decodeOctetStringAsString(children[0]);
  const newRDN = decodeOctetStringAsString(children[1]);
  const deleteOldRDN = decodeBoolean(children[2]);
  let newSuperior: string | undefined;
  if (children.length > 3) {
    // [0] IMPLICIT LDAPDN
    newSuperior = new TextDecoder().decode(children[3].value);
  }
  return { type: ProtocolOp.ModifyDNRequest, entry, newRDN, deleteOldRDN, newSuperior };
}

function parseExtendedRequest(el: BerElement): ExtendedRequest {
  const children = decodeChildren(el);
  // [0] requestName (OID as string)
  const requestName = new TextDecoder().decode(children[0].value);
  let requestValue: Uint8Array | undefined;
  if (children.length > 1) {
    requestValue = decodeOctetString(children[1]);
  }
  return { type: ProtocolOp.ExtendedRequest, requestName, requestValue };
}

function parseControls(el: BerElement): LdapControl[] {
  const controls: LdapControl[] = [];
  for (const seq of decodeChildren(el)) {
    const children = decodeChildren(seq);
    const oid = decodeOctetStringAsString(children[0]);
    let criticality = false;
    let value: Uint8Array | undefined;
    if (children.length > 1) {
      if (children[1].tag === 0x01) {
        criticality = decodeBoolean(children[1]);
        if (children.length > 2) value = decodeOctetString(children[2]);
      } else {
        value = decodeOctetString(children[1]);
      }
    }
    controls.push({ oid, criticality, value });
  }
  return controls;
}
