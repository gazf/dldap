/**
 * TypeScript representations of LDAP protocol messages (RFC 4511).
 */

import { FilterTag, ModifyOp, ProtocolOp, SearchScope } from "./constants.ts";

export interface LdapMessage {
  messageId: number;
  protocolOp: LdapOperation;
  controls?: LdapControl[];
}

export interface LdapControl {
  oid: string;
  criticality?: boolean;
  value?: Uint8Array;
}

export type LdapOperation =
  | BindRequest
  | BindResponse
  | UnbindRequest
  | SearchRequest
  | SearchResultEntry
  | SearchResultDone
  | ModifyRequest
  | ModifyResponse
  | AddRequest
  | AddResponse
  | DelRequest
  | DelResponse
  | ModifyDNRequest
  | ModifyDNResponse
  | AbandonRequest
  | ExtendedRequest
  | ExtendedResponse;

// --- Bind ---

export interface BindRequest {
  type: ProtocolOp.BindRequest;
  version: number;
  dn: string;
  /** Simple authentication password */
  password: string;
}

export interface BindResponse {
  type: ProtocolOp.BindResponse;
  result: LdapResult;
}

export interface UnbindRequest {
  type: ProtocolOp.UnbindRequest;
}

// --- Search ---

export interface SearchRequest {
  type: ProtocolOp.SearchRequest;
  baseObject: string;
  scope: SearchScope;
  derefAliases: number;
  sizeLimit: number;
  timeLimit: number;
  typesOnly: boolean;
  filter: Filter;
  attributes: string[];
}

export type Filter =
  | AndFilter
  | OrFilter
  | NotFilter
  | EqualityFilter
  | SubstringsFilter
  | GreaterOrEqualFilter
  | LessOrEqualFilter
  | PresentFilter
  | ApproxFilter;

export interface AndFilter {
  type: FilterTag.And;
  filters: Filter[];
}

export interface OrFilter {
  type: FilterTag.Or;
  filters: Filter[];
}

export interface NotFilter {
  type: FilterTag.Not;
  filter: Filter;
}

export interface EqualityFilter {
  type: FilterTag.EqualityMatch;
  attribute: string;
  value: string;
}

export interface SubstringsFilter {
  type: FilterTag.Substrings;
  attribute: string;
  initial?: string;
  any?: string[];
  final?: string;
}

export interface GreaterOrEqualFilter {
  type: FilterTag.GreaterOrEqual;
  attribute: string;
  value: string;
}

export interface LessOrEqualFilter {
  type: FilterTag.LessOrEqual;
  attribute: string;
  value: string;
}

export interface PresentFilter {
  type: FilterTag.Present;
  attribute: string;
}

export interface ApproxFilter {
  type: FilterTag.ApproxMatch;
  attribute: string;
  value: string;
}

export interface SearchResultEntry {
  type: ProtocolOp.SearchResultEntry;
  objectName: string;
  attributes: PartialAttribute[];
}

export interface PartialAttribute {
  type: string;
  values: string[];
}

export interface SearchResultDone {
  type: ProtocolOp.SearchResultDone;
  result: LdapResult;
}

// --- Modify ---

export interface ModifyRequest {
  type: ProtocolOp.ModifyRequest;
  object: string;
  changes: Change[];
}

export interface Change {
  operation: ModifyOp;
  modification: PartialAttribute;
}

export interface ModifyResponse {
  type: ProtocolOp.ModifyResponse;
  result: LdapResult;
}

// --- Add ---

export interface AddRequest {
  type: ProtocolOp.AddRequest;
  entry: string;
  attributes: PartialAttribute[];
}

export interface AddResponse {
  type: ProtocolOp.AddResponse;
  result: LdapResult;
}

// --- Delete ---

export interface DelRequest {
  type: ProtocolOp.DelRequest;
  entry: string;
}

export interface DelResponse {
  type: ProtocolOp.DelResponse;
  result: LdapResult;
}

// --- ModifyDN ---

export interface ModifyDNRequest {
  type: ProtocolOp.ModifyDNRequest;
  entry: string;
  newRDN: string;
  deleteOldRDN: boolean;
  newSuperior?: string;
}

export interface ModifyDNResponse {
  type: ProtocolOp.ModifyDNResponse;
  result: LdapResult;
}

// --- Abandon ---

export interface AbandonRequest {
  type: ProtocolOp.AbandonRequest;
  messageId: number;
}

// --- Extended ---

export interface ExtendedRequest {
  type: ProtocolOp.ExtendedRequest;
  requestName: string;
  requestValue?: Uint8Array;
}

export interface ExtendedResponse {
  type: ProtocolOp.ExtendedResponse;
  result: LdapResult;
  responseName?: string;
  responseValue?: Uint8Array;
}

// --- LDAPResult (common to most responses) ---

export interface LdapResult {
  resultCode: number;
  matchedDN: string;
  diagnosticMessage: string;
  referral?: string[];
}

export function successResult(): LdapResult {
  return { resultCode: 0, matchedDN: "", diagnosticMessage: "" };
}

export function errorResult(code: number, message: string, matchedDN = ""): LdapResult {
  return { resultCode: code, matchedDN, diagnosticMessage: message };
}
