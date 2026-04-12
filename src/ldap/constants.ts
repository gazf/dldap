/**
 * LDAP protocol constants: application tags, result codes, search scope, etc.
 */

// Application tag numbers (RFC 4511)
export const enum ProtocolOp {
  BindRequest = 0, // [APPLICATION 0]
  BindResponse = 1, // [APPLICATION 1]
  UnbindRequest = 2, // [APPLICATION 2]
  SearchRequest = 3, // [APPLICATION 3]
  SearchResultEntry = 4, // [APPLICATION 4]
  SearchResultDone = 5, // [APPLICATION 5]
  ModifyRequest = 6, // [APPLICATION 6]
  ModifyResponse = 7, // [APPLICATION 7]
  AddRequest = 8, // [APPLICATION 8]
  AddResponse = 9, // [APPLICATION 9]
  DelRequest = 10, // [APPLICATION 10]
  DelResponse = 11, // [APPLICATION 11]
  ModifyDNRequest = 12, // [APPLICATION 12]
  ModifyDNResponse = 13, // [APPLICATION 13]
  CompareRequest = 14, // [APPLICATION 14]
  CompareResponse = 15, // [APPLICATION 15]
  AbandonRequest = 16, // [APPLICATION 16]
  SearchResultReference = 19, // [APPLICATION 19]
  ExtendedRequest = 23, // [APPLICATION 23]
  ExtendedResponse = 24, // [APPLICATION 24]
}

/** Build application tag byte for constructed elements */
export function appTag(op: number, constructed = false): number {
  return 0x40 | (constructed ? 0x20 : 0) | op;
}

/** Build context tag byte */
export function ctxTag(n: number, constructed = false): number {
  return 0x80 | (constructed ? 0x20 : 0) | n;
}

// Result codes (RFC 4511 §4.1.9)
export const enum ResultCode {
  Success = 0,
  OperationsError = 1,
  ProtocolError = 2,
  TimeLimitExceeded = 3,
  SizeLimitExceeded = 4,
  CompareFalse = 5,
  CompareTrue = 6,
  AuthMethodNotSupported = 7,
  StrongerAuthRequired = 8,
  NoSuchAttribute = 16,
  UndefinedAttributeType = 17,
  InappropriateMatching = 18,
  ConstraintViolation = 19,
  AttributeOrValueExists = 20,
  InvalidAttributeSyntax = 21,
  NoSuchObject = 32,
  AliasProblem = 33,
  InvalidDNSyntax = 34,
  AliasDereferencingProblem = 36,
  InappropriateAuthentication = 48,
  InvalidCredentials = 49,
  InsufficientAccessRights = 50,
  Busy = 51,
  Unavailable = 52,
  UnwillingToPerform = 53,
  LoopDetect = 54,
  NamingViolation = 64,
  ObjectClassViolation = 65,
  NotAllowedOnNonLeaf = 66,
  NotAllowedOnRDN = 67,
  EntryAlreadyExists = 68,
  ObjectClassModsProhibited = 69,
  AffectsMultipleDSAs = 71,
  Other = 80,
}

// Search scope
export const enum SearchScope {
  BaseObject = 0,
  SingleLevel = 1,
  WholeSubtree = 2,
}

// Aliases dereferencing
export const enum DerefAliases {
  NeverDerefAliases = 0,
  DerefInSearching = 1,
  DerefFindingBaseObj = 2,
  DerefAlways = 3,
}

// Modify operation
export const enum ModifyOp {
  Add = 0,
  Delete = 1,
  Replace = 2,
}

// Filter tags (context-specific within SearchRequest filter)
export const enum FilterTag {
  And = 0, // [0] SET OF Filter
  Or = 1, // [1] SET OF Filter
  Not = 2, // [2] Filter
  EqualityMatch = 3, // [3] AttributeValueAssertion
  Substrings = 4, // [4] SubstringFilter
  GreaterOrEqual = 5, // [5] AttributeValueAssertion
  LessOrEqual = 6, // [6] AttributeValueAssertion
  Present = 7, // [7] AttributeDescription (primitive)
  ApproxMatch = 8, // [8] AttributeValueAssertion
  ExtensibleMatch = 9, // [9] MatchingRuleAssertion
}
