/** RADIUS packet codes (RFC 2865 §4, RFC 2866 §4) */
export const RadiusCode = {
  AccessRequest: 1,
  AccessAccept: 2,
  AccessReject: 3,
  AccountingRequest: 4,
  AccountingResponse: 5,
  AccessChallenge: 11,
} as const;
export type RadiusCode = typeof RadiusCode[keyof typeof RadiusCode];

/** RADIUS attribute type numbers (RFC 2865 §5) */
export const Attr = {
  UserName: 1,
  UserPassword: 2,
  NasIpAddress: 4,
  NasPort: 5,
  ReplyMessage: 18,
  State: 24,
  VendorSpecific: 26,
  NasPortType: 61,
  EapMessage: 79,
  MessageAuthenticator: 80,
} as const;

/** EAP codes (RFC 3748 §4) */
export const EapCode = {
  Request: 1,
  Response: 2,
  Success: 3,
  Failure: 4,
} as const;

/** EAP type numbers */
export const EapType = {
  Identity: 1,
  MSCHAPv2: 26,
} as const;

/** MS-CHAPv2 opcodes (RFC 2759) */
export const MSCHAPv2Opcode = {
  Challenge: 1,
  Response: 2,
  Success: 3,
  Failure: 4,
} as const;

/** Microsoft Vendor ID (RFC 2548) */
export const MS_VENDOR_ID = 311;

/** Microsoft vendor-specific attribute types */
export const MsAttr = {
  MppeSendKey: 16,
  MppeRecvKey: 17,
} as const;
