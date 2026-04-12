/**
 * Core LDAP schema definitions (subset of RFC 4519 / RFC 2256).
 * Used for basic attribute type knowledge (single-valued, syntax hints).
 */

export interface AttributeType {
  name: string;
  aliases?: string[];
  singleValue?: boolean;
  /** Whether this attribute holds binary data */
  binary?: boolean;
}

export interface ObjectClass {
  name: string;
  sup?: string;
  required?: string[];
  optional?: string[];
}

// Core attribute types
export const CORE_ATTRIBUTE_TYPES: AttributeType[] = [
  { name: "cn", aliases: ["commonName"] },
  { name: "sn", aliases: ["surname"] },
  { name: "givenName" },
  { name: "uid", aliases: ["userid"] },
  { name: "uidNumber", singleValue: true },
  { name: "gidNumber", singleValue: true },
  { name: "homeDirectory", singleValue: true },
  { name: "loginShell", singleValue: true },
  { name: "gecos", singleValue: true },
  { name: "userPassword" },
  { name: "shadowLastChange", singleValue: true },
  { name: "shadowMin", singleValue: true },
  { name: "shadowMax", singleValue: true },
  { name: "shadowWarning", singleValue: true },
  { name: "shadowInactive", singleValue: true },
  { name: "shadowExpire", singleValue: true },
  { name: "shadowFlag", singleValue: true },
  { name: "mail" },
  { name: "telephoneNumber" },
  { name: "description" },
  { name: "displayName", singleValue: true },
  { name: "title" },
  { name: "o", aliases: ["organization"] },
  { name: "ou", aliases: ["organizationalUnitName"] },
  { name: "dc", aliases: ["domainComponent"] },
  { name: "l", aliases: ["localityName"] },
  { name: "st", aliases: ["stateOrProvinceName"] },
  { name: "street", aliases: ["streetAddress"] },
  { name: "postalCode" },
  { name: "member" },
  { name: "memberUid" },
  { name: "uniqueMember" },
  { name: "objectClass" },
  { name: "entryDN", singleValue: true },
  { name: "createTimestamp", singleValue: true },
  { name: "modifyTimestamp", singleValue: true },
  { name: "jpegPhoto", binary: true },
  { name: "userCertificate", binary: true },
];

export const CORE_OBJECT_CLASSES: ObjectClass[] = [
  {
    name: "top",
    required: ["objectClass"],
  },
  {
    name: "person",
    sup: "top",
    required: ["cn", "sn"],
    optional: ["userPassword", "telephoneNumber", "description"],
  },
  {
    name: "organizationalPerson",
    sup: "person",
    optional: ["title", "l", "st", "street", "postalCode", "ou"],
  },
  {
    name: "inetOrgPerson",
    sup: "organizationalPerson",
    optional: ["uid", "mail", "givenName", "displayName", "jpegPhoto"],
  },
  {
    name: "posixAccount",
    sup: "top",
    required: ["cn", "uid", "uidNumber", "gidNumber", "homeDirectory"],
    optional: ["userPassword", "loginShell", "gecos", "description"],
  },
  {
    name: "posixGroup",
    sup: "top",
    required: ["cn", "gidNumber"],
    optional: ["userPassword", "memberUid", "description"],
  },
  {
    name: "shadowAccount",
    sup: "top",
    required: ["uid"],
    optional: [
      "userPassword",
      "shadowLastChange",
      "shadowMin",
      "shadowMax",
      "shadowWarning",
      "shadowInactive",
      "shadowExpire",
      "shadowFlag",
    ],
  },
  {
    name: "organization",
    sup: "top",
    required: ["o"],
    optional: ["description"],
  },
  {
    name: "organizationalUnit",
    sup: "top",
    required: ["ou"],
    optional: ["description"],
  },
  {
    name: "domain",
    sup: "top",
    required: ["dc"],
    optional: ["description"],
  },
  {
    name: "groupOfNames",
    sup: "top",
    required: ["cn", "member"],
    optional: ["description"],
  },
  {
    name: "groupOfUniqueNames",
    sup: "top",
    required: ["cn", "uniqueMember"],
    optional: ["description"],
  },
];

/** Look up an attribute type by name (case-insensitive). */
export function findAttributeType(name: string): AttributeType | undefined {
  const lower = name.toLowerCase();
  return CORE_ATTRIBUTE_TYPES.find(
    (at) =>
      at.name.toLowerCase() === lower ||
      (at.aliases?.some((a) => a.toLowerCase() === lower) ?? false),
  );
}
