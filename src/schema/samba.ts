/**
 * Samba schema definitions (samba.schema).
 * Object classes and attributes for Samba LDAP integration.
 */

import type { AttributeType, ObjectClass } from "./core.ts";

export const SAMBA_ATTRIBUTE_TYPES: AttributeType[] = [
  { name: "sambaSID", singleValue: true },
  { name: "sambaNTPassword", singleValue: true },
  { name: "sambaLMPassword", singleValue: true },
  { name: "sambaAcctFlags", singleValue: true },
  { name: "sambaPrimaryGroupSID", singleValue: true },
  { name: "sambaDomainName", singleValue: true },
  { name: "sambaHomePath", singleValue: true },
  { name: "sambaHomeDrive", singleValue: true },
  { name: "sambaLogonScript", singleValue: true },
  { name: "sambaProfilePath", singleValue: true },
  { name: "sambaUserWorkstations" },
  { name: "sambaLogonTime", singleValue: true },
  { name: "sambaLogoffTime", singleValue: true },
  { name: "sambaKickoffTime", singleValue: true },
  { name: "sambaPwdLastSet", singleValue: true },
  { name: "sambaPwdCanChange", singleValue: true },
  { name: "sambaPwdMustChange", singleValue: true },
  { name: "sambaBadPasswordCount", singleValue: true },
  { name: "sambaBadPasswordTime", singleValue: true },
  { name: "sambaLogonHours" },
  { name: "sambaGroupType", singleValue: true },
  { name: "sambaNextUserRid", singleValue: true },
  { name: "sambaNextGroupRid", singleValue: true },
  { name: "sambaNextRid", singleValue: true },
  { name: "sambaAlgorithmicRidBase", singleValue: true },
  { name: "sambaShareName", singleValue: true },
  { name: "sambaOptionName", singleValue: true },
  { name: "sambaBoolOption", singleValue: true },
  { name: "sambaIntegerOption", singleValue: true },
  { name: "sambaStringOption", singleValue: true },
  { name: "sambaStringListoption" },
  { name: "sambaPrivName", singleValue: true },
  { name: "sambaPrivilegeList" },
  { name: "sambaSIDList" },
  { name: "sambaForceLogoff", singleValue: true },
  { name: "sambaRefuseMachinePwdChange", singleValue: true },
  { name: "sambaMinPwdLength", singleValue: true },
  { name: "sambaPwdHistoryLength", singleValue: true },
  { name: "sambaLockoutThreshold", singleValue: true },
  { name: "sambaLockoutDuration", singleValue: true },
  { name: "sambaLockoutObservationWindow", singleValue: true },
  { name: "sambaMaxPwdAge", singleValue: true },
  { name: "sambaMinPwdAge", singleValue: true },
  { name: "sambaTrustFlags", singleValue: true },
  { name: "sambaConnectedUserSID" },
  { name: "sambaShareSecurity" },
];

export const SAMBA_OBJECT_CLASSES: ObjectClass[] = [
  {
    name: "sambaSamAccount",
    sup: "top",
    required: ["uid", "sambaSID"],
    optional: [
      "cn",
      "sambaNTPassword",
      "sambaLMPassword",
      "sambaAcctFlags",
      "sambaPrimaryGroupSID",
      "sambaDomainName",
      "sambaHomePath",
      "sambaHomeDrive",
      "sambaLogonScript",
      "sambaProfilePath",
      "sambaUserWorkstations",
      "sambaLogonTime",
      "sambaLogoffTime",
      "sambaKickoffTime",
      "sambaPwdLastSet",
      "sambaPwdCanChange",
      "sambaPwdMustChange",
      "sambaBadPasswordCount",
      "sambaBadPasswordTime",
      "sambaLogonHours",
    ],
  },
  {
    name: "sambaGroupMapping",
    sup: "top",
    required: ["gidNumber", "sambaSID", "sambaGroupType"],
    optional: ["displayName", "description", "sambaSIDList"],
  },
  {
    name: "sambaDomain",
    sup: "top",
    required: ["sambaDomainName", "sambaSID"],
    optional: [
      "sambaNextUserRid",
      "sambaNextGroupRid",
      "sambaNextRid",
      "sambaAlgorithmicRidBase",
      "sambaForceLogoff",
      "sambaRefuseMachinePwdChange",
      "sambaMinPwdLength",
      "sambaPwdHistoryLength",
      "sambaLockoutThreshold",
      "sambaLockoutDuration",
      "sambaLockoutObservationWindow",
      "sambaMaxPwdAge",
      "sambaMinPwdAge",
    ],
  },
  {
    name: "sambaTrustPassword",
    sup: "top",
    required: ["sambaDomainName", "sambaNTPassword", "sambaTrustFlags", "sambaSID"],
    optional: ["sambaPwdLastSet"],
  },
  {
    name: "sambaUnixIdPool",
    sup: "top",
    required: ["uidNumber", "gidNumber"],
  },
  {
    name: "sambaIdmapEntry",
    sup: "top",
    required: ["sambaSID"],
    optional: ["uidNumber", "gidNumber"],
  },
  {
    name: "sambaPrivilege",
    sup: "top",
    required: ["sambaSID"],
    optional: ["sambaPrivilegeList"],
  },
];

/** Check if an entry has the sambaSamAccount object class. */
export function isSambaSamAccount(objectClasses: string[]): boolean {
  return objectClasses.some((oc) => oc.toLowerCase() === "sambasamaccount");
}

/** Default Samba account flags for a normal user account. */
export const DEFAULT_ACCT_FLAGS = "[U          ]";

/** Default Samba account flags for a disabled account. */
export const DISABLED_ACCT_FLAGS = "[UD         ]";

/** Default Samba account flags for a machine/workstation account. */
export const MACHINE_ACCT_FLAGS = "[W          ]";
