/**
 * Samba attribute auto-generation hooks.
 *
 * Called during Add and Modify operations to automatically populate
 * Samba-specific attributes when userPassword changes or a
 * sambaSamAccount is created.
 */

import type { SambaConfig } from "../../config/default.ts";
import { lmHash, ntHash } from "../samba/hash.ts";
import {
  DEFAULT_ACCT_FLAGS,
  isSambaSamAccount,
} from "../schema/samba.ts";
import {
  buildSID,
  resolveGroupSID,
  resolvePrimaryGroupSID,
  resolveUserSID,
} from "../samba/sid.ts";

/**
 * Enrich attrs with Samba attributes when adding a new entry.
 * Mutates attrs in place.
 */
export function onAdd(
  attrs: Record<string, string[]>,
  samba: SambaConfig,
): void {
  if (!samba.enabled) return;

  const objectClasses = attrs["objectclass"] ?? [];
  if (!isSambaSamAccount(objectClasses)) return;

  // Generate SID if missing
  if (!attrs["sambasid"]) {
    attrs["sambasid"] = [resolveUserSID(samba.domainSID, attrs)];
  }

  // Primary group SID
  if (!attrs["sambaprimarygroupsid"]) {
    attrs["sambaprimarygroupsid"] = [resolvePrimaryGroupSID(samba.domainSID, attrs)];
  }

  // Account flags
  if (!attrs["sambaacctflags"]) {
    attrs["sambaacctflags"] = [DEFAULT_ACCT_FLAGS];
  }

  // NT/LM hash from userPassword
  const passwords = attrs["userpassword"] ?? [];
  if (passwords.length > 0 && samba.autoHash) {
    const plaintext = extractPlainPassword(passwords[0]);
    if (plaintext !== null) {
      if (!attrs["sambantpassword"]) {
        attrs["sambantpassword"] = [ntHash(plaintext)];
      }
      if (samba.lmHashEnabled && !attrs["sambalMpassword"]) {
        attrs["sambalMpassword"] = [lmHash(plaintext)];
      }
    }
  }

  // Domain name
  if (!attrs["sambadomainname"] && samba.domain) {
    attrs["sambadomainname"] = [samba.domain];
  }

  // Password last set
  if (!attrs["sambapwdlastset"]) {
    attrs["sambapwdlastset"] = [String(Math.floor(Date.now() / 1000))];
  }
}

/**
 * Update Samba hashes when userPassword is modified.
 * Returns the additional attribute changes to apply.
 */
export function onPasswordChange(
  newPassword: string,
  existingAttrs: Record<string, string[]>,
  samba: SambaConfig,
): Record<string, string[]> {
  if (!samba.enabled || !samba.autoHash) return {};

  const objectClasses = existingAttrs["objectclass"] ?? [];
  if (!isSambaSamAccount(objectClasses)) return {};

  const updates: Record<string, string[]> = {};
  const plaintext = extractPlainPassword(newPassword);
  if (plaintext === null) return {};

  updates["sambantpassword"] = [ntHash(plaintext)];
  if (samba.lmHashEnabled) {
    updates["sambalMpassword"] = [lmHash(plaintext)];
  }
  updates["sambapwdlastset"] = [String(Math.floor(Date.now() / 1000))];

  return updates;
}

/** Extract plaintext from a userPassword value (strips {CLEARTEXT} prefix). */
function extractPlainPassword(value: string): string | null {
  if (value.startsWith("{CLEARTEXT}")) return value.slice(11);
  if (value.startsWith("{")) return null; // Hashed scheme — cannot derive NT hash
  return value;
}
