/**
 * Samba SID (Security Identifier) generation and management.
 *
 * SID format: S-1-5-21-<sub1>-<sub2>-<sub3>-<RID>
 *
 * Well-known RIDs:
 *   500 - Administrator
 *   501 - Guest
 *   512 - Domain Admins (group)
 *   513 - Domain Users (group)
 *   514 - Domain Guests (group)
 */

export const WELL_KNOWN_RIDS = {
  ADMINISTRATOR: 500,
  GUEST: 501,
  DOMAIN_ADMINS: 512,
  DOMAIN_USERS: 513,
  DOMAIN_GUESTS: 514,
} as const;

/** Compute user RID from uidNumber (Samba convention). */
export function userRID(uidNumber: number): number {
  return uidNumber * 2 + 1000;
}

/** Compute group RID from gidNumber (Samba convention). */
export function groupRID(gidNumber: number): number {
  return gidNumber * 2 + 1001;
}

/** Build a full SID from domain SID and RID. */
export function buildSID(domainSID: string, rid: number): string {
  return `${domainSID}-${rid}`;
}

/**
 * Generate a random domain SID of the form S-1-5-21-X-X-X.
 * Each sub-authority is a 32-bit unsigned integer.
 */
export function generateDomainSID(): string {
  const buf = new Uint32Array(3);
  crypto.getRandomValues(buf);
  return `S-1-5-21-${buf[0]}-${buf[1]}-${buf[2]}`;
}

/**
 * Determine the RID for a new user/group entry.
 * Prefers uidNumber/gidNumber attributes; falls back to a sequential counter.
 */
export function resolveUserSID(
  domainSID: string,
  attrs: Record<string, string[]>,
): string {
  const uidNumbers = attrs["uidnumber"] ?? attrs["uidNumber"] ?? [];
  if (uidNumbers.length > 0) {
    const uid = parseInt(uidNumbers[0], 10);
    if (!isNaN(uid)) return buildSID(domainSID, userRID(uid));
  }
  // Fallback: use a high RID unlikely to collide
  return buildSID(domainSID, 1000 + Math.floor(Math.random() * 50000));
}

export function resolveGroupSID(
  domainSID: string,
  attrs: Record<string, string[]>,
): string {
  const gidNumbers = attrs["gidnumber"] ?? attrs["gidNumber"] ?? [];
  if (gidNumbers.length > 0) {
    const gid = parseInt(gidNumbers[0], 10);
    if (!isNaN(gid)) return buildSID(domainSID, groupRID(gid));
  }
  return buildSID(domainSID, 1001 + Math.floor(Math.random() * 50000));
}

/**
 * Determine the primary group SID from gidNumber.
 * Defaults to Domain Users (RID 513).
 */
export function resolvePrimaryGroupSID(
  domainSID: string,
  attrs: Record<string, string[]>,
): string {
  const gids = attrs["gidnumber"] ?? attrs["gidNumber"] ?? [];
  if (gids.length > 0) {
    const gid = parseInt(gids[0], 10);
    if (!isNaN(gid)) return buildSID(domainSID, groupRID(gid));
  }
  return buildSID(domainSID, WELL_KNOWN_RIDS.DOMAIN_USERS);
}
