/**
 * RADIUS authentication helpers.
 * Mirrors the pattern in src/handlers/bind.ts.
 */

import type { DirectoryEntry, DirectoryStore } from "../store/types.ts";

// ---------------------------------------------------------------------------
// User lookup
// ---------------------------------------------------------------------------

/**
 * Find a user entry by uid attribute.
 * Searches ou=users,<baseDN> first, then falls back to full subtree scan.
 */
export async function findUserByUid(
  uid: string,
  store: DirectoryStore,
  baseDN: string,
): Promise<DirectoryEntry | null> {
  // Primary: ou=users subtree (matches the REST API convention)
  const usersOU = `ou=users,${baseDN}`.toLowerCase();
  try {
    const candidates = await store.listSubtree(usersOU);
    const found = candidates.find((e) => e.attrs["uid"]?.[0] === uid);
    if (found) return found;
  } catch {
    // ou=users may not exist — fall through to full scan
  }

  // Fallback: full subtree
  const all = await store.listSubtree(baseDN.toLowerCase());
  return all.find((e) => e.attrs["uid"]?.[0] === uid) ?? null;
}

// ---------------------------------------------------------------------------
// PAP: plaintext password verification
// ---------------------------------------------------------------------------

/**
 * Verify a plaintext password against the userPassword attribute.
 * Supports bare plaintext and {CLEARTEXT} prefix (same as bind.ts).
 */
export function verifyPassword(entry: DirectoryEntry, password: string): boolean {
  const passwords = entry.attrs["userpassword"] ?? [];
  return passwords.some((p) => {
    if (p.startsWith("{CLEARTEXT}")) return p.slice(11) === password;
    return p === password;
  });
}

export async function verifyPap(
  username: string,
  plainPassword: string,
  store: DirectoryStore,
  baseDN: string,
): Promise<boolean> {
  const entry = await findUserByUid(username, store, baseDN);
  if (!entry) return false;
  return verifyPassword(entry, plainPassword);
}

// ---------------------------------------------------------------------------
// EAP-MSCHAPv2: NT hash retrieval
// ---------------------------------------------------------------------------

/**
 * Retrieve the NT hash for a user from the sambaNTPassword attribute.
 * Returns null if the user is not found or the attribute is missing.
 *
 * Callers should log a warning when null is returned (SAMBA_AUTO_HASH may be disabled).
 */
export async function getNtHash(
  username: string,
  store: DirectoryStore,
  baseDN: string,
): Promise<Uint8Array | null> {
  const entry = await findUserByUid(username, store, baseDN);
  if (!entry) return null;

  const hex = entry.attrs["sambantpassword"]?.[0];
  if (!hex || hex.length !== 32) return null;

  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
