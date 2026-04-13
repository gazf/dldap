/**
 * Directory store interface — the abstraction layer over Deno KV.
 */

export interface DirectoryEntry {
  /** Distinguished Name (normalized to lowercase) */
  dn: string;
  /** Attribute map: attribute type (lowercase) → array of values */
  attrs: Record<string, string[]>;
}

export interface DirectoryStore {
  /** Retrieve a single entry by exact DN. Returns null if not found. */
  get(dn: string): Promise<DirectoryEntry | null>;

  /** Store or overwrite an entry. */
  set(entry: DirectoryEntry): Promise<void>;

  /** Delete an entry by DN. Returns false if not found. */
  delete(dn: string): Promise<boolean>;

  /** List all direct children of a DN (one level). */
  listChildren(parentDN: string): Promise<DirectoryEntry[]>;

  /** List all descendants of a DN (whole subtree, excluding the base itself). */
  listSubtree(baseDN: string): Promise<DirectoryEntry[]>;

  /** Rename/move an entry. */
  rename(oldDN: string, newDN: string): Promise<void>;

  /** Close/cleanup the store. */
  close(): Promise<void>;

  /** Atomically allocate the next UID (>= start) and increment the counter. */
  allocateUid(start: number): Promise<number>;

  /** Atomically allocate the next GID (>= start) and increment the counter. */
  allocateGid(start: number): Promise<number>;
}

/** Normalize a DN for consistent storage/comparison. */
export function normalizeDN(dn: string): string {
  return dn.trim().toLowerCase();
}

/** Parse a DN into its RDN components (outermost first). */
export function parseDN(dn: string): string[] {
  // Simple split on comma — does not handle escaped commas
  return dn.split(",").map((s) => s.trim());
}

/** Get the parent DN of a given DN. Returns empty string for top-level. */
export function parentDN(dn: string): string {
  const parts = parseDN(dn);
  if (parts.length <= 1) return "";
  return parts.slice(1).join(",");
}
