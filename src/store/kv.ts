/**
 * Deno KV-backed directory store.
 *
 * Key layout:
 *   ["entry", dn]          → DirectoryEntry  (primary index by full DN)
 *   ["children", parentDN, dn]  → true        (secondary index for one-level listing)
 *
 * All DNs are stored in normalized (lowercase, trimmed) form.
 */

import type { DirectoryEntry, DirectoryStore } from "./types.ts";
import { normalizeDN, parentDN } from "./types.ts";

export class KvStore implements DirectoryStore {
  private constructor(private kv: Deno.Kv) {}

  /** 内部 Deno.Kv インスタンスへのアクセス（API サーバーのセッション管理用）。 */
  rawKv(): Deno.Kv {
    return this.kv;
  }

  static async open(path?: string): Promise<KvStore> {
    if (path) {
      const dir = path.substring(0, path.lastIndexOf("/"));
      if (dir) await Deno.mkdir(dir, { recursive: true });
    }
    const kv = await Deno.openKv(path);
    return new KvStore(kv);
  }

  async get(dn: string): Promise<DirectoryEntry | null> {
    const key = ["entry", normalizeDN(dn)];
    const result = await this.kv.get<DirectoryEntry>(key);
    return result.value;
  }

  async set(entry: DirectoryEntry): Promise<void> {
    const dn = normalizeDN(entry.dn);
    const parent = parentDN(dn);

    const normalized: DirectoryEntry = { dn, attrs: {} };
    for (const [k, v] of Object.entries(entry.attrs)) {
      normalized.attrs[k.toLowerCase()] = v;
    }

    const atomic = this.kv.atomic()
      .set(["entry", dn], normalized)
      .set(["children", parent, dn], true);

    const res = await atomic.commit();
    if (!res.ok) {
      throw new Error(`KV commit failed when setting entry: ${dn}`);
    }
  }

  async delete(dn: string): Promise<boolean> {
    const normalDN = normalizeDN(dn);
    const existing = await this.get(normalDN);
    if (!existing) return false;

    const parent = parentDN(normalDN);
    const atomic = this.kv.atomic()
      .delete(["entry", normalDN])
      .delete(["children", parent, normalDN]);

    const res = await atomic.commit();
    if (!res.ok) {
      throw new Error(`KV commit failed when deleting entry: ${normalDN}`);
    }
    return true;
  }

  async listChildren(parentDN_: string): Promise<DirectoryEntry[]> {
    const parent = normalizeDN(parentDN_);
    const entries: DirectoryEntry[] = [];

    const iter = this.kv.list<true>({ prefix: ["children", parent] });
    for await (const item of iter) {
      const childDN = item.key[2] as string;
      const entry = await this.get(childDN);
      if (entry) entries.push(entry);
    }

    return entries;
  }

  async listSubtree(baseDN: string): Promise<DirectoryEntry[]> {
    const base = normalizeDN(baseDN);
    const entries: DirectoryEntry[] = [];

    // All entries whose DN ends with the base DN suffix
    // We iterate the entire entry space and filter.
    // For small directories this is fine; for large ones add prefix index if needed.
    const iter = this.kv.list<DirectoryEntry>({ prefix: ["entry"] });
    for await (const item of iter) {
      const dn = item.key[1] as string;
      if (dn === base) continue; // Exclude base itself
      if (dn.endsWith(`,${base}`) || dn === base) {
        if (item.value) entries.push(item.value);
      }
    }

    return entries;
  }

  async rename(oldDN: string, newDN: string): Promise<void> {
    const oldNorm = normalizeDN(oldDN);
    const newNorm = normalizeDN(newDN);

    const existing = await this.get(oldNorm);
    if (!existing) {
      throw new Error(`Entry not found: ${oldNorm}`);
    }

    const oldParent = parentDN(oldNorm);
    const newParent = parentDN(newNorm);

    const newEntry: DirectoryEntry = { ...existing, dn: newNorm };

    const atomic = this.kv.atomic()
      .delete(["entry", oldNorm])
      .delete(["children", oldParent, oldNorm])
      .set(["entry", newNorm], newEntry)
      .set(["children", newParent, newNorm], true);

    const res = await atomic.commit();
    if (!res.ok) {
      throw new Error(`KV commit failed when renaming ${oldNorm} → ${newNorm}`);
    }
  }

  async close(): Promise<void> {
    this.kv.close();
  }

  async allocateUid(start: number): Promise<number> {
    const key = ["config", "next_uid"];
    while (true) {
      const entry = await this.kv.get<number>(key);
      const current = entry.value ?? start;
      const result = await this.kv.atomic().check(entry).set(key, current + 1).commit();
      if (result.ok) return current;
    }
  }

  async allocateGid(start: number): Promise<number> {
    const key = ["config", "next_gid"];
    while (true) {
      const entry = await this.kv.get<number>(key);
      const current = entry.value ?? start;
      const result = await this.kv.atomic().check(entry).set(key, current + 1).commit();
      if (result.ok) return current;
    }
  }
}
