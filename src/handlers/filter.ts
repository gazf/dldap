/**
 * LDAP search filter evaluation against directory entries.
 */

import { FilterTag } from "../ldap/constants.ts";
import type { DirectoryEntry } from "../store/types.ts";
import type { Filter } from "../ldap/messages.ts";

/** Evaluate a filter against a directory entry. */
export function matchesFilter(entry: DirectoryEntry, filter: Filter): boolean {
  switch (filter.type) {
    case FilterTag.And:
      return filter.filters.every((f) => matchesFilter(entry, f));

    case FilterTag.Or:
      return filter.filters.some((f) => matchesFilter(entry, f));

    case FilterTag.Not:
      return !matchesFilter(entry, filter.filter);

    case FilterTag.Present: {
      const attr = filter.attribute.toLowerCase();
      if (attr === "objectclass") return true; // Every entry has objectClass
      if (attr === "dn" || attr === "entrydn") return true;
      return attr in entry.attrs;
    }

    case FilterTag.EqualityMatch: {
      const attr = filter.attribute.toLowerCase();
      const val = filter.value.toLowerCase();
      if (attr === "dn" || attr === "entrydn") {
        return entry.dn === val;
      }
      const values = entry.attrs[attr] ?? [];
      return values.some((v) => v.toLowerCase() === val);
    }

    case FilterTag.Substrings: {
      const attr = filter.attribute.toLowerCase();
      const values = entry.attrs[attr] ?? [];
      return values.some((v) => matchSubstrings(v.toLowerCase(), filter));
    }

    case FilterTag.GreaterOrEqual: {
      const attr = filter.attribute.toLowerCase();
      const val = filter.value;
      const values = entry.attrs[attr] ?? [];
      return values.some((v) => v >= val);
    }

    case FilterTag.LessOrEqual: {
      const attr = filter.attribute.toLowerCase();
      const val = filter.value;
      const values = entry.attrs[attr] ?? [];
      return values.some((v) => v <= val);
    }

    case FilterTag.ApproxMatch: {
      // Treat approx as case-insensitive substring match
      const attr = filter.attribute.toLowerCase();
      const val = filter.value.toLowerCase();
      const values = entry.attrs[attr] ?? [];
      return values.some((v) => v.toLowerCase().includes(val));
    }

    default:
      return false;
  }
}

function matchSubstrings(
  value: string,
  filter: { initial?: string; any?: string[]; final?: string },
): boolean {
  let pos = 0;

  if (filter.initial !== undefined) {
    const initial = filter.initial.toLowerCase();
    if (!value.startsWith(initial)) return false;
    pos = initial.length;
  }

  if (filter.any) {
    for (const part of filter.any) {
      const p = part.toLowerCase();
      const idx = value.indexOf(p, pos);
      if (idx === -1) return false;
      pos = idx + p.length;
    }
  }

  if (filter.final !== undefined) {
    const final = filter.final.toLowerCase();
    if (!value.endsWith(final)) return false;
    if (pos > value.length - final.length) return false;
  }

  return true;
}
