import { ResultCode, SearchScope } from "../ldap/constants.ts";
import { ProtocolOp } from "../ldap/constants.ts";
import type {
  PartialAttribute,
  SearchRequest,
  SearchResultDone,
  SearchResultEntry,
} from "../ldap/messages.ts";
import { errorResult, successResult } from "../ldap/messages.ts";
import type { DirectoryEntry } from "../store/types.ts";
import { normalizeDN } from "../store/types.ts";
import type { Config } from "../../config/default.ts";
import type { HandlerContext } from "./context.ts";
import { matchesFilter } from "./filter.ts";

function buildSambaDomainEntry(config: Config): DirectoryEntry {
  const dn = `sambaDomainName=${config.samba.domain},${config.baseDN}`.toLowerCase();
  return {
    dn,
    attrs: {
      objectclass: ["top", "sambaDomain"],
      sambadomainname: [config.samba.domain],
      sambasid: [config.samba.domainSID],
    },
  };
}

export interface SearchResult {
  entries: SearchResultEntry[];
  done: SearchResultDone;
}

export async function handleSearch(
  req: SearchRequest,
  ctx: HandlerContext,
): Promise<SearchResult> {
  const baseDN = normalizeDN(req.baseObject);

  // Collect candidates based on scope
  let candidates: DirectoryEntry[];

  try {
    if (req.scope === SearchScope.BaseObject) {
      const entry = await ctx.store.get(baseDN);
      candidates = entry ? [entry] : [];
    } else if (req.scope === SearchScope.SingleLevel) {
      candidates = await ctx.store.listChildren(baseDN);
    } else {
      // WholeSubtree
      const base = await ctx.store.get(baseDN);
      const subtree = await ctx.store.listSubtree(baseDN);
      candidates = base ? [base, ...subtree] : subtree;
    }
  } catch {
    return {
      entries: [],
      done: {
        type: ProtocolOp.SearchResultDone,
        result: errorResult(ResultCode.NoSuchObject, `Base object not found: ${baseDN}`),
      },
    };
  }

  if (ctx.config.samba.enabled) {
    const virtual = buildSambaDomainEntry(ctx.config);
    if (req.scope === SearchScope.BaseObject) {
      if (virtual.dn === baseDN) candidates = [virtual];
    } else {
      candidates = [...candidates, virtual];
    }
  }

  const entries: SearchResultEntry[] = [];

  for (const entry of candidates) {
    if (!matchesFilter(entry, req.filter)) continue;

    const attrs = selectAttributes(entry, req.attributes, req.typesOnly);
    entries.push({
      type: ProtocolOp.SearchResultEntry,
      objectName: entry.dn,
      attributes: attrs,
    });

    if (req.sizeLimit > 0 && entries.length >= req.sizeLimit) {
      return {
        entries,
        done: {
          type: ProtocolOp.SearchResultDone,
          result: errorResult(ResultCode.SizeLimitExceeded, "Size limit exceeded"),
        },
      };
    }
  }

  return {
    entries,
    done: { type: ProtocolOp.SearchResultDone, result: successResult() },
  };
}

/**
 * Select attributes to return based on the requested attribute list.
 * Empty list or "*" means return all user attributes.
 * "+" means return operational attributes (not implemented here).
 */
function selectAttributes(
  entry: DirectoryEntry,
  requested: string[],
  typesOnly: boolean,
): PartialAttribute[] {
  const all = requested.length === 0 || requested.includes("*");
  const result: PartialAttribute[] = [];

  // Always include objectClass if not explicitly excluded
  const attrMap = entry.attrs;

  const include = (attrName: string): boolean => {
    if (all) return true;
    return requested.some((r) => r.toLowerCase() === attrName.toLowerCase());
  };

  for (const [type, values] of Object.entries(attrMap)) {
    if (!include(type)) continue;
    result.push({
      type,
      values: typesOnly ? [] : values,
    });
  }

  return result;
}
