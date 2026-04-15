/**
 * dldap — Public library API.
 *
 * Use this when embedding dldap as a library in another Deno project.
 */

// Core server
export { createServer } from "./src/server.ts";
export type { Server } from "./src/server.ts";

// Store
export { KvStore } from "./src/store/kv.ts";
export type { DirectoryEntry, DirectoryStore } from "./src/store/types.ts";

// Config
export { defaultConfig } from "./config/default.ts";
export type { Config, SambaConfig } from "./config/default.ts";

// Samba utilities
export { lmHash, md4, ntHash } from "./src/samba/hash.ts";
export { buildSID, generateDomainSID, groupRID, userRID } from "./src/samba/sid.ts";

// LDAP messages and types
export type { Filter, LdapMessage } from "./src/ldap/messages.ts";
export { ResultCode, SearchScope } from "./src/ldap/constants.ts";
