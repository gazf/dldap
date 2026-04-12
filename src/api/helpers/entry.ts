/**
 * DirectoryEntry ↔ DTO 変換ヘルパー。
 *
 * LDAP エントリの生の属性マップを REST API が返す型安全な DTO に変換する。
 * objectClass によってエントリ種別（ユーザー／グループ／OU）を判定する。
 */

import type { DirectoryEntry, DirectoryStore } from "../../store/types.ts";

// ---------------------------------------------------------------------------
// DTO 型定義
// ---------------------------------------------------------------------------

export interface UserDTO {
  uid: string;
  dn: string;
  cn: string;
  sn?: string;
  givenName?: string;
  mail?: string;
  uidNumber?: number;
  gidNumber?: number;
  homeDirectory?: string;
  loginShell?: string;
  description?: string;
  objectClasses: string[];
  /** sambaSamAccount の場合のみ存在 */
  sambaSID?: string;
  sambaAcctFlags?: string;
}

export interface GroupDTO {
  cn: string;
  dn: string;
  gidNumber?: number;
  description?: string;
  /** memberUid 属性の配列（posixGroup）または member 属性の DN 配列（groupOfNames） */
  members: string[];
  objectClasses: string[];
}

export interface OUDTO {
  ou: string;
  dn: string;
  description?: string;
  objectClasses: string[];
}

export interface StatusDTO {
  ok: boolean;
  baseDN: string;
  adminDN: string;
  sambaEnabled: boolean;
  sambaDomain?: string;
  counts: {
    users: number;
    groups: number;
    ous: number;
    total: number;
  };
}

// ---------------------------------------------------------------------------
// エントリ種別判定
// ---------------------------------------------------------------------------

export function isUser(entry: DirectoryEntry): boolean {
  const oc = entry.attrs["objectclass"] ?? [];
  return oc.includes("posixaccount") || oc.includes("inetorgperson");
}

export function isGroup(entry: DirectoryEntry): boolean {
  const oc = entry.attrs["objectclass"] ?? [];
  return oc.includes("posixgroup") || oc.includes("groupofnames");
}

export function isOU(entry: DirectoryEntry): boolean {
  const oc = entry.attrs["objectclass"] ?? [];
  return oc.includes("organizationalunit");
}

// ---------------------------------------------------------------------------
// DirectoryEntry → DTO 変換
// ---------------------------------------------------------------------------

export function entryToUser(entry: DirectoryEntry): UserDTO {
  const a = entry.attrs;
  const dto: UserDTO = {
    uid: first(a["uid"]) ?? "",
    dn: entry.dn,
    cn: first(a["cn"]) ?? "",
    objectClasses: a["objectclass"] ?? [],
  };

  if (a["sn"]) dto.sn = first(a["sn"]);
  if (a["givenname"]) dto.givenName = first(a["givenname"]);
  if (a["mail"]) dto.mail = first(a["mail"]);
  if (a["uidnumber"]) dto.uidNumber = parseInt(first(a["uidnumber"])!, 10);
  if (a["gidnumber"]) dto.gidNumber = parseInt(first(a["gidnumber"])!, 10);
  if (a["homedirectory"]) dto.homeDirectory = first(a["homedirectory"]);
  if (a["loginshell"]) dto.loginShell = first(a["loginshell"]);
  if (a["description"]) dto.description = first(a["description"]);
  if (a["sambasid"]) dto.sambaSID = first(a["sambasid"]);
  if (a["sambaacctflags"]) dto.sambaAcctFlags = first(a["sambaacctflags"]);

  return dto;
}

export function entryToGroup(entry: DirectoryEntry): GroupDTO {
  const a = entry.attrs;
  const dto: GroupDTO = {
    cn: first(a["cn"]) ?? "",
    dn: entry.dn,
    // posixGroup は memberUid（UID 文字列）、groupOfNames は member（DN 文字列）
    members: a["memberuid"] ?? a["member"] ?? [],
    objectClasses: a["objectclass"] ?? [],
  };

  if (a["gidnumber"]) dto.gidNumber = parseInt(first(a["gidnumber"])!, 10);
  if (a["description"]) dto.description = first(a["description"]);

  return dto;
}

export function entryToOU(entry: DirectoryEntry): OUDTO {
  const a = entry.attrs;
  const dto: OUDTO = {
    ou: first(a["ou"]) ?? "",
    dn: entry.dn,
    objectClasses: a["objectclass"] ?? [],
  };

  if (a["description"]) dto.description = first(a["description"]);

  return dto;
}

// ---------------------------------------------------------------------------
// ストアからの一覧取得
// ---------------------------------------------------------------------------

export async function findUsers(
  store: DirectoryStore,
  baseDN: string,
): Promise<UserDTO[]> {
  const usersOU = `ou=users,${baseDN}`;
  const entries = await store.listSubtree(usersOU);
  return entries.filter(isUser).map(entryToUser);
}

export async function findGroups(
  store: DirectoryStore,
  baseDN: string,
): Promise<GroupDTO[]> {
  const groupsOU = `ou=groups,${baseDN}`;
  const entries = await store.listSubtree(groupsOU);
  return entries.filter(isGroup).map(entryToGroup);
}

export async function findOUs(
  store: DirectoryStore,
  baseDN: string,
): Promise<OUDTO[]> {
  const entries = await store.listChildren(baseDN);
  return entries.filter(isOU).map(entryToOU);
}

// ---------------------------------------------------------------------------
// ユーティリティ
// ---------------------------------------------------------------------------

function first(arr: string[] | undefined): string | undefined {
  return arr?.[0];
}
