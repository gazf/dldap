export interface UserDTO {
  dn: string;
  uid: string;
  cn: string;
  sn?: string;
  givenName?: string;
  mail?: string;
  uidNumber?: number;
  gidNumber?: number;
  homeDirectory?: string;
  loginShell?: string;
  description?: string;
}

export interface GroupDTO {
  dn: string;
  cn: string;
  gidNumber?: number;
  members: string[];
  description?: string;
}

export interface OUDTO {
  dn: string;
  ou: string;
  description?: string;
}

export interface StatusDTO {
  ok: boolean;
  baseDN: string;
  adminDN: string;
  sambaEnabled: boolean;
  sambaDomain?: string;
  sambaSID?: string;
  counts: {
    users: number;
    groups: number;
    ous: number;
    total: number;
  };
}

export interface ApiError {
  message: string;
}
