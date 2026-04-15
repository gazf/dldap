export interface PosixConfig {
  /** Starting UID for auto-allocation (default: 1000) */
  uidStart: number;
  /** Starting GID for auto-allocation (default: 1000) */
  gidStart: number;
  /** Base path for auto-generated homeDirectory (default: /home) */
  homeBase: string;
  /** Default loginShell when not specified (default: /bin/bash) */
  defaultShell: string;
}

export interface SambaConfig {
  enabled: boolean;
  /** Domain SID e.g. S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX */
  domainSID: string;
  domain: string;
  /** Automatically generate sambaNTPassword when userPassword is set */
  autoHash: boolean;
  /** Generate sambaLMPassword (deprecated, insecure) */
  lmHashEnabled: boolean;
}

export interface Config {
  port: number;
  host: string;
  /** Base DN e.g. dc=example,dc=com */
  baseDN: string;
  /** Admin DN */
  adminDN: string;
  adminPassword: string;
  /** Deno KV file path. Omit to use Deno default location. */
  kvPath?: string;
  samba: SambaConfig;
  posix: PosixConfig;
}

export const defaultConfig: Config = {
  port: 389,
  host: "0.0.0.0",
  baseDN: "dc=example,dc=com",
  adminDN: "cn=admin,dc=example,dc=com",
  adminPassword: "", // 必ず LDAP_ADMIN_PW 環境変数で上書きすること
  kvPath: "./db/dldap.kv",
  samba: {
    enabled: true,
    domainSID: "", // 起動時に KV から読み込むか新規生成する
    domain: "WORKGROUP",
    autoHash: false,
    lmHashEnabled: false,
  },
  posix: {
    uidStart: 1000,
    gidStart: 1000,
    homeBase: "/home",
    defaultShell: "/bin/bash",
  },
};
