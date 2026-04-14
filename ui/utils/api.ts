const API_BASE = "/api";
const TOKEN_KEY = "dldap_token";

export function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

export async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((options.headers ?? {}) as Record<string, string>),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });

  if (res.status === 401) {
    clearToken();
    globalThis.location.href = "/login";
    throw new Error("Unauthorized");
  }

  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      msg = body.error ?? body.message ?? msg;
    } catch {
      msg = (await res.text()) || msg;
    }
    throw new Error(msg);
  }

  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export async function login(password: string): Promise<string> {
  const res = await fetch(`${API_BASE}/auth`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      msg = body.error ?? body.message ?? msg;
    } catch {
      msg = (await res.text()) || msg;
    }
    throw new Error(msg);
  }
  const data = await res.json();
  return data.token as string;
}

export async function logout(): Promise<void> {
  const token = getToken();
  if (token) {
    await fetch(`${API_BASE}/auth`, {
      method: "DELETE",
      headers: { "Authorization": `Bearer ${token}` },
    }).catch(() => {});
  }
  clearToken();
}
