import { useSignal } from "@preact/signals";
import { login, setToken } from "../utils/api.ts";

export default function Login() {
  const password = useSignal("");
  const error = useSignal("");
  const loading = useSignal(false);

  async function handleSubmit(e: Event) {
    e.preventDefault();
    error.value = "";
    loading.value = true;
    try {
      const token = await login(password.value);
      setToken(token);
      globalThis.location.href = "/status";
    } catch (err) {
      error.value = err instanceof Error ? err.message : "Login failed";
    } finally {
      loading.value = false;
    }
  }

  return (
    <div class="login-page">
      <div class="login-card">
        <h1>dldap admin</h1>
        {error.value && <div class="alert alert-error">{error.value}</div>}
        <form onSubmit={handleSubmit}>
          <div class="form-group">
            <label>Admin password</label>
            <input
              type="password"
              value={password.value}
              onInput={(e) => (password.value = (e.target as HTMLInputElement).value)}
              placeholder="Password"
              autofocus
              required
            />
          </div>
          <button type="submit" class="btn btn-primary btn-full" disabled={loading.value}>
            {loading.value ? "Logging in…" : "Login"}
          </button>
        </form>
      </div>
    </div>
  );
}
