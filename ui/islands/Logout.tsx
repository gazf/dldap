import { IS_BROWSER } from "fresh/runtime";
import { logout } from "../utils/api.ts";

export default function Logout() {
  if (IS_BROWSER) {
    logout().then(() => {
      globalThis.location.href = "/login";
    });
  }
  return <div class="loading">Logging out…</div>;
}
