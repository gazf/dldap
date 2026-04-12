import { useSignal } from "@preact/signals";
import { IS_BROWSER } from "fresh/runtime";
import { apiFetch, getToken } from "../utils/api.ts";
import type { StatusDTO } from "../utils/types.ts";

export default function StatusPanel() {
  const status = useSignal<StatusDTO | null>(null);
  const error = useSignal("");
  const loading = useSignal(true);

  if (IS_BROWSER && !getToken()) {
    globalThis.location.href = "/login";
    return <div class="loading">Redirecting…</div>;
  }

  if (IS_BROWSER && loading.value && !status.value && !error.value) {
    apiFetch<StatusDTO>("/status")
      .then((s) => {
        status.value = s;
        loading.value = false;
      })
      .catch((err) => {
        error.value = err instanceof Error ? err.message : "Error";
        loading.value = false;
      });
  }

  if (loading.value) return <div class="loading">Loading…</div>;
  if (error.value) return <div class="alert alert-error">{error.value}</div>;
  if (!status.value) return null;

  const s = status.value;
  return (
    <div>
      <div class="stat-grid">
        <div class="stat-card">
          <div class="label">Users</div>
          <div class="value">{s.counts.users}</div>
        </div>
        <div class="stat-card">
          <div class="label">Groups</div>
          <div class="value">{s.counts.groups}</div>
        </div>
        <div class="stat-card">
          <div class="label">OUs</div>
          <div class="value">{s.counts.ous}</div>
        </div>
        <div class="stat-card">
          <div class="label">Total entries</div>
          <div class="value">{s.counts.total}</div>
        </div>
      </div>

      <div class="info-table">
        <div class="info-row">
          <span class="info-key">Base DN</span>
          <span class="info-val">{s.baseDN}</span>
        </div>
        <div class="info-row">
          <span class="info-key">Admin DN</span>
          <span class="info-val">{s.adminDN}</span>
        </div>
        <div class="info-row">
          <span class="info-key">Samba</span>
          <span class="info-val">
            {s.sambaEnabled
              ? `enabled (domain: ${s.sambaDomain ?? "—"})`
              : "disabled"}
          </span>
        </div>
      </div>
    </div>
  );
}
