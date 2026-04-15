import { useSignal } from "@preact/signals";
import { IS_BROWSER } from "fresh/runtime";
import { apiFetch, getToken } from "../utils/api.ts";
import type { StatusDTO } from "../utils/types.ts";

export default function StatusPanel() {
  const status = useSignal<StatusDTO | null>(null);
  const error = useSignal("");
  const loading = useSignal(true);
  const sidInput = useSignal("");
  const sidEditing = useSignal(false);
  const sidError = useSignal("");
  const sidSaving = useSignal(false);

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

  function openSidEdit() {
    sidInput.value = status.value?.sambaSID ?? "";
    sidError.value = "";
    sidEditing.value = true;
  }

  function cancelSidEdit() {
    sidEditing.value = false;
    sidError.value = "";
  }

  async function saveSid() {
    sidSaving.value = true;
    sidError.value = "";
    try {
      await apiFetch("/status/sid", {
        method: "PUT",
        body: JSON.stringify({ sid: sidInput.value.trim() }),
      });
      if (status.value) status.value = { ...status.value, sambaSID: sidInput.value.trim() };
      sidEditing.value = false;
    } catch (err) {
      sidError.value = err instanceof Error ? err.message : "Error";
    } finally {
      sidSaving.value = false;
    }
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
            {s.sambaEnabled ? `enabled (domain: ${s.sambaDomain ?? "—"})` : "disabled"}
          </span>
        </div>
        {s.sambaEnabled && (
          <div class="info-row">
            <span class="info-key">Domain SID</span>
            <span class="info-val" style="display:flex;align-items:center;gap:0.5rem">
              {sidEditing.value
                ? (
                  <span style="display:flex;flex-direction:column;gap:0.25rem;flex:1">
                    <span style="display:flex;gap:0.5rem;align-items:center">
                      <input
                        value={sidInput.value}
                        onInput={(e) => sidInput.value = (e.target as HTMLInputElement).value}
                        placeholder="S-1-5-21-X-X-X"
                        style="font-family:monospace;flex:1"
                      />
                      <button
                        type="button"
                        class="btn btn-primary"
                        onClick={saveSid}
                        disabled={sidSaving.value}
                      >
                        {sidSaving.value ? "Saving…" : "Save"}
                      </button>
                      <button type="button" class="btn btn-secondary" onClick={cancelSidEdit}>
                        Cancel
                      </button>
                    </span>
                    {sidError.value && (
                      <span style="color:var(--color-danger);font-size:0.85rem">
                        {sidError.value}
                      </span>
                    )}
                  </span>
                )
                : (
                  <>
                    <code>{s.sambaSID ?? "—"}</code>
                    <button type="button" class="btn btn-secondary" onClick={openSidEdit}>
                      Edit
                    </button>
                  </>
                )}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
