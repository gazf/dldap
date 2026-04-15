import { useSignal } from "@preact/signals";
import { IS_BROWSER } from "fresh/runtime";
import { apiFetch, getToken } from "../utils/api.ts";
import type { OUDTO } from "../utils/types.ts";

type ModalMode = "create" | "delete" | null;

const EMPTY_FORM = {
  ou: "",
  description: "",
};

export default function OuList() {
  const ous = useSignal<OUDTO[]>([]);
  const loading = useSignal(true);
  const error = useSignal("");
  const modalMode = useSignal<ModalMode>(null);
  const selectedOu = useSignal<OUDTO | null>(null);
  const form = useSignal({ ...EMPTY_FORM });
  const formError = useSignal("");
  const formLoading = useSignal(false);

  if (IS_BROWSER && !getToken()) {
    globalThis.location.href = "/login";
    return <div class="loading">Redirecting…</div>;
  }

  async function load() {
    loading.value = true;
    error.value = "";
    try {
      ous.value = await apiFetch<OUDTO[]>("/ous");
    } catch (err) {
      error.value = err instanceof Error ? err.message : "Error";
    } finally {
      loading.value = false;
    }
  }

  if (IS_BROWSER && loading.value && ous.value.length === 0 && !error.value) {
    load();
  }

  function openCreate() {
    form.value = { ...EMPTY_FORM };
    formError.value = "";
    modalMode.value = "create";
  }

  function openDelete(ou: OUDTO) {
    selectedOu.value = ou;
    formError.value = "";
    modalMode.value = "delete";
  }

  function closeModal() {
    modalMode.value = null;
    selectedOu.value = null;
  }

  function setField(key: keyof typeof EMPTY_FORM) {
    return (e: Event) => {
      form.value = { ...form.value, [key]: (e.target as HTMLInputElement).value };
    };
  }

  async function submitCreate() {
    formLoading.value = true;
    formError.value = "";
    try {
      const f = form.value;
      const body: Record<string, string> = { ou: f.ou };
      if (f.description) body.description = f.description;
      await apiFetch("/ous", { method: "POST", body: JSON.stringify(body) });
      closeModal();
      await load();
    } catch (err) {
      formError.value = err instanceof Error ? err.message : "Error";
    } finally {
      formLoading.value = false;
    }
  }

  async function submitDelete() {
    if (!selectedOu.value) return;
    formLoading.value = true;
    formError.value = "";
    try {
      await apiFetch(`/ous/${encodeURIComponent(selectedOu.value.ou)}`, { method: "DELETE" });
      closeModal();
      await load();
    } catch (err) {
      formError.value = err instanceof Error ? err.message : "Error";
    } finally {
      formLoading.value = false;
    }
  }

  return (
    <div>
      {error.value && <div class="alert alert-error">{error.value}</div>}

      <div class="toolbar">
        <button type="button" class="btn btn-primary" onClick={openCreate}>+ Add OU</button>
        <button type="button" class="btn btn-secondary" onClick={load} disabled={loading.value}>
          Refresh
        </button>
      </div>

      {loading.value
        ? <div class="loading">Loading…</div>
        : ous.value.length === 0
        ? <div class="empty">No OUs found.</div>
        : (
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>OU</th>
                  <th>DN</th>
                  <th>Description</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {ous.value.map((ou) => (
                  <tr key={ou.ou}>
                    <td>
                      <code>{ou.ou}</code>
                    </td>
                    <td style="font-family:monospace;font-size:0.8rem;color:#555">{ou.dn}</td>
                    <td>{ou.description ?? "—"}</td>
                    <td>
                      <button type="button" class="btn btn-danger" onClick={() => openDelete(ou)}>
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

      {/* Create modal */}
      {modalMode.value === "create" && (
        <div class="modal-overlay" onClick={closeModal}>
          <div class="modal" onClick={(e) => e.stopPropagation()}>
            <div class="modal-header">
              <h3>Add OU</h3>
              <button type="button" class="btn btn-secondary" onClick={closeModal}>✕</button>
            </div>
            <div class="modal-body">
              {formError.value && <div class="alert alert-error">{formError.value}</div>}
              <div class="form-group">
                <label>OU name *</label>
                <input
                  value={form.value.ou}
                  onInput={setField("ou")}
                  required
                  placeholder="e.g. engineering"
                />
              </div>
              <div class="form-group">
                <label>Description</label>
                <input value={form.value.description} onInput={setField("description")} />
              </div>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary" onClick={closeModal}>Cancel</button>
              <button
                type="button"
                class="btn btn-primary"
                onClick={submitCreate}
                disabled={formLoading.value}
              >
                {formLoading.value ? "Saving…" : "Create"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete modal */}
      {modalMode.value === "delete" && (
        <div class="modal-overlay" onClick={closeModal}>
          <div class="modal" onClick={(e) => e.stopPropagation()}>
            <div class="modal-header">
              <h3>Delete OU</h3>
              <button type="button" class="btn btn-secondary" onClick={closeModal}>✕</button>
            </div>
            <div class="modal-body">
              {formError.value && <div class="alert alert-error">{formError.value}</div>}
              <p>
                Delete OU{" "}
                <strong>{selectedOu.value?.ou}</strong>? The OU must be empty before it can be
                deleted.
              </p>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary" onClick={closeModal}>Cancel</button>
              <button
                type="button"
                class="btn btn-danger"
                onClick={submitDelete}
                disabled={formLoading.value}
              >
                {formLoading.value ? "Deleting…" : "Delete"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
