import { useSignal } from "@preact/signals";
import { IS_BROWSER } from "fresh/runtime";
import { apiFetch, getToken } from "../utils/api.ts";
import type { GroupDTO } from "../utils/types.ts";

type ModalMode = "create" | "edit" | "delete" | "member" | null;

const EMPTY_FORM = {
  cn: "",
  gidNumber: "",
  description: "",
  memberUid: "",
};

export default function GroupList() {
  const groups = useSignal<GroupDTO[]>([]);
  const loading = useSignal(true);
  const error = useSignal("");
  const modalMode = useSignal<ModalMode>(null);
  const selectedGroup = useSignal<GroupDTO | null>(null);
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
      groups.value = await apiFetch<GroupDTO[]>("/groups");
    } catch (err) {
      error.value = err instanceof Error ? err.message : "Error";
    } finally {
      loading.value = false;
    }
  }

  if (IS_BROWSER && loading.value && groups.value.length === 0 && !error.value) {
    load();
  }

  function openCreate() {
    form.value = { ...EMPTY_FORM };
    formError.value = "";
    modalMode.value = "create";
  }

  function openEdit(g: GroupDTO) {
    selectedGroup.value = g;
    form.value = {
      cn: g.cn,
      gidNumber: g.gidNumber != null ? String(g.gidNumber) : "",
      description: g.description ?? "",
      memberUid: "",
    };
    formError.value = "";
    modalMode.value = "edit";
  }

  function openDelete(g: GroupDTO) {
    selectedGroup.value = g;
    formError.value = "";
    modalMode.value = "delete";
  }

  function openMember(g: GroupDTO) {
    selectedGroup.value = g;
    form.value = { ...EMPTY_FORM };
    formError.value = "";
    modalMode.value = "member";
  }

  function closeModal() {
    modalMode.value = null;
    selectedGroup.value = null;
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
      const body: Record<string, string> = { cn: f.cn };
      if (f.gidNumber) body.gidNumber = f.gidNumber;
      if (f.description) body.description = f.description;
      await apiFetch("/groups", { method: "POST", body: JSON.stringify(body) });
      closeModal();
      await load();
    } catch (err) {
      formError.value = err instanceof Error ? err.message : "Error";
    } finally {
      formLoading.value = false;
    }
  }

  async function submitEdit() {
    if (!selectedGroup.value) return;
    formLoading.value = true;
    formError.value = "";
    try {
      const f = form.value;
      const body: Record<string, string> = {};
      if (f.gidNumber !== undefined) body.gidNumber = f.gidNumber;
      if (f.description !== undefined) body.description = f.description;
      await apiFetch(`/groups/${selectedGroup.value.cn}`, {
        method: "PUT",
        body: JSON.stringify(body),
      });
      closeModal();
      await load();
    } catch (err) {
      formError.value = err instanceof Error ? err.message : "Error";
    } finally {
      formLoading.value = false;
    }
  }

  async function submitDelete() {
    if (!selectedGroup.value) return;
    formLoading.value = true;
    formError.value = "";
    try {
      await apiFetch(`/groups/${selectedGroup.value.cn}`, { method: "DELETE" });
      closeModal();
      await load();
    } catch (err) {
      formError.value = err instanceof Error ? err.message : "Error";
    } finally {
      formLoading.value = false;
    }
  }

  async function submitAddMember() {
    if (!selectedGroup.value) return;
    formLoading.value = true;
    formError.value = "";
    try {
      await apiFetch(`/groups/${selectedGroup.value.cn}/members`, {
        method: "POST",
        body: JSON.stringify({ uid: form.value.memberUid }),
      });
      closeModal();
      await load();
    } catch (err) {
      formError.value = err instanceof Error ? err.message : "Error";
    } finally {
      formLoading.value = false;
    }
  }

  async function removeMember(cn: string, uid: string) {
    try {
      await apiFetch(`/groups/${cn}/members/${uid}`, { method: "DELETE" });
      await load();
    } catch (err) {
      error.value = err instanceof Error ? err.message : "Error";
    }
  }

  return (
    <div>
      {error.value && <div class="alert alert-error">{error.value}</div>}

      <div class="toolbar">
        <button class="btn btn-primary" onClick={openCreate}>+ Add Group</button>
        <button class="btn btn-secondary" onClick={load} disabled={loading.value}>
          Refresh
        </button>
      </div>

      {loading.value
        ? <div class="loading">Loading…</div>
        : groups.value.length === 0
        ? <div class="empty">No groups found.</div>
        : (
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>CN</th>
                  <th>GID#</th>
                  <th>Members</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {groups.value.map((g) => (
                  <tr key={g.cn}>
                    <td><code>{g.cn}</code></td>
                    <td>{g.gidNumber ?? "—"}</td>
                    <td>
                      {g.members.length === 0
                        ? <span style="color:#aaa">—</span>
                        : g.members.map((m) => (
                          <span key={m} class="tag">
                            {m}
                            <button
                              onClick={() => removeMember(g.cn, m)}
                              style="background:none;border:none;cursor:pointer;margin-left:2px;color:#888;font-size:0.7rem"
                              title={`Remove ${m}`}
                            >
                              ✕
                            </button>
                          </span>
                        ))}
                    </td>
                    <td>
                      <span style="display:flex;gap:4px">
                        <button class="btn btn-secondary" onClick={() => openMember(g)}>+ Member</button>
                        <button class="btn btn-secondary" onClick={() => openEdit(g)}>Edit</button>
                        <button class="btn btn-danger" onClick={() => openDelete(g)}>Delete</button>
                      </span>
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
              <h3>Add Group</h3>
              <button class="btn btn-secondary" onClick={closeModal}>✕</button>
            </div>
            <div class="modal-body">
              {formError.value && <div class="alert alert-error">{formError.value}</div>}
              <div class="form-group">
                <label>CN *</label>
                <input value={form.value.cn} onInput={setField("cn")} required />
              </div>
              <div class="form-group">
                <label>GID Number</label>
                <input type="number" value={form.value.gidNumber} onInput={setField("gidNumber")} />
              </div>
              <div class="form-group">
                <label>Description</label>
                <input value={form.value.description} onInput={setField("description")} />
              </div>
            </div>
            <div class="modal-footer">
              <button class="btn btn-secondary" onClick={closeModal}>Cancel</button>
              <button class="btn btn-primary" onClick={submitCreate} disabled={formLoading.value}>
                {formLoading.value ? "Saving…" : "Create"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit modal */}
      {modalMode.value === "edit" && (
        <div class="modal-overlay" onClick={closeModal}>
          <div class="modal" onClick={(e) => e.stopPropagation()}>
            <div class="modal-header">
              <h3>Edit Group: {selectedGroup.value?.cn}</h3>
              <button class="btn btn-secondary" onClick={closeModal}>✕</button>
            </div>
            <div class="modal-body">
              {formError.value && <div class="alert alert-error">{formError.value}</div>}
              <div class="form-group">
                <label>GID Number</label>
                <input type="number" value={form.value.gidNumber} onInput={setField("gidNumber")} />
              </div>
              <div class="form-group">
                <label>Description</label>
                <input value={form.value.description} onInput={setField("description")} />
              </div>
            </div>
            <div class="modal-footer">
              <button class="btn btn-secondary" onClick={closeModal}>Cancel</button>
              <button class="btn btn-primary" onClick={submitEdit} disabled={formLoading.value}>
                {formLoading.value ? "Saving…" : "Save"}
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
              <h3>Delete Group</h3>
              <button class="btn btn-secondary" onClick={closeModal}>✕</button>
            </div>
            <div class="modal-body">
              {formError.value && <div class="alert alert-error">{formError.value}</div>}
              <p>
                Delete group <strong>{selectedGroup.value?.cn}</strong>? This cannot be undone.
              </p>
            </div>
            <div class="modal-footer">
              <button class="btn btn-secondary" onClick={closeModal}>Cancel</button>
              <button class="btn btn-danger" onClick={submitDelete} disabled={formLoading.value}>
                {formLoading.value ? "Deleting…" : "Delete"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add member modal */}
      {modalMode.value === "member" && (
        <div class="modal-overlay" onClick={closeModal}>
          <div class="modal" onClick={(e) => e.stopPropagation()}>
            <div class="modal-header">
              <h3>Add Member to: {selectedGroup.value?.cn}</h3>
              <button class="btn btn-secondary" onClick={closeModal}>✕</button>
            </div>
            <div class="modal-body">
              {formError.value && <div class="alert alert-error">{formError.value}</div>}
              <div class="form-group">
                <label>UID *</label>
                <input
                  value={form.value.memberUid}
                  onInput={setField("memberUid")}
                  placeholder="username"
                  required
                />
              </div>
            </div>
            <div class="modal-footer">
              <button class="btn btn-secondary" onClick={closeModal}>Cancel</button>
              <button class="btn btn-primary" onClick={submitAddMember} disabled={formLoading.value}>
                {formLoading.value ? "Adding…" : "Add"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
