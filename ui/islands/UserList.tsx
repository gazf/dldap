import { useSignal } from "@preact/signals";
import { IS_BROWSER } from "fresh/runtime";
import { apiFetch, getToken } from "../utils/api.ts";
import type { GroupDTO, UserDTO } from "../utils/types.ts";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
type ModalMode = "create" | "edit" | "delete" | "password" | null;

const EMPTY_FORM = {
  uid: "",
  cn: "",
  sn: "",
  givenName: "",
  mail: "",
  uidNumber: "",
  gidNumber: "",
  homeDirectory: "",
  loginShell: "/bin/bash",
  description: "",
  password: "",
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
export default function UserList() {
  const users = useSignal<UserDTO[]>([]);
  const groups = useSignal<GroupDTO[]>([]);
  const loading = useSignal(true);
  const error = useSignal("");
  const modalMode = useSignal<ModalMode>(null);
  const selectedUser = useSignal<UserDTO | null>(null);
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
      [users.value, groups.value] = await Promise.all([
        apiFetch<UserDTO[]>("/users"),
        apiFetch<GroupDTO[]>("/groups"),
      ]);
    } catch (err) {
      error.value = err instanceof Error ? err.message : "Error";
    } finally {
      loading.value = false;
    }
  }

  if (IS_BROWSER && loading.value && users.value.length === 0 && !error.value) {
    load();
  }

  function openCreate() {
    form.value = { ...EMPTY_FORM };
    formError.value = "";
    modalMode.value = "create";
  }

  function openEdit(user: UserDTO) {
    selectedUser.value = user;
    form.value = {
      uid: user.uid,
      cn: user.cn,
      sn: user.sn ?? "",
      givenName: user.givenName ?? "",
      mail: user.mail ?? "",
      uidNumber: user.uidNumber != null ? String(user.uidNumber) : "",
      gidNumber: user.gidNumber != null ? String(user.gidNumber) : "",
      homeDirectory: user.homeDirectory ?? "",
      loginShell: user.loginShell ?? "/bin/bash",
      description: user.description ?? "",
      password: "",
    };
    formError.value = "";
    modalMode.value = "edit";
  }

  function openDelete(user: UserDTO) {
    selectedUser.value = user;
    formError.value = "";
    modalMode.value = "delete";
  }

  function openPassword(user: UserDTO) {
    selectedUser.value = user;
    form.value = { ...EMPTY_FORM };
    formError.value = "";
    modalMode.value = "password";
  }

  function closeModal() {
    modalMode.value = null;
    selectedUser.value = null;
  }

  async function submitCreate() {
    formLoading.value = true;
    formError.value = "";
    try {
      const f = form.value;
      if (!f.gidNumber) {
        formError.value = "GID Number（グループ）は必須です";
        formLoading.value = false;
        return;
      }
      const body: Record<string, string> = {
        uid: f.uid,
        cn: f.cn,
        password: f.password,
        gidNumber: f.gidNumber,
      };
      if (f.sn) body.sn = f.sn;
      if (f.givenName) body.givenName = f.givenName;
      if (f.mail) body.mail = f.mail;
      if (f.uidNumber) body.uidNumber = f.uidNumber;
      if (f.homeDirectory) body.homeDirectory = f.homeDirectory;
      if (f.loginShell) body.loginShell = f.loginShell;
      if (f.description) body.description = f.description;
      await apiFetch("/users", { method: "POST", body: JSON.stringify(body) });
      closeModal();
      await load();
    } catch (err) {
      formError.value = err instanceof Error ? err.message : "Error";
    } finally {
      formLoading.value = false;
    }
  }

  async function submitEdit() {
    if (!selectedUser.value) return;
    formLoading.value = true;
    formError.value = "";
    try {
      const f = form.value;
      if (!f.gidNumber) {
        formError.value = "GID Number（グループ）は必須です";
        formLoading.value = false;
        return;
      }
      if (!groups.value.some((g) => String(g.gidNumber) === f.gidNumber)) {
        formError.value = "無効なグループが選択されています。グループを選び直してください。";
        formLoading.value = false;
        return;
      }
      const body: Record<string, string> = { cn: f.cn };
      if (f.sn !== undefined) body.sn = f.sn;
      if (f.givenName !== undefined) body.givenName = f.givenName;
      if (f.mail !== undefined) body.mail = f.mail;
      if (f.uidNumber !== undefined) body.uidNumber = f.uidNumber;
      if (f.gidNumber !== undefined) body.gidNumber = f.gidNumber;
      if (f.homeDirectory !== undefined) body.homeDirectory = f.homeDirectory;
      if (f.loginShell !== undefined) body.loginShell = f.loginShell;
      if (f.description !== undefined) body.description = f.description;
      await apiFetch(`/users/${selectedUser.value.uid}`, {
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
    if (!selectedUser.value) return;
    formLoading.value = true;
    formError.value = "";
    try {
      await apiFetch(`/users/${selectedUser.value.uid}`, { method: "DELETE" });
      closeModal();
      await load();
    } catch (err) {
      formError.value = err instanceof Error ? err.message : "Error";
    } finally {
      formLoading.value = false;
    }
  }

  async function submitPassword() {
    if (!selectedUser.value) return;
    formLoading.value = true;
    formError.value = "";
    try {
      await apiFetch(`/users/${selectedUser.value.uid}/password`, {
        method: "PUT",
        body: JSON.stringify({ password: form.value.password }),
      });
      closeModal();
    } catch (err) {
      formError.value = err instanceof Error ? err.message : "Error";
    } finally {
      formLoading.value = false;
    }
  }

  function setField(key: keyof typeof EMPTY_FORM) {
    return (e: Event) => {
      form.value = { ...form.value, [key]: (e.target as HTMLInputElement).value };
    };
  }

  async function addSecondaryGroup(groupCn: string) {
    await apiFetch(`/groups/${groupCn}/members`, {
      method: "POST",
      body: JSON.stringify({ uid: selectedUser.value!.uid }),
    });
    groups.value = await apiFetch<GroupDTO[]>("/groups");
  }

  async function removeSecondaryGroup(groupCn: string) {
    await apiFetch(`/groups/${groupCn}/members/${selectedUser.value!.uid}`, {
      method: "DELETE",
    });
    groups.value = await apiFetch<GroupDTO[]>("/groups");
  }

  return (
    <div>
      {error.value && <div class="alert alert-error">{error.value}</div>}

      <div class="toolbar">
        <button type="button" class="btn btn-primary" onClick={openCreate}>+ Add User</button>
        <button type="button" class="btn btn-secondary" onClick={load} disabled={loading.value}>
          Refresh
        </button>
      </div>

      {loading.value
        ? <div class="loading">Loading…</div>
        : users.value.length === 0
        ? <div class="empty">No users found.</div>
        : (
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>UID</th>
                  <th>CN</th>
                  <th>Mail</th>
                  <th>UID#</th>
                  <th>GID#</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.value.map((u) => (
                  <tr key={u.uid}>
                    <td>
                      <code>{u.uid}</code>
                    </td>
                    <td>{u.cn}</td>
                    <td>{u.mail ?? "—"}</td>
                    <td>{u.uidNumber ?? "—"}</td>
                    <td>{u.gidNumber ?? "—"}</td>
                    <td>
                      <span style="display:flex;gap:4px">
                        <button type="button" class="btn btn-secondary" onClick={() => openEdit(u)}>
                          Edit
                        </button>
                        <button
                          type="button"
                          class="btn btn-secondary"
                          onClick={() => openPassword(u)}
                        >
                          PW
                        </button>
                        <button type="button" class="btn btn-danger" onClick={() => openDelete(u)}>
                          Delete
                        </button>
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
              <h3>Add User</h3>
              <button type="button" class="btn btn-secondary" onClick={closeModal}>✕</button>
            </div>
            <div class="modal-body">
              {formError.value && <div class="alert alert-error">{formError.value}</div>}
              <UserFormFields
                form={form.value}
                setField={setField}
                showPassword
                groups={groups.value}
              />
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

      {/* Edit modal */}
      {modalMode.value === "edit" && (
        <div class="modal-overlay" onClick={closeModal}>
          <div class="modal" onClick={(e) => e.stopPropagation()}>
            <div class="modal-header">
              <h3>Edit User: {selectedUser.value?.uid}</h3>
              <button type="button" class="btn btn-secondary" onClick={closeModal}>✕</button>
            </div>
            <div class="modal-body">
              {formError.value && <div class="alert alert-error">{formError.value}</div>}
              <UserFormFields
                form={form.value}
                setField={setField}
                showPassword={false}
                groups={groups.value}
                secondaryGroups={groups.value.filter(
                  (g) =>
                    g.members.includes(selectedUser.value?.uid ?? "") &&
                    String(g.gidNumber) !== form.value.gidNumber,
                )}
                availableGroups={groups.value.filter(
                  (g) =>
                    !g.members.includes(selectedUser.value?.uid ?? "") &&
                    String(g.gidNumber) !== form.value.gidNumber,
                )}
                onAddSecondary={addSecondaryGroup}
                onRemoveSecondary={removeSecondaryGroup}
              />
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary" onClick={closeModal}>Cancel</button>
              <button
                type="button"
                class="btn btn-primary"
                onClick={submitEdit}
                disabled={formLoading.value}
              >
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
              <h3>Delete User</h3>
              <button type="button" class="btn btn-secondary" onClick={closeModal}>✕</button>
            </div>
            <div class="modal-body">
              {formError.value && <div class="alert alert-error">{formError.value}</div>}
              <p>
                Delete user <strong>{selectedUser.value?.uid}</strong>? This cannot be undone.
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

      {/* Password modal */}
      {modalMode.value === "password" && (
        <div class="modal-overlay" onClick={closeModal}>
          <div class="modal" onClick={(e) => e.stopPropagation()}>
            <div class="modal-header">
              <h3>Change Password: {selectedUser.value?.uid}</h3>
              <button type="button" class="btn btn-secondary" onClick={closeModal}>✕</button>
            </div>
            <div class="modal-body">
              {formError.value && <div class="alert alert-error">{formError.value}</div>}
              <div class="form-group">
                <label>New password</label>
                <input
                  type="password"
                  value={form.value.password}
                  onInput={setField("password")}
                  required
                />
              </div>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary" onClick={closeModal}>Cancel</button>
              <button
                type="button"
                class="btn btn-primary"
                onClick={submitPassword}
                disabled={formLoading.value}
              >
                {formLoading.value ? "Changing…" : "Change"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-component: form fields (not an island)
// ---------------------------------------------------------------------------
interface FormFieldsProps {
  form: typeof EMPTY_FORM;
  setField: (key: keyof typeof EMPTY_FORM) => (e: Event) => void;
  showPassword: boolean;
  groups: GroupDTO[];
  secondaryGroups?: GroupDTO[];
  availableGroups?: GroupDTO[];
  onAddSecondary?: (cn: string) => void;
  onRemoveSecondary?: (cn: string) => void;
}

function UserFormFields(
  {
    form,
    setField,
    showPassword,
    groups,
    secondaryGroups,
    availableGroups,
    onAddSecondary,
    onRemoveSecondary,
  }: FormFieldsProps,
) {
  return (
    <div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem">
        <div class="form-group">
          <label>UID *</label>
          <input value={form.uid} onInput={setField("uid")} required disabled={!showPassword} />
        </div>
        <div class="form-group">
          <label>CN (Display name) *</label>
          <input value={form.cn} onInput={setField("cn")} required />
        </div>
        <div class="form-group">
          <label>Given name</label>
          <input value={form.givenName} onInput={setField("givenName")} />
        </div>
        <div class="form-group">
          <label>SN (Surname)</label>
          <input value={form.sn} onInput={setField("sn")} />
        </div>
        <div class="form-group" style="grid-column:1/-1">
          <label>Mail</label>
          <input type="email" value={form.mail} onInput={setField("mail")} />
        </div>
        <div class="form-group">
          <label>UID Number</label>
          <input type="number" value={form.uidNumber} onInput={setField("uidNumber")} />
        </div>
        <div class="form-group">
          <label>GID Number *</label>
          <select value={form.gidNumber} onChange={setField("gidNumber")}>
            <option value="">-- グループを選択 --</option>
            {form.gidNumber && !groups.some((g) => String(g.gidNumber) === form.gidNumber) && (
              <option value={form.gidNumber} style="color:red">
                ⚠ {form.gidNumber}（グループ未存在）
              </option>
            )}
            {groups.map((g) => (
              <option key={g.dn} value={String(g.gidNumber)}>
                {g.cn} ({g.gidNumber})
              </option>
            ))}
          </select>
        </div>
        {secondaryGroups !== undefined && (
          <div class="form-group" style="grid-column:1/-1">
            <label>所属グループ（セカンダリ）</label>
            <div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center">
              {secondaryGroups.map((g) => (
                <span key={g.dn} class="tag">
                  {g.cn}
                  <button
                    type="button"
                    onClick={() => onRemoveSecondary?.(g.cn)}
                    style="background:none;border:none;cursor:pointer;margin-left:2px;color:#888"
                  >
                    ✕
                  </button>
                </span>
              ))}
              {availableGroups && availableGroups.length > 0 && (
                <select
                  value=""
                  onChange={(e) => {
                    const cn = (e.target as HTMLSelectElement).value;
                    if (cn) onAddSecondary?.(cn);
                    (e.target as HTMLSelectElement).value = "";
                  }}
                >
                  <option value="">＋ 追加</option>
                  {availableGroups.map((g) => <option key={g.dn} value={g.cn}>{g.cn}</option>)}
                </select>
              )}
            </div>
          </div>
        )}
        <div class="form-group" style="grid-column:1/-1">
          <label>Home directory</label>
          <input
            value={form.homeDirectory}
            onInput={setField("homeDirectory")}
            placeholder="/home/username"
          />
        </div>
        <div class="form-group">
          <label>Login shell</label>
          <input value={form.loginShell} onInput={setField("loginShell")} />
        </div>
        <div class="form-group">
          <label>Description</label>
          <input value={form.description} onInput={setField("description")} />
        </div>
        {showPassword && (
          <div class="form-group" style="grid-column:1/-1">
            <label>Password *</label>
            <input type="password" value={form.password} onInput={setField("password")} required />
          </div>
        )}
      </div>
    </div>
  );
}
