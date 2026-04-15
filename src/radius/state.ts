/**
 * EAP challenge state management in Deno KV.
 *
 * Deno KV does not support TTL-based auto-expiry for all versions,
 * so we store a createdAt timestamp and perform manual expiry checks.
 * Stale entries (> 5 minutes old) are deleted on retrieval.
 */

const EAP_STATE_TTL_MS = 5 * 60 * 1000; // 5 minutes

export interface EapState {
  /** 16-byte server-generated auth challenge (stored as hex string) */
  authChallenge: string;
  /** EAP identifier for the next packet (MSCHAPv2 challenge id) */
  eapId: number;
  /** MSCHAPv2 ID (opcode-level, same as eapId for simplicity) */
  msChapId: number;
  /** Username extracted from EAP Identity */
  userName: string;
  /** Date.now() at creation */
  createdAt: number;
}

function stateKey(token: Uint8Array): Deno.KvKey {
  return ["radius_eap_state", hex(token)];
}

function hex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export async function saveEapState(
  kv: Deno.Kv,
  stateToken: Uint8Array,
  state: EapState,
): Promise<void> {
  await kv.set(stateKey(stateToken), state);
}

export async function getEapState(
  kv: Deno.Kv,
  stateToken: Uint8Array,
): Promise<EapState | null> {
  const result = await kv.get<EapState>(stateKey(stateToken));
  if (!result.value) return null;

  const state = result.value;
  if (Date.now() - state.createdAt > EAP_STATE_TTL_MS) {
    // Expired — clean up
    await kv.delete(stateKey(stateToken));
    return null;
  }
  return state;
}

export async function deleteEapState(
  kv: Deno.Kv,
  stateToken: Uint8Array,
): Promise<void> {
  await kv.delete(stateKey(stateToken));
}
