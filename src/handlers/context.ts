/**
 * Handler context — shared state passed to every operation handler.
 */

import type { Config } from "../../config/default.ts";
import type { DirectoryStore } from "../store/types.ts";

export interface HandlerContext {
  config: Config;
  store: DirectoryStore;
  /** DN of the currently authenticated user (empty string = anonymous) */
  boundDN: string;
  /** Whether the current session is authenticated as admin */
  isAdmin: boolean;
}
