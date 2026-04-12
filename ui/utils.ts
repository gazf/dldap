import { createDefine } from "fresh";

// Shared state type across middlewares, layouts, and routes.
// Auth is handled client-side via localStorage.
export interface State {
  // nothing shared server-side for now
}

export const define = createDefine<State>();
