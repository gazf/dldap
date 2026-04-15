import { createDefine } from "fresh";

// Shared state type across middlewares, layouts, and routes.
// Auth is handled client-side via localStorage.
// deno-lint-ignore no-empty-interface
export interface State {}

export const define = createDefine<State>();
