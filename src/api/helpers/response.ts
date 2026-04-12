/** JSON レスポンスヘルパー。 */

export function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export function ok(data: unknown): Response {
  return json(data, 200);
}

export function created(data: unknown): Response {
  return json(data, 201);
}

export function noContent(): Response {
  return new Response(null, { status: 204 });
}

export function badRequest(message: string): Response {
  return json({ error: message, code: "BAD_REQUEST" }, 400);
}

export function unauthorized(): Response {
  return json({ error: "Unauthorized", code: "UNAUTHORIZED" }, 401);
}

export function notFound(message = "Not found"): Response {
  return json({ error: message, code: "NOT_FOUND" }, 404);
}

export function conflict(message: string): Response {
  return json({ error: message, code: "CONFLICT" }, 409);
}

export function serverError(message = "Internal server error"): Response {
  return json({ error: message, code: "INTERNAL_ERROR" }, 500);
}
