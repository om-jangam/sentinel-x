import createClient from "openapi-fetch";

import { refreshAccessToken, session } from "@/lib/session";

import type { paths } from "./schema";

const UNAUTHENTICATED_PATHS = new Set(["/api/v1/auth/login", "/api/v1/auth/refresh"]);

/**
 * Attaches the in-memory bearer token and transparently recovers from an expired access token:
 * on a 401 it performs one serialised refresh and replays the original request once.
 */
export async function authFetch(request: Request): Promise<Response> {
  const replay = request.clone();
  const token = session.getToken();
  if (token) request.headers.set("Authorization", `Bearer ${token}`);

  const response = await fetch(request);
  if (response.status !== 401 || UNAUTHENTICATED_PATHS.has(new URL(request.url).pathname)) {
    return response;
  }

  const fresh = await refreshAccessToken();
  if (!fresh) return response;
  replay.headers.set("Authorization", `Bearer ${fresh}`);
  return fetch(replay);
}

export const api = createClient<paths>({
  baseUrl: import.meta.env.VITE_API_BASE_URL ?? globalThis.location?.origin ?? "",
  fetch: authFetch,
});
