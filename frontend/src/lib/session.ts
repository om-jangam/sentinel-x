/**
 * Access-token session store.
 *
 * The access JWT lives only in memory (never localStorage — XSS could read it). The refresh token is an
 * HttpOnly cookie the browser sends to /api/v1/auth/refresh; JavaScript never sees it.
 *
 * Refresh tokens rotate on every use and a replayed token revokes the whole session, so concurrent
 * refreshes must be serialised: single-flight within a tab, Web Locks across tabs.
 */

export interface TokenResponse {
  access_token: string;
  token_type: "bearer";
  expires_in: number;
  expires_at: string;
}

type Listener = (token: string | null) => void;

const REFRESH_PATH = "/api/v1/auth/refresh";
const PROACTIVE_REFRESH_MARGIN_MS = 60_000;

let accessToken: string | null = null;
let refreshTimer: ReturnType<typeof setTimeout> | undefined;
let inflight: Promise<string | null> | null = null;
const listeners = new Set<Listener>();

function notify(): void {
  for (const listener of listeners) listener(accessToken);
}

function scheduleProactiveRefresh(expiresAt: string): void {
  clearTimeout(refreshTimer);
  const delay = new Date(expiresAt).getTime() - Date.now() - PROACTIVE_REFRESH_MARGIN_MS;
  if (delay > 0) {
    refreshTimer = setTimeout(() => void refreshAccessToken(), delay);
  }
}

export const session = {
  getToken(): string | null {
    return accessToken;
  },

  accept(response: TokenResponse): void {
    accessToken = response.access_token;
    scheduleProactiveRefresh(response.expires_at);
    notify();
  },

  clear(): void {
    accessToken = null;
    clearTimeout(refreshTimer);
    notify();
  },

  subscribe(listener: Listener): () => void {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
};

async function withCrossTabLock<T>(task: () => Promise<T>): Promise<T> {
  if (typeof navigator !== "undefined" && "locks" in navigator && navigator.locks) {
    return navigator.locks.request("sentinelx-token-refresh", task);
  }
  return task();
}

export function refreshAccessToken(): Promise<string | null> {
  inflight ??= withCrossTabLock(async () => {
    try {
      const response = await fetch(REFRESH_PATH, { method: "POST", credentials: "same-origin" });
      if (!response.ok) {
        session.clear();
        return null;
      }
      session.accept((await response.json()) as TokenResponse);
      return session.getToken();
    } catch {
      session.clear();
      return null;
    }
  }).finally(() => {
    inflight = null;
  });
  return inflight;
}
