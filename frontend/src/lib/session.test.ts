import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { refreshAccessToken, session } from "./session";

const tokenBody = (token: string) => ({
  access_token: token,
  token_type: "bearer",
  expires_in: 600,
  expires_at: new Date(Date.now() + 600_000).toISOString(),
});

describe("session", () => {
  beforeEach(() => session.clear());
  afterEach(() => vi.restoreAllMocks());

  it("single-flights concurrent refreshes so a rotating refresh token is never replayed", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(JSON.stringify(tokenBody("fresh")), { status: 200 }));

    const results = await Promise.all([refreshAccessToken(), refreshAccessToken(), refreshAccessToken()]);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(results).toEqual(["fresh", "fresh", "fresh"]);
    expect(session.getToken()).toBe("fresh");
  });

  it("clears the session and notifies listeners when refresh is rejected", async () => {
    session.accept(tokenBody("stale") as never);
    const listener = vi.fn();
    const unsubscribe = session.subscribe(listener);
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 401 }));

    expect(await refreshAccessToken()).toBeNull();
    expect(session.getToken()).toBeNull();
    expect(listener).toHaveBeenLastCalledWith(null);
    unsubscribe();
  });

  it("treats network failure as signed out", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("offline"));
    expect(await refreshAccessToken()).toBeNull();
  });
});
