import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { session } from "@/lib/session";

import { authFetch } from "./client";
import { ApiError, unwrap } from "./errors";

const ORIGIN = "http://localhost";
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

describe("authFetch", () => {
  beforeEach(() => session.clear());
  afterEach(() => vi.restoreAllMocks());

  it("attaches the bearer token", async () => {
    session.accept({
      access_token: "t1",
      token_type: "bearer",
      expires_in: 600,
      expires_at: new Date(Date.now() + 6e5).toISOString(),
    });
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(json({ ok: true }));

    await authFetch(new Request(`${ORIGIN}/api/v1/me`));

    const sent = fetchMock.mock.calls[0]?.[0] as Request;
    expect(sent.headers.get("Authorization")).toBe("Bearer t1");
  });

  it("refreshes once and replays the request (including its body) after a 401", async () => {
    session.accept({
      access_token: "expired",
      token_type: "bearer",
      expires_in: 600,
      expires_at: new Date(Date.now() + 6e5).toISOString(),
    });
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url.endsWith("/api/v1/auth/refresh")) {
        return json({
          access_token: "renewed",
          token_type: "bearer",
          expires_in: 600,
          expires_at: new Date(Date.now() + 6e5).toISOString(),
        });
      }
      const request = input as Request;
      return request.headers.get("Authorization") === "Bearer renewed"
        ? json({ body: await request.text() })
        : json({}, 401);
    });

    const response = await authFetch(
      new Request(`${ORIGIN}/api/v1/users`, { method: "POST", body: '{"a":1}' }),
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ body: '{"a":1}' });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("does not try to refresh when the login call itself is rejected", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(json({ status: 401, title: "x" }, 401));
    const response = await authFetch(new Request(`${ORIGIN}/api/v1/auth/login`, { method: "POST" }));
    expect(response.status).toBe(401);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("unwrap", () => {
  it("turns problem documents into ApiErrors with field details", () => {
    const problem = {
      type: "https://sentinel-x.dev/errors/validation-failed",
      title: "Validation failed",
      status: 422,
      detail: "Password does not meet the password policy",
      errors: [{ msg: "must be at least 12 characters" }],
    };
    expect(() => unwrap({ error: problem, response: new Response(null, { status: 422 }) })).toThrow(ApiError);
    try {
      unwrap({ error: problem, response: new Response(null, { status: 422 }) });
    } catch (error) {
      expect((error as ApiError).describe()).toBe(
        "Password does not meet the password policy: must be at least 12 characters",
      );
    }
  });
});
