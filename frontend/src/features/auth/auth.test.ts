import { describe, expect, it } from "vitest";

import type { Me } from "@/api/types";

import { hasPermission, safeRedirect } from "./auth";

describe("safeRedirect", () => {
  it.each([
    ["/admin/users", "/admin/users"],
    ["/admin/audit?action=x", "/admin/audit?action=x"],
    ["//evil.example", "/"],
    ["https://evil.example", "/"],
    ["javascript:alert(1)", "/"],
    [undefined, "/"],
    [42, "/"],
  ])("safeRedirect(%s) → %s", (input, expected) => {
    expect(safeRedirect(input)).toBe(expected);
  });
});

describe("hasPermission", () => {
  const me = { permissions: ["audit:read"] } as unknown as Me;

  it("checks effective permissions", () => {
    expect(hasPermission(me, "audit:read")).toBe(true);
    expect(hasPermission(me, "user:manage")).toBe(false);
    expect(hasPermission(undefined, "audit:read")).toBe(false);
  });
});
