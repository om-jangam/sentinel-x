import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { adminMe, mockApi, renderWithQuery, viewerMe } from "@/test/utils";

import { DashboardPage } from "./DashboardPage";

afterEach(() => vi.restoreAllMocks());

describe("DashboardPage", () => {
  it("shows access, platform health and audit integrity to an admin", async () => {
    mockApi({
      "GET /api/v1/me": adminMe,
      "GET /api/v1/health": {
        status: "ok",
        checks: { database: "ok", redis: "not_configured" },
        version: "0.1.0",
        environment: "development",
      },
      "GET /api/v1/audit/verify": {
        valid: true,
        entries_checked: 21,
        head_hash: "be".repeat(32),
        broken_at_index: null,
        reason: null,
      },
    });
    renderWithQuery(<DashboardPage />);

    expect(await screen.findByText("Welcome, Ada Admin")).toBeInTheDocument();
    expect(await screen.findByText("v0.1.0 · development")).toBeInTheDocument();
    expect(screen.getByText("not configured")).toBeInTheDocument();
    expect(await screen.findByText(/Chain intact — 21 entries verified/)).toBeInTheDocument();
  });

  it("hides audit integrity from principals without audit:read", async () => {
    const api = mockApi({
      "GET /api/v1/me": viewerMe,
      "GET /api/v1/health": {
        status: "ok",
        checks: { database: "ok" },
        version: "0.1.0",
        environment: "test",
      },
    });
    renderWithQuery(<DashboardPage />);

    expect(await screen.findByText("Welcome, Vic Viewer")).toBeInTheDocument();
    expect(screen.queryByText("Audit trail integrity")).not.toBeInTheDocument();
    expect(api.calls.some((c) => c.path === "/api/v1/audit/verify")).toBe(false);
  });
});
