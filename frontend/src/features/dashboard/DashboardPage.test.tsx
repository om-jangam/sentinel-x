import { screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { Incident } from "@/api/types";
import { renderInRouter } from "@/test/router";
import { adminMe, mockApi, viewerMe } from "@/test/utils";

import { DashboardPage } from "./DashboardPage";

afterEach(() => vi.restoreAllMocks());

const health = {
  status: "ok",
  checks: { database: "ok", redis: "not_configured" },
  version: "0.1.0",
  environment: "development",
};
const verification = {
  valid: true,
  entries_checked: 21,
  head_hash: "be".repeat(32),
  broken_at_index: null,
  reason: null,
};
const assistantOff = { enabled: false, provider: null, model: null, prompt_version: "assistant-v2" };

function incident(overrides: Partial<Incident>): Incident {
  return {
    id: "i-1",
    title: "Logon after failures on web-01",
    severity_id: 4,
    severity: "High",
    status: "new",
    resolution: null,
    techniques: ["T1110"],
    tactics: [],
    finding_count: 2,
    event_count: 10,
    first_seen: "2026-09-22T09:00:00Z",
    last_seen: "2026-09-22T09:10:00Z",
    created_at: "2026-09-22T09:10:00Z",
    updated_at: "2026-09-22T09:10:00Z",
    closed_at: null,
    version: 1,
    ...overrides,
  };
}

const analystMe = {
  ...adminMe,
  permissions: [...adminMe.permissions, "incident:read", "intel:read"],
} as typeof adminMe;

describe("DashboardPage", () => {
  it("shows access, platform health and audit integrity to an admin", async () => {
    mockApi({
      "GET /api/v1/me": adminMe,
      "GET /api/v1/health": health,
      "GET /api/v1/audit/verify": verification,
      "GET /api/v1/assistant": assistantOff,
    });
    renderInRouter(DashboardPage);

    expect(await screen.findByText("Welcome, Ada Admin")).toBeInTheDocument();
    expect(await screen.findByText("v0.1.0 · development")).toBeInTheDocument();
    expect(screen.getByText("not configured")).toBeInTheDocument();
    expect(await screen.findByText(/Chain intact — 21 entries verified/)).toBeInTheDocument();
  });

  it("summarises open incidents, most severe first, and what is switched on", async () => {
    mockApi({
      "GET /api/v1/me": analystMe,
      "GET /api/v1/health": health,
      "GET /api/v1/audit/verify": verification,
      "GET /api/v1/assistant": { ...assistantOff, enabled: true, provider: "ollama", model: "qwen2.5:3b" },
      "GET /api/v1/intel/providers": [],
      "GET /api/v1/incidents": {
        items: [
          incident({}),
          incident({
            id: "i-2",
            title: "Beacon from ws-fin-07",
            severity_id: 5,
            severity: "Critical",
            event_count: 28,
          }),
          incident({ id: "i-3", title: "Old closed one", status: "closed", severity_id: 2, severity: "Low" }),
        ],
        next_cursor: null,
      },
    });
    renderInRouter(DashboardPage);

    const open = (await screen.findByText("Open incidents")).closest("a")!;
    expect(within(open).getByText("2")).toBeInTheDocument();
    expect(within(screen.getByText("Events as evidence").closest("a")!).getByText("48")).toBeInTheDocument();

    const attention = screen.getByText("Needs attention").closest("div.rounded-lg")!;
    const titles = within(attention as HTMLElement)
      .getAllByRole("link")
      .map((link) => link.textContent);
    expect(titles[1]).toContain("Beacon from ws-fin-07");
    expect(titles[2]).toContain("Logon after failures on web-01");
    expect(within(attention as HTMLElement).queryByText("Old closed one")).not.toBeInTheDocument();

    expect(screen.getByText("qwen2.5:3b")).toBeInTheDocument();
    expect(screen.getByText("No provider configured")).toBeInTheDocument();
  });

  it("explains how to get data when there are no incidents", async () => {
    mockApi({
      "GET /api/v1/me": analystMe,
      "GET /api/v1/assistant": assistantOff,
      "GET /api/v1/intel/providers": [],
      "GET /api/v1/incidents": { items: [], next_cursor: null },
    });
    renderInRouter(DashboardPage);

    expect(await screen.findByText("No incidents yet")).toBeInTheDocument();
    expect(screen.getByText(/sentinelx load-demo/)).toBeInTheDocument();
  });

  it("hides audit integrity and incidents from principals without the permissions", async () => {
    const api = mockApi({
      "GET /api/v1/me": viewerMe,
      "GET /api/v1/health": { ...health, checks: { database: "ok" } },
      "GET /api/v1/assistant": assistantOff,
    });
    renderInRouter(DashboardPage);

    expect(await screen.findByText("Welcome, Vic Viewer")).toBeInTheDocument();
    expect(screen.queryByText("Audit trail integrity")).not.toBeInTheDocument();
    expect(api.calls.some((c) => c.path === "/api/v1/audit/verify")).toBe(false);
    expect(api.calls.some((c) => c.path === "/api/v1/incidents")).toBe(false);
  });
});
