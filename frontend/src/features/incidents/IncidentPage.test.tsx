import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { Me } from "@/api/types";
import {
  evidence,
  graph,
  INCIDENT_ID,
  incidentDetail,
  analystMe,
  note,
  seniorMe,
  timeline,
} from "@/test/incidents";
import { renderInRouter } from "@/test/router";
import { json, mockApi, viewerMe } from "@/test/utils";

import { IncidentPage } from "./IncidentPage";

afterEach(() => vi.restoreAllMocks());

const base = `/api/v1/incidents/${INCIDENT_ID}`;

function workspace(me: Me, overrides: Record<string, unknown> = {}) {
  const api = mockApi({
    "GET /api/v1/me": me,
    [`GET ${base}`]: incidentDetail,
    [`GET ${base}/timeline`]: timeline,
    [`GET ${base}/graph`]: graph,
    [`GET ${base}/evidence`]: evidence,
    [`GET ${base}/notes`]: [note],
    ...overrides,
  });
  renderInRouter(() => <IncidentPage incidentId={INCIDENT_ID} />, { path: `/incidents/${INCIDENT_ID}` });
  return api;
}

describe("IncidentPage", () => {
  it("shows the summary, why it is critical, and the timeline in order", async () => {
    workspace(analystMe);

    expect(await screen.findByRole("heading", { name: incidentDetail.title })).toBeInTheDocument();
    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.getByText(/a successful logon followed brute-force failures/)).toBeInTheDocument();
    const steps = within(await screen.findByRole("list", { name: "Attack timeline" })).getAllByRole("button");
    expect(steps.map((step) => step.textContent)).toEqual([
      expect.stringContaining("Failed logon×5"),
      expect.stringContaining("Logged on"),
      expect.stringContaining("explorer.exe → powershell.exe"),
    ]);
    expect(screen.getByText("Logon after failures")).toBeInTheDocument();
  });

  it("traces a timeline step to the events behind it", async () => {
    workspace(analystMe);
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: /Logged on/ }));
    const inspector = screen.getByRole("region", { name: "Evidence inspector" });
    expect(within(inspector).getByText("event_uid e-logon")).toBeInTheDocument();
    expect(within(inspector).getByText(/"EventID":4624/)).toBeInTheDocument();
    expect(within(inspector).getByText("Logon after failures")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Failed logon/ }));
    expect(within(inspector).getAllByText(/^event_uid e-fail-/)).toHaveLength(5);
  });

  it("traces a graph relationship to its events", async () => {
    workspace(analystMe);
    const user = userEvent.setup();

    await user.click(await screen.findByRole("tab", { name: "Graph" }));
    expect(screen.getByRole("button", { name: /ip 198.51.100.23, 6 events/ })).toBeInTheDocument();
    const relationships = screen.getByRole("table", { name: "Relationships" });
    const row = within(relationships).getByText("failed logon to (5); logged on to (1)");
    await user.click(row);

    const inspector = screen.getByRole("region", { name: "Evidence inspector" });
    expect(within(inspector).getByText("198.51.100.23 → ws-fin-07")).toBeInTheDocument();
    expect(within(inspector).getAllByText(/^event_uid e-/)).toHaveLength(6);
  });

  it("explains when the event store can't provide the stored event", async () => {
    workspace(analystMe, {
      "GET /api/v1/events/e-ps": json(
        { type: "about:blank", title: "Service Unavailable", status: 503, detail: "Event store unavailable" },
        503,
      ),
    });
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: /Process started/ }));
    await user.click(screen.getByRole("button", { name: /Load stored event/ }));
    expect(await screen.findByText(/The event store is unavailable/)).toBeInTheDocument();
  });

  it("moves a new incident into investigation with the version it read", async () => {
    const api = workspace(analystMe, {
      [`PATCH ${base}`]: { ...incidentDetail, status: "investigating", version: 3 },
    });
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: "Start investigating" }));
    await waitFor(() =>
      expect(api.calls).toContainEqual({
        method: "PATCH",
        path: base,
        body: { status: "investigating", version: 2 },
      }),
    );
    expect(screen.queryByRole("button", { name: "Close…" })).not.toBeInTheDocument();
  });

  it("closes with a resolution only for those allowed to resolve", async () => {
    const api = workspace(seniorMe, {
      [`PATCH ${base}`]: { ...incidentDetail, status: "closed", resolution: "false_positive", version: 3 },
    });
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: "Close…" }));
    await user.selectOptions(screen.getByLabelText("Resolution"), "false_positive");
    await user.click(screen.getByRole("button", { name: "Close incident" }));
    await waitFor(() =>
      expect(api.calls).toContainEqual({
        method: "PATCH",
        path: base,
        body: { status: "closed", resolution: "false_positive", version: 2 },
      }),
    );
  });

  it("adds analyst notes", async () => {
    const api = workspace(analystMe, {
      [`POST ${base}/notes`]: json({ ...note, id: "n-2", body: "VPN checked." }, 201),
    });
    const user = userEvent.setup();

    await user.click(await screen.findByRole("tab", { name: "Notes" }));
    expect(await screen.findByText("RDP right after the burst.")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Add a note"), "VPN checked.");
    await user.click(screen.getByRole("button", { name: "Add note" }));
    await waitFor(() =>
      expect(api.calls).toContainEqual({
        method: "POST",
        path: `${base}/notes`,
        body: { body: "VPN checked." },
      }),
    );
  });

  it("is read-only for viewers", async () => {
    workspace({ ...viewerMe, permissions: ["incident:read", "platform:read"] });
    const user = userEvent.setup();

    expect(await screen.findByRole("heading", { name: incidentDetail.title })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Start investigating" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Notes" }));
    await screen.findByText("RDP right after the burst.");
    expect(screen.queryByLabelText("Add a note")).not.toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Timeline" }));
    await user.click(await screen.findByRole("button", { name: /Logged on/ }));
    expect(screen.queryByRole("button", { name: /Load stored event/ })).not.toBeInTheDocument();
  });

  it("shows what each intel provider said, and flags the graph", async () => {
    const intelMe = { ...analystMe, permissions: [...analystMe.permissions, "intel:read" as const] };
    workspace(intelMe, {
      "GET /api/v1/intel/providers": [
        {
          name: "local",
          title: "Local indicator feed (demo.csv)",
          kind: "local",
          supports: ["ip"],
          detail: {},
        },
      ],
      "POST /api/v1/intel/lookup": {
        results: [
          {
            indicator: "ip:198.51.100.23",
            provider: "local",
            status: "found",
            verdict: "malicious",
            confidence: 80,
            summary: "Demo feed: RDP password guessing",
            tags: ["rdp"],
            related: [],
            references: ["https://intel.example/198.51.100.23", "javascript:alert(1)"],
            provider_first_seen: null,
            provider_last_seen: null,
            retrieved_at: "2026-09-15T10:00:00Z",
            expires_at: "2026-09-15T11:00:00Z",
            error: null,
          },
        ],
        skipped: ["host:ws-fin-07"],
      },
    });
    const user = userEvent.setup();

    await user.click(await screen.findByRole("tab", { name: "Threat intel" }));
    const section = await screen.findByRole("region", { name: "Intel for ip:198.51.100.23" });
    expect(within(section).getByText("Demo feed: RDP password guessing")).toBeInTheDocument();
    expect(within(section).getByRole("link", { name: /intel.example/ })).toHaveAttribute(
      "rel",
      "noopener noreferrer",
    );
    expect(within(section).queryByRole("link", { name: /javascript/ })).not.toBeInTheDocument();
    expect(screen.getByText(/never sent to a provider/)).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Graph" }));
    expect(
      screen.getByRole("button", { name: /ip 198.51.100.23, 6 events, malicious according to local/ }),
    ).toBeInTheDocument();
  });

  it("says so when no intel provider is configured", async () => {
    const intelMe = { ...analystMe, permissions: [...analystMe.permissions, "intel:read" as const] };
    workspace(intelMe, {
      "GET /api/v1/intel/providers": [],
      "POST /api/v1/intel/lookup": { results: [], skipped: [] },
    });
    const user = userEvent.setup();
    await user.click(await screen.findByRole("tab", { name: "Threat intel" }));
    expect(await screen.findByText(/No threat-intelligence providers are configured/)).toBeInTheDocument();
  });

  it("asks for access without incident:read", async () => {
    workspace(viewerMe);
    expect(await screen.findByText(/requires the/)).toBeInTheDocument();
  });
});
