import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { AuditEntry } from "@/api/types";
import { adminMe, mockApi, renderWithQuery } from "@/test/utils";

import { AuditPage } from "./AuditPage";

afterEach(() => vi.restoreAllMocks());

const entry: AuditEntry = {
  id: "a-1",
  chain_index: 1,
  ts: "2026-09-15T10:05:00Z",
  actor_id: "u-admin",
  actor_type: "user",
  action: "user.created",
  resource_type: "user",
  resource_id: "u-new",
  before: null,
  after: { email: "new@example.com", roles: ["analyst"] },
  context: null,
  correlation_id: "corr-1",
  entry_hash: "ab".repeat(32),
};

const valid = {
  valid: true,
  entries_checked: 2,
  head_hash: "ab".repeat(32),
  broken_at_index: null,
  reason: null,
};

describe("AuditPage", () => {
  it("shows chain integrity and expands an entry's before/after", async () => {
    mockApi({
      "GET /api/v1/me": adminMe,
      "GET /api/v1/audit": { items: [entry], next_cursor: null },
      "GET /api/v1/audit/verify": valid,
    });
    renderWithQuery(<AuditPage />);

    expect(await screen.findByText(/Hash chain intact across 2 entries/)).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(await screen.findByText("user.created"));
    expect(screen.getByText(/"email": "new@example.com"/)).toBeInTheDocument();
    expect(screen.getByText(/correlation corr-1/)).toBeInTheDocument();
  });

  it("surfaces tampering", async () => {
    mockApi({
      "GET /api/v1/me": adminMe,
      "GET /api/v1/audit": { items: [], next_cursor: null },
      "GET /api/v1/audit/verify": {
        ...valid,
        valid: false,
        broken_at_index: 1,
        reason: "entry content does not match its hash",
      },
    });
    renderWithQuery(<AuditPage />);

    expect(await screen.findByText(/Integrity failure at entry #1/)).toBeInTheDocument();
    expect(await screen.findByText("No matching entries.")).toBeInTheDocument();
  });

  it("sends filters to the API", async () => {
    const api = mockApi({
      "GET /api/v1/me": adminMe,
      "GET /api/v1/audit": { items: [entry], next_cursor: null },
      "GET /api/v1/audit/verify": valid,
    });
    const spy = api.spy;
    renderWithQuery(<AuditPage />);

    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Action"), "auth.login_failed");
    await user.click(screen.getByRole("button", { name: "Apply" }));

    await waitFor(() =>
      expect(
        spy.mock.calls.some(([input]) => (input as Request).url.includes("action=auth.login_failed")),
      ).toBe(true),
    );
  });
});
