import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { analystMe, incidentDetail } from "@/test/incidents";
import { renderInRouter } from "@/test/router";
import { mockApi } from "@/test/utils";

import { IncidentsPage } from "./IncidentsPage";

afterEach(() => vi.restoreAllMocks());

describe("IncidentsPage", () => {
  it("lists incidents and opens one", async () => {
    mockApi({
      "GET /api/v1/me": analystMe,
      "GET /api/v1/incidents": { items: [incidentDetail], next_cursor: null },
    });
    const router = renderInRouter(IncidentsPage, { path: "/incidents" });

    const link = await screen.findByRole("link", { name: incidentDetail.title });
    const table = within(screen.getByRole("table"));
    expect(table.getByText("Critical")).toBeInTheDocument();
    expect(table.getByText("New")).toBeInTheDocument();
    await userEvent.setup().click(link);
    await waitFor(() => expect(router.state.location.pathname).toBe(`/incidents/${incidentDetail.id}`));
  });

  it("filters by status and severity", async () => {
    const api = mockApi({
      "GET /api/v1/me": analystMe,
      "GET /api/v1/incidents": { items: [], next_cursor: null },
    });
    renderInRouter(IncidentsPage, { path: "/incidents" });
    const user = userEvent.setup();

    expect(await screen.findByText(/No incidents yet/)).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Status"), "closed");
    await user.selectOptions(screen.getByLabelText("Minimum severity"), "4");
    await waitFor(() => expect(api.spy).toHaveBeenCalledTimes(4));
    const last = api.spy.mock.calls.at(-1)?.[0];
    const url = new URL(last instanceof Request ? last.url : String(last));
    expect(url.searchParams.get("status")).toBe("closed");
    expect(url.searchParams.get("severity_min")).toBe("4");
    expect(await screen.findByText("No incidents match these filters.")).toBeInTheDocument();
  });
});
