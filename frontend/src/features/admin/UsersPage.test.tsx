import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { adminMe, adminUser, analystUser, mockApi, renderWithQuery, roles, viewerMe } from "@/test/utils";

import { UsersPage } from "./UsersPage";

afterEach(() => vi.restoreAllMocks());

const adminRoutes = {
  "GET /api/v1/me": adminMe,
  "GET /api/v1/users": { items: [adminUser, analystUser], next_cursor: null },
  "GET /api/v1/roles": roles,
};

describe("UsersPage", () => {
  it("lists users and creates one with the selected roles", async () => {
    const api = mockApi({
      ...adminRoutes,
      "POST /api/v1/users": { ...analystUser, id: "u-new", email: "new@example.com" },
    });
    renderWithQuery(<UsersPage />);

    expect(await screen.findByText("analyst@example.com")).toBeInTheDocument();

    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Email"), "new@example.com");
    await user.type(screen.getByLabelText("Full name"), "New Analyst");
    await user.type(screen.getByLabelText("Initial password"), "a-long-initial-passphrase");
    await user.click(screen.getByRole("button", { name: /create user/i }));

    await waitFor(() => expect(api.calls.some((c) => c.method === "POST")).toBe(true));
    expect(api.calls.find((c) => c.method === "POST")?.body).toEqual({
      email: "new@example.com",
      full_name: "New Analyst",
      password: "a-long-initial-passphrase",
      roles: ["analyst"],
    });
  });

  it("prevents admins from deactivating their own account", async () => {
    mockApi(adminRoutes);
    renderWithQuery(<UsersPage />);

    const ownRow = (await screen.findByText(adminUser.email)).closest("tr");
    const otherRow = screen.getByText(analystUser.email).closest("tr");
    expect(within(ownRow!).getByRole("button", { name: "Deactivate" })).toBeDisabled();
    expect(within(otherRow!).getByRole("button", { name: "Deactivate" })).toBeEnabled();
  });

  it("saves an edited role assignment", async () => {
    const api = mockApi({
      ...adminRoutes,
      "PUT /api/v1/users/u-analyst/roles": { ...analystUser, roles: ["analyst", "soc_auditor"] },
    });
    renderWithQuery(<UsersPage />);

    const row = (await screen.findByText(analystUser.email)).closest("tr")!;
    const user = userEvent.setup();
    await user.click(within(row).getByRole("button", { name: "Edit roles" }));
    await user.click(within(row).getByRole("checkbox", { name: "soc_auditor" }));
    await user.click(within(row).getByRole("button", { name: "Save" }));

    await waitFor(() => expect(api.calls.some((c) => c.method === "PUT")).toBe(true));
    expect(api.calls.find((c) => c.method === "PUT")?.body).toEqual({ roles: ["analyst", "soc_auditor"] });
  });

  it("shows an access notice and never requests users without user:read", async () => {
    const api = mockApi({ "GET /api/v1/me": viewerMe });
    renderWithQuery(<UsersPage />);

    expect(await screen.findByText(/don't have access/i)).toBeInTheDocument();
    expect(api.calls.some((c) => c.path === "/api/v1/users")).toBe(false);
  });
});
