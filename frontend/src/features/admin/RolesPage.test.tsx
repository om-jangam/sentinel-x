import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { adminMe, mockApi, permissionCatalogue, renderWithQuery, roles } from "@/test/utils";

import { RolesPage } from "./RolesPage";

afterEach(() => vi.restoreAllMocks());

describe("RolesPage", () => {
  it("locks system roles and edits custom role permissions", async () => {
    const api = mockApi({
      "GET /api/v1/me": adminMe,
      "GET /api/v1/roles": roles,
      "GET /api/v1/permissions": permissionCatalogue,
      "PATCH /api/v1/roles/r-auditor": { ...roles[2], permissions: ["audit:read", "platform:read"] },
    });
    renderWithQuery(<RolesPage />);

    expect(await screen.findByText("soc_auditor")).toBeInTheDocument();
    expect(screen.getAllByText("system")).toHaveLength(2);
    // Only the one custom role is editable.
    const editButtons = screen.getAllByRole("button", { name: "Edit permissions" });
    expect(editButtons).toHaveLength(1);

    const user = userEvent.setup();
    await user.click(editButtons[0]!);
    // The create-role form renders its own checklist first; the role editor's comes last.
    const checkboxes = await screen.findAllByRole("checkbox", { name: /platform:read/ });
    await user.click(checkboxes[checkboxes.length - 1]!);
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(api.calls.some((c) => c.method === "PATCH")).toBe(true));
    expect(api.calls.find((c) => c.method === "PATCH")?.body).toEqual({
      permissions: ["audit:read", "platform:read"],
    });
  });

  it("creates a custom role", async () => {
    const api = mockApi({
      "GET /api/v1/me": adminMe,
      "GET /api/v1/roles": roles,
      "GET /api/v1/permissions": permissionCatalogue,
      "POST /api/v1/roles": { ...roles[2], id: "r-new", name: "tier2" },
    });
    renderWithQuery(<RolesPage />);

    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Name"), "tier2");
    await user.type(screen.getByLabelText("Description"), "Escalations");
    await user.click((await screen.findAllByRole("checkbox", { name: /audit:read/ }))[0]!);
    await user.click(screen.getByRole("button", { name: /create role/i }));

    await waitFor(() => expect(api.calls.some((c) => c.method === "POST")).toBe(true));
    expect(api.calls.find((c) => c.method === "POST")?.body).toEqual({
      name: "tier2",
      description: "Escalations",
      permissions: ["audit:read"],
    });
  });
});
