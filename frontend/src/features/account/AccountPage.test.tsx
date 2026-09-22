import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { session } from "@/lib/session";
import { adminMe, json, mockApi, renderWithQuery } from "@/test/utils";

import { AccountPage } from "./AccountPage";

afterEach(() => {
  vi.restoreAllMocks();
  session.clear();
});

const tokens = {
  access_token: "new-access-token",
  token_type: "bearer",
  expires_in: 900,
  expires_at: "2026-09-22T12:15:00Z",
};

async function fill(current: string, next: string, confirm = next) {
  const user = userEvent.setup();
  await user.type(screen.getByLabelText("Current password"), current);
  await user.type(screen.getByLabelText("New password"), next);
  await user.type(screen.getByLabelText("Confirm new password"), confirm);
  await user.click(screen.getByRole("button", { name: "Change password" }));
}

describe("AccountPage", () => {
  it("changes the password and adopts the new session token", async () => {
    const api = mockApi({ "GET /api/v1/me": adminMe, "POST /api/v1/auth/password": tokens });
    renderWithQuery(<AccountPage />);

    expect(await screen.findByText(/ada@example.com/)).toBeInTheDocument();
    await fill("old-passphrase-here", "a-brand-new-passphrase");

    await waitFor(() => expect(session.getToken()).toBe("new-access-token"));
    expect(api.calls.find((c) => c.path === "/api/v1/auth/password")?.body).toEqual({
      current_password: "old-passphrase-here",
      new_password: "a-brand-new-passphrase",
    });
    expect(screen.getByLabelText("Current password")).toHaveValue("");
  });

  it("never sends mismatched new passwords", async () => {
    const api = mockApi({ "GET /api/v1/me": adminMe });
    renderWithQuery(<AccountPage />);

    await fill("old-passphrase-here", "a-brand-new-passphrase", "a-different-passphrase");

    expect(await screen.findByRole("alert")).toHaveTextContent("don't match");
    expect(api.calls.some((c) => c.path === "/api/v1/auth/password")).toBe(false);
  });

  it("shows the server's reason when the change is refused", async () => {
    mockApi({
      "GET /api/v1/me": adminMe,
      "POST /api/v1/auth/password": json(
        {
          type: "about:blank",
          title: "Validation failed",
          status: 422,
          detail: "Current password is incorrect",
          errors: [{ loc: ["current_password"], msg: "is incorrect", type: "invalid" }],
        },
        422,
      ),
    });
    renderWithQuery(<AccountPage />);

    await fill("wrong-passphrase", "a-brand-new-passphrase");

    expect(await screen.findByRole("alert")).toHaveTextContent("Current password is incorrect");
    expect(session.getToken()).toBeNull();
  });
});
