import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { Me } from "@/api/types";
import { adminMe, mockApi, viewerMe } from "@/test/utils";

import { AppShell } from "./AppShell";

afterEach(() => vi.restoreAllMocks());

function renderShell(me: Me) {
  mockApi({ "GET /api/v1/me": me });
  const rootRoute = createRootRoute({ component: AppShell });
  const pages = ["/", "/admin/users", "/admin/roles", "/admin/audit"].map((path) =>
    createRoute({ getParentRoute: () => rootRoute, path, component: () => <p>page {path}</p> }),
  );
  const router = createRouter({
    routeTree: rootRoute.addChildren(pages),
    history: createMemoryHistory({ initialEntries: ["/"] }),
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router as never} />
    </QueryClientProvider>,
  );
}

describe("AppShell", () => {
  it("shows admin navigation to an admin", async () => {
    renderShell(adminMe);
    const nav = await screen.findByRole("navigation", { name: "Primary" });
    await waitFor(() => expect(nav).toHaveTextContent("Audit log"));
    expect(nav).toHaveTextContent("Users");
    expect(nav).toHaveTextContent("Roles & permissions");
  });

  it("hides links the principal lacks permission for", async () => {
    renderShell(viewerMe);
    expect(await screen.findByText("vic@example.com")).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Primary" });
    expect(nav).toHaveTextContent("Overview");
    expect(nav).not.toHaveTextContent("Users");
    expect(nav).not.toHaveTextContent("Audit log");
  });

  it("opens the mobile drawer, closes it on Escape and after navigating", async () => {
    renderShell(adminMe);
    const user = userEvent.setup();
    const sidebar = await waitFor(() => {
      const element = document.getElementById("primary-sidebar");
      if (!element) throw new Error("sidebar not rendered");
      return element;
    });
    expect(sidebar).toHaveAttribute("data-open", "false");

    await user.click(screen.getByRole("button", { name: "Open navigation" }));
    expect(sidebar).toHaveAttribute("data-open", "true");
    expect(screen.getByRole("button", { name: "Close navigation" })).toHaveAttribute("aria-expanded", "true");

    await user.keyboard("{Escape}");
    expect(sidebar).toHaveAttribute("data-open", "false");

    await user.click(screen.getByRole("button", { name: "Open navigation" }));
    await user.click(await screen.findByRole("link", { name: "Users" }));
    expect(await screen.findByText("page /admin/users")).toBeInTheDocument();
    expect(sidebar).toHaveAttribute("data-open", "false");
  });
});
