import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { vi } from "vitest";

import type { Me, RoleRead, UserRead } from "@/api/types";

type Handler = (request: Request) => unknown;

export interface RecordedCall {
  method: string;
  path: string;
  body: unknown;
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

/** Stubs `fetch` by "METHOD /path"; unmocked routes return a 404 problem document. */
export function mockApi(routes: Record<string, unknown>) {
  const calls: RecordedCall[] = [];
  const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const url = new URL(request.url);
    const key = `${request.method} ${url.pathname}`;
    const text = request.method === "GET" ? "" : await request.clone().text();
    calls.push({ method: request.method, path: url.pathname, body: text ? JSON.parse(text) : undefined });
    if (!(key in routes)) {
      return json({ type: "about:blank", title: "Not Found", status: 404, detail: `unmocked ${key}` }, 404);
    }
    const route = routes[key];
    const result = typeof route === "function" ? await (route as Handler)(request) : route;
    return result instanceof Response ? result : json(result);
  });
  return { calls, spy };
}

export function renderWithQuery(ui: ReactElement) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>);
}

export const adminMe: Me = {
  id: "u-admin",
  org_id: "org-1",
  email: "ada@example.com",
  full_name: "Ada Admin",
  roles: ["admin"],
  permissions: ["audit:read", "platform:read", "role:manage", "role:read", "user:manage", "user:read"],
  last_login_at: "2026-09-15T10:00:00Z",
};

export const viewerMe: Me = {
  ...adminMe,
  id: "u-viewer",
  email: "vic@example.com",
  full_name: "Vic Viewer",
  roles: ["viewer"],
  permissions: ["platform:read"],
};

const timestamps = { created_at: "2026-09-01T09:00:00Z", updated_at: "2026-09-01T09:00:00Z" };

export const adminUser: UserRead = {
  id: adminMe.id,
  org_id: "org-1",
  email: adminMe.email,
  full_name: adminMe.full_name,
  is_active: true,
  roles: ["admin"],
  last_login_at: adminMe.last_login_at,
  ...timestamps,
};

export const analystUser: UserRead = {
  id: "u-analyst",
  org_id: "org-1",
  email: "analyst@example.com",
  full_name: "Sam Analyst",
  is_active: true,
  roles: ["analyst"],
  last_login_at: null,
  ...timestamps,
};

export const roles: RoleRead[] = [
  {
    id: "r-admin",
    name: "admin",
    description: "Full platform administration",
    is_system: true,
    permissions: adminMe.permissions,
  },
  {
    id: "r-analyst",
    name: "analyst",
    description: "Tier-1 analyst",
    is_system: true,
    permissions: ["platform:read"],
  },
  {
    id: "r-auditor",
    name: "soc_auditor",
    description: "Reads audit",
    is_system: false,
    permissions: ["audit:read"],
  },
];

export const permissionCatalogue = [
  { name: "audit:read", description: "Read the audit log and verify its integrity" },
  { name: "platform:read", description: "View platform status and non-secret configuration" },
];
