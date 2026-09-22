import type { QueryClient } from "@tanstack/react-query";
import {
  createRootRouteWithContext,
  createRoute,
  createRouter,
  Link,
  Outlet,
  redirect,
} from "@tanstack/react-router";
import { Toaster } from "sonner";

import { AppShell } from "@/components/layout/AppShell";
import { AuditPage } from "@/features/admin/AuditPage";
import { RolesPage } from "@/features/admin/RolesPage";
import { UsersPage } from "@/features/admin/UsersPage";
import { ensureSession, safeRedirect } from "@/features/auth/auth";
import { LoginPage } from "@/features/auth/LoginPage";
import { DashboardPage } from "@/features/dashboard/DashboardPage";
import { IncidentPage } from "@/features/incidents/IncidentPage";
import { IncidentsPage } from "@/features/incidents/IncidentsPage";

import { queryClient } from "./query";

interface RouterContext {
  queryClient: QueryClient;
}

const rootRoute = createRootRouteWithContext<RouterContext>()({
  component: () => (
    <>
      <Outlet />
      <Toaster theme="dark" richColors position="bottom-right" />
    </>
  ),
  notFoundComponent: () => (
    <div className="grid h-full place-items-center p-8 text-center">
      <div className="space-y-2">
        <p className="text-lg font-semibold">Page not found</p>
        <Link to="/" className="text-primary underline">
          Back to overview
        </Link>
      </div>
    </div>
  ),
});

export const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  validateSearch: (search: Record<string, unknown>): { redirect?: string } =>
    search.redirect === undefined ? {} : { redirect: safeRedirect(search.redirect) },
  component: LoginPage,
});

const appRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "app",
  beforeLoad: async ({ context, location }) => {
    const me = await ensureSession(context.queryClient);
    if (!me) {
      throw redirect({ to: "/login", search: { redirect: location.href } });
    }
    return { me };
  },
  component: AppShell,
});

const dashboardRoute = createRoute({ getParentRoute: () => appRoute, path: "/", component: DashboardPage });
const usersRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/admin/users",
  component: UsersPage,
});
const rolesRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/admin/roles",
  component: RolesPage,
});
const incidentsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/incidents",
  component: IncidentsPage,
});
const incidentRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/incidents/$incidentId",
  component: function IncidentRoute() {
    const { incidentId } = incidentRoute.useParams();
    return <IncidentPage key={incidentId} incidentId={incidentId} />;
  },
});
const auditRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/admin/audit",
  component: AuditPage,
});

const routeTree = rootRoute.addChildren([
  loginRoute,
  appRoute.addChildren([dashboardRoute, incidentsRoute, incidentRoute, usersRoute, rolesRoute, auditRoute]),
]);

export const router = createRouter({
  routeTree,
  context: { queryClient },
  defaultPreload: "intent",
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
