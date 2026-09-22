import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from "@tanstack/react-router";
import { render } from "@testing-library/react";
import type { FunctionComponent } from "react";

/** Renders a page inside a real router, so `Link` works; any other path renders "Navigated elsewhere". */
export function renderInRouter(Page: FunctionComponent, { path = "/" }: { path?: string } = {}) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const root = createRootRoute({ component: Outlet });
  const page = createRoute({ getParentRoute: () => root, path, component: Page });
  const elsewhere = createRoute({
    getParentRoute: () => root,
    path: "$",
    component: function Elsewhere() {
      return <p>Navigated elsewhere</p>;
    },
  });
  const router = createRouter({
    routeTree: root.addChildren([page, elsewhere]),
    history: createMemoryHistory({ initialEntries: [path] }),
  });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return router;
}
