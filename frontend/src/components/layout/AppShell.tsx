import { useQueryClient } from "@tanstack/react-query";
import { Link, Outlet, useNavigate } from "@tanstack/react-router";
import {
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  ScrollText,
  ShieldCheck,
  Siren,
  Users,
  X,
} from "lucide-react";
import { type ComponentType, useEffect, useState } from "react";

import { useMe } from "@/api/hooks";
import type { PermissionName } from "@/api/types";
import { Button } from "@/components/ui/button";
import { hasPermission, logout } from "@/features/auth/auth";
import { session } from "@/lib/session";
import { cn } from "@/lib/utils";

interface NavItem {
  to: "/" | "/incidents" | "/admin/users" | "/admin/roles" | "/admin/audit";
  label: string;
  icon: ComponentType<{ className?: string }>;
  permission?: PermissionName;
}

const NAV: NavItem[] = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/incidents", label: "Incidents", icon: Siren, permission: "incident:read" },
  { to: "/admin/users", label: "Users", icon: Users, permission: "user:read" },
  { to: "/admin/roles", label: "Roles & permissions", icon: ShieldCheck, permission: "role:read" },
  { to: "/admin/audit", label: "Audit log", icon: ScrollText, permission: "audit:read" },
];

function Brand() {
  return (
    <div className="flex items-center gap-2">
      <img src="/favicon.svg" alt="" className="size-7" />
      <div>
        <p className="font-semibold leading-tight">Sentinel-X</p>
        <p className="text-xs text-muted">SOC Console</p>
      </div>
    </div>
  );
}

export function AppShell() {
  const { data: me } = useMe();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  // Below the md breakpoint the sidebar becomes an off-canvas drawer.
  const [navOpen, setNavOpen] = useState(false);

  // If a refresh ever fails (session revoked elsewhere, reuse detected), send the analyst to login.
  useEffect(
    () =>
      session.subscribe((token) => {
        if (token === null) void navigate({ to: "/login", search: {} });
      }),
    [navigate],
  );

  useEffect(() => {
    if (!navOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setNavOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [navOpen]);

  const onLogout = async () => {
    await logout(queryClient);
    await navigate({ to: "/login", search: {} });
  };

  return (
    <div className="flex h-full flex-col md:flex-row">
      <header className="flex items-center justify-between border-b border-border bg-surface px-4 py-3 md:hidden">
        <Brand />
        <Button
          variant="ghost"
          size="icon"
          aria-label={navOpen ? "Close navigation" : "Open navigation"}
          aria-expanded={navOpen}
          aria-controls="primary-sidebar"
          onClick={() => setNavOpen(!navOpen)}
        >
          {navOpen ? <X /> : <Menu />}
        </Button>
      </header>

      {navOpen ? (
        <div
          className="fixed inset-0 z-30 bg-black/60 md:hidden"
          aria-hidden
          onClick={() => setNavOpen(false)}
        />
      ) : null}

      <aside
        id="primary-sidebar"
        data-open={navOpen}
        className={cn(
          "fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-border bg-surface transition-transform duration-200",
          "md:static md:z-auto md:w-60 md:shrink-0 md:translate-x-0",
          navOpen ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="px-5 py-4">
          <Brand />
        </div>
        <nav className="flex flex-1 flex-col gap-1 px-3" aria-label="Primary">
          {NAV.filter((item) => !item.permission || hasPermission(me, item.permission)).map((item) => (
            <Link
              key={item.to}
              to={item.to}
              activeOptions={{ exact: item.to === "/" }}
              onClick={() => setNavOpen(false)}
              className="flex items-center gap-3 rounded-md px-3 py-2 text-sm text-muted hover:bg-surface-raised hover:text-foreground"
              activeProps={{ className: "bg-surface-raised text-foreground" }}
            >
              <item.icon className="size-4" />
              {item.label}
            </Link>
          ))}
        </nav>
        <div className="border-t border-border p-3">
          <p className="truncate px-2 text-sm font-medium">{me?.full_name}</p>
          <p className="truncate px-2 text-xs text-muted">{me?.email}</p>
          <Link
            to="/account"
            onClick={() => setNavOpen(false)}
            className="mt-2 flex items-center gap-2 rounded-md px-3 py-1.5 text-sm text-muted hover:bg-surface-raised hover:text-foreground [&_svg]:size-4"
            activeProps={{ className: "bg-surface-raised text-foreground" }}
          >
            <KeyRound /> Change password
          </Link>
          <Button variant="ghost" size="sm" className="w-full justify-start" onClick={() => void onLogout()}>
            <LogOut /> Sign out
          </Button>
        </div>
      </aside>

      <main className="min-w-0 flex-1 overflow-y-auto">
        <div className="mx-auto max-w-6xl p-4 md:p-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
