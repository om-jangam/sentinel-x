import { ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";

import { useMe } from "@/api/hooks";
import type { PermissionName } from "@/api/types";
import { hasPermission } from "@/features/auth/auth";

/**
 * UI gating only — improves the experience for users without access. The API enforces every
 * permission independently, so hiding a control is never the security boundary.
 */
export function RequirePermission({
  permission,
  children,
}: {
  permission: PermissionName;
  children: ReactNode;
}) {
  const { data: me, isPending } = useMe();
  if (isPending) return null;
  if (!hasPermission(me, permission)) {
    return (
      <div role="alert" className="flex items-center gap-3 rounded-lg border border-border bg-surface p-6">
        <ShieldAlert className="size-5 text-warning" />
        <div>
          <p className="font-medium">You don&apos;t have access to this page</p>
          <p className="text-sm text-muted">
            It requires the <code className="font-mono">{permission}</code> permission. Ask an administrator.
          </p>
        </div>
      </div>
    );
  }
  return <>{children}</>;
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description ? <p className="mt-1 text-sm text-muted">{description}</p> : null}
      </div>
      {actions}
    </div>
  );
}
