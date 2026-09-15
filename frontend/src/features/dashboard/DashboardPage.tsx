import { CheckCircle2, CircleAlert, CircleDashed } from "lucide-react";

import { useAuditVerification, useHealth, useMe } from "@/api/hooks";
import { PageHeader } from "@/components/RequirePermission";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { hasPermission } from "@/features/auth/auth";
import { formatDateTime } from "@/lib/utils";

function CheckIcon({ state }: { state: string }) {
  if (state === "ok") return <CheckCircle2 className="size-4 text-success" />;
  if (state === "not_configured") return <CircleDashed className="size-4 text-muted" />;
  return <CircleAlert className="size-4 text-danger" />;
}

export function DashboardPage() {
  const { data: me } = useMe();
  const canReadPlatform = hasPermission(me, "platform:read");
  const canReadAudit = hasPermission(me, "audit:read");
  const health = useHealth(canReadPlatform);
  const verification = useAuditVerification(canReadAudit);

  if (!me) return null;

  return (
    <>
      <PageHeader
        title={`Welcome, ${me.full_name}`}
        description={`Last sign-in ${formatDateTime(me.last_login_at)}`}
      />
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Your access</CardTitle>
            <CardDescription>
              Roles and effective permissions, resolved live on every request.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex flex-wrap gap-1.5">
              {me.roles.map((role) => (
                <Badge key={role} tone="primary">
                  {role}
                </Badge>
              ))}
            </div>
            <div className="flex flex-wrap gap-1.5">
              {me.permissions.map((permission) => (
                <Badge key={permission} className="font-mono">
                  {permission}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>

        {canReadPlatform ? (
          <Card>
            <CardHeader>
              <CardTitle>Platform health</CardTitle>
              <CardDescription>
                {health.data
                  ? `v${health.data.version} · ${health.data.environment}`
                  : "Checking dependencies…"}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {health.data ? (
                <ul className="space-y-2">
                  {Object.entries(health.data.checks).map(([name, state]) => (
                    <li key={name} className="flex items-center justify-between text-sm">
                      <span className="flex items-center gap-2 capitalize">
                        <CheckIcon state={state} /> {name}
                      </span>
                      <span className="text-muted">{state.replace("_", " ")}</span>
                    </li>
                  ))}
                </ul>
              ) : health.isError ? (
                <p className="text-sm text-danger">Health check unavailable</p>
              ) : null}
            </CardContent>
          </Card>
        ) : null}

        {canReadAudit ? (
          <Card className="md:col-span-2">
            <CardHeader>
              <CardTitle>Audit trail integrity</CardTitle>
              <CardDescription>
                Every state change is hash-chained. Verification recomputes the chain end to end.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {verification.data ? (
                verification.data.valid ? (
                  <p className="flex items-center gap-2 text-sm">
                    <CheckCircle2 className="size-4 text-success" />
                    Chain intact — {verification.data.entries_checked} entries verified. Head{" "}
                    <code className="font-mono text-xs text-muted">
                      {verification.data.head_hash?.slice(0, 16)}…
                    </code>
                  </p>
                ) : (
                  <p className="flex items-center gap-2 text-sm text-danger">
                    <CircleAlert className="size-4" />
                    Tampering detected at entry #{verification.data.broken_at_index}:{" "}
                    {verification.data.reason}
                  </p>
                )
              ) : (
                <p className="text-sm text-muted">Verifying…</p>
              )}
            </CardContent>
          </Card>
        ) : null}
      </div>
    </>
  );
}
