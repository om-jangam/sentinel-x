import { Link } from "@tanstack/react-router";
import {
  ArrowRight,
  BrainCircuit,
  CheckCircle2,
  ChevronDown,
  CircleAlert,
  CircleDashed,
  Clock,
  Database,
  Globe,
  Link2,
  type LucideIcon,
  Radar,
  ShieldAlert,
  Siren,
} from "lucide-react";
import type { ReactNode } from "react";

import {
  useAssistantStatus,
  useAuditVerification,
  useHealth,
  useIncidents,
  useIntelProviders,
  useMe,
} from "@/api/hooks";
import type { Incident } from "@/api/types";
import { PageHeader } from "@/components/RequirePermission";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { hasPermission } from "@/features/auth/auth";
import { STATUS_LABELS, severityTone, statusTone } from "@/features/incidents/format";
import { cn, formatDateTime } from "@/lib/utils";

function CheckIcon({ state }: { state: string }) {
  if (state === "ok") return <CheckCircle2 className="size-4 text-success" />;
  if (state === "not_configured") return <CircleDashed className="size-4 text-muted" />;
  return <CircleAlert className="size-4 text-danger" />;
}

// ------------------------------------------------------------------ incident summary

function StatTile({
  label,
  value,
  hint,
  icon: Icon,
  tone = "neutral",
}: {
  label: string;
  value: ReactNode;
  hint: string;
  icon: LucideIcon;
  tone?: "neutral" | "danger" | "warning" | "success";
}) {
  const toneClass = {
    neutral: "text-primary bg-primary/10",
    danger: "text-danger bg-danger/10",
    warning: "text-warning bg-warning/10",
    success: "text-success bg-success/10",
  }[tone];
  return (
    <Link
      to="/incidents"
      className="group rounded-lg border border-border bg-surface p-4 transition-colors hover:border-primary/50"
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm text-muted">{label}</p>
          <p className="mt-1 text-3xl font-semibold tabular-nums">{value}</p>
        </div>
        <span className={cn("grid size-9 place-items-center rounded-md", toneClass)}>
          <Icon className="size-4" />
        </span>
      </div>
      <p className="mt-2 text-xs text-muted">{hint}</p>
    </Link>
  );
}

function bySeverityThenRecency(a: Incident, b: Incident): number {
  return b.severity_id - a.severity_id || b.last_seen.localeCompare(a.last_seen);
}

function IncidentOverview() {
  const incidents = useIncidents({});
  const items = incidents.data?.pages.flatMap((page) => page.items) ?? [];
  // Only the first page is loaded; say so rather than show a total that might be low.
  const more = incidents.hasNextPage ? "+" : "";

  if (incidents.isPending) {
    return <p className="text-sm text-muted">Loading incidents…</p>;
  }
  if (incidents.isError) {
    return <p className="text-sm text-danger">Incidents are unavailable right now.</p>;
  }
  if (items.length === 0) {
    return <NoIncidentsYet />;
  }

  const open = items.filter((incident) => incident.status !== "closed");
  const urgent = open.filter((incident) => incident.severity_id >= 4);
  const investigating = open.filter((incident) => incident.status === "investigating");
  const events = items.reduce((sum, incident) => sum + incident.event_count, 0);
  const attention = [...open].sort(bySeverityThenRecency).slice(0, 5);

  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile
          label="Open incidents"
          value={`${open.length}${more}`}
          hint="New or under investigation"
          icon={Siren}
        />
        <StatTile
          label="High or critical"
          value={`${urgent.length}${more}`}
          hint="Open incidents to look at first"
          icon={ShieldAlert}
          tone={urgent.length ? "danger" : "success"}
        />
        <StatTile
          label="Being investigated"
          value={`${investigating.length}${more}`}
          hint="Someone has picked these up"
          icon={Radar}
          tone="warning"
        />
        <StatTile
          label="Events as evidence"
          value={`${events}${more}`}
          hint="Stored events the incidents cite"
          icon={Database}
        />
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <div>
            <CardTitle>Needs attention</CardTitle>
            <CardDescription>Open incidents, most severe first.</CardDescription>
          </div>
          <Link to="/incidents" className="flex items-center gap-1 text-sm text-primary hover:underline">
            All incidents <ArrowRight className="size-3.5" />
          </Link>
        </CardHeader>
        <CardContent className="p-0">
          {attention.length === 0 ? (
            <p className="px-5 pb-5 text-sm text-muted">Every incident is closed.</p>
          ) : (
            <ul className="divide-y divide-border border-t border-border">
              {attention.map((incident) => (
                <li key={incident.id}>
                  <Link
                    to="/incidents/$incidentId"
                    params={{ incidentId: incident.id }}
                    className="flex flex-wrap items-center gap-x-4 gap-y-1 px-5 py-3 hover:bg-surface-raised"
                  >
                    <Badge tone={severityTone(incident.severity_id)} className="w-16 justify-center">
                      {incident.severity}
                    </Badge>
                    <span className="min-w-0 flex-1 truncate font-medium">{incident.title}</span>
                    <Badge tone={statusTone(incident.status)}>{STATUS_LABELS[incident.status]}</Badge>
                    <span className="flex items-center gap-1 text-xs text-muted">
                      <Clock className="size-3" /> {formatDateTime(incident.last_seen)}
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function NoIncidentsYet() {
  return (
    <Card className="border-dashed">
      <CardContent className="flex flex-col items-center gap-3 py-10 text-center">
        <span className="grid size-12 place-items-center rounded-full bg-primary/10 text-primary">
          <Siren className="size-5" />
        </span>
        <div className="space-y-1">
          <p className="font-semibold">No incidents yet</p>
          <p className="max-w-lg text-sm text-muted">
            Incidents appear once security logs arrive and detection finds something suspicious in them. To
            explore with the two sample attacks, run this in the Sentinel-X folder:
          </p>
        </div>
        <code className="max-w-full rounded-md border border-border bg-surface-raised px-3 py-1.5 font-mono text-xs break-words">
          docker compose run --rm --no-deps -v ./pipeline/samples:/samples:ro api sentinelx load-demo
          --samples /samples
        </code>
      </CardContent>
    </Card>
  );
}

// ------------------------------------------------------------------ how it works

type StageState = "on" | "off";

interface Stage {
  icon: LucideIcon;
  title: string;
  text: string;
  state: StageState;
  status: string;
}

function PipelineCard({ canReadIntel }: { canReadIntel: boolean }) {
  const providers = useIntelProviders(canReadIntel);
  const assistant = useAssistantStatus();

  const intelStatus = !canReadIntel
    ? { state: "off" as const, status: "Not visible to your role" }
    : providers.data === undefined
      ? { state: "off" as const, status: "Checking…" }
      : providers.data.length
        ? { state: "on" as const, status: providers.data.map((p) => p.title).join(", ") }
        : { state: "off" as const, status: "No provider configured" };
  const aiStatus =
    assistant.data === undefined
      ? { state: "off" as const, status: "Checking…" }
      : assistant.data.enabled
        ? { state: "on" as const, status: assistant.data.model ?? assistant.data.provider ?? "On" }
        : { state: "off" as const, status: "No model configured" };

  const stages: Stage[] = [
    {
      icon: Database,
      title: "Collect",
      text: "Logs from Windows, Linux and the network are converted to one common format and stored unchanged.",
      state: "on",
      status: "Always on",
    },
    {
      icon: Radar,
      title: "Detect",
      text: "Fixed rules flag suspicious events, such as a logon after many failures. Each flag is a finding.",
      state: "on",
      status: "Always on",
    },
    {
      icon: Link2,
      title: "Correlate",
      text: "Findings that share a host, user or address become one incident. Every link cites its events.",
      state: "on",
      status: "Always on",
    },
    {
      icon: Globe,
      title: "Threat intel",
      text: "Outside IPs, domains and file hashes are checked against intel sources. Context, not proof.",
      ...intelStatus,
    },
    {
      icon: BrainCircuit,
      title: "AI explanation",
      text: "On request, a model summarises an incident. Anything it says without real evidence is removed.",
      ...aiStatus,
    },
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle>How Sentinel-X works</CardTitle>
        <CardDescription>From raw logs to an explained incident. Nothing is ever invented.</CardDescription>
      </CardHeader>
      <CardContent>
        <ol className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
          {stages.map((stage, index) => (
            <li
              key={stage.title}
              className="relative rounded-md border border-border bg-surface-raised/40 p-3"
            >
              <div className="flex items-center gap-2">
                <span className="grid size-6 shrink-0 place-items-center rounded-full bg-primary/15 text-xs font-semibold text-primary">
                  {index + 1}
                </span>
                <stage.icon className="size-4 shrink-0 text-muted" aria-hidden />
                <p className="text-sm font-semibold">{stage.title}</p>
              </div>
              <p className="mt-2 text-xs leading-relaxed text-muted">{stage.text}</p>
              <p
                className={cn(
                  "mt-2 flex items-start gap-1.5 text-xs [&_svg]:mt-px [&_svg]:shrink-0",
                  stage.state === "on" ? "text-success" : "text-muted",
                )}
              >
                {stage.state === "on" ? (
                  <CheckCircle2 className="size-3.5" />
                ) : (
                  <CircleDashed className="size-3.5" />
                )}
                <span>{stage.status}</span>
              </p>
            </li>
          ))}
        </ol>
      </CardContent>
    </Card>
  );
}

// ------------------------------------------------------------------ system

export function DashboardPage() {
  const { data: me } = useMe();
  const canReadPlatform = hasPermission(me, "platform:read");
  const canReadAudit = hasPermission(me, "audit:read");
  const canReadIncidents = hasPermission(me, "incident:read");
  const health = useHealth(canReadPlatform);
  const verification = useAuditVerification(canReadAudit);

  if (!me) return null;

  return (
    <>
      <PageHeader
        title={`Welcome, ${me.full_name}`}
        description={`Last sign-in ${formatDateTime(me.last_login_at)}`}
      />
      <div className="space-y-6">
        {canReadIncidents ? <IncidentOverview /> : null}

        <PipelineCard canReadIntel={hasPermission(me, "intel:read")} />

        <div className="grid gap-4 lg:grid-cols-3">
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
                          <CheckIcon state={state} /> {name.replace("_", " ")}
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
            <Card>
              <CardHeader>
                <CardTitle>Audit trail integrity</CardTitle>
                <CardDescription>
                  Every change is chained to the one before, so tampering shows.
                </CardDescription>
              </CardHeader>
              <CardContent>
                {verification.data ? (
                  verification.data.valid ? (
                    <div className="space-y-2 text-sm">
                      <p className="flex items-center gap-2">
                        <CheckCircle2 className="size-4 text-success" />
                        Chain intact — {verification.data.entries_checked} entries verified.
                      </p>
                      <p className="text-xs text-muted">
                        Head <code className="font-mono">{verification.data.head_hash?.slice(0, 16)}…</code>
                      </p>
                      <Link
                        to="/admin/audit"
                        className="inline-flex items-center gap-1 text-primary hover:underline"
                      >
                        Open audit log <ArrowRight className="size-3.5" />
                      </Link>
                    </div>
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

          <Card>
            <CardHeader>
              <CardTitle>Your access</CardTitle>
              <CardDescription>Checked again on every request.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex flex-wrap gap-1.5">
                {me.roles.map((role) => (
                  <Badge key={role} tone="primary">
                    {role}
                  </Badge>
                ))}
              </div>
              <details className="group text-sm">
                <summary className="flex cursor-pointer list-none items-center gap-1 text-muted hover:text-foreground">
                  {me.permissions.length} permissions
                  <ChevronDown className="size-3.5 transition-transform group-open:rotate-180" />
                </summary>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {me.permissions.map((permission) => (
                    <Badge key={permission} className="font-mono">
                      {permission}
                    </Badge>
                  ))}
                </div>
              </details>
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  );
}
