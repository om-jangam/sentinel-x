import { Link } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { type FormEvent, useState } from "react";
import { toast } from "sonner";

import { ApiError, errorMessage } from "@/api/errors";
import {
  useAddNote,
  useChangeIncidentStatus,
  useIncident,
  useIncidentEvidence,
  useIncidentGraph,
  useIncidentNotes,
  useIncidentTimeline,
  useMe,
} from "@/api/hooks";
import type { IncidentDetail, IncidentStatus, Resolution } from "@/api/types";
import { RequirePermission } from "@/components/RequirePermission";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Label, Select } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { hasPermission } from "@/features/auth/auth";
import { cn, formatDateTime } from "@/lib/utils";

import { EntityGraphView } from "./EntityGraphView";
import {
  entityValue,
  RESOLUTION_LABELS,
  RULE_LABELS,
  STATUS_LABELS,
  severityTone,
  statusTone,
} from "./format";
import { Inspector } from "./Inspector";
import type { Selection } from "./selection";
import { Timeline } from "./Timeline";

const TABS = ["timeline", "graph", "links", "entities", "notes"] as const;
type Tab = (typeof TABS)[number];
const TAB_LABELS: Record<Tab, string> = {
  timeline: "Timeline",
  graph: "Graph",
  links: "Findings & links",
  entities: "Entities",
  notes: "Notes",
};

function StatusActions({ incident }: { incident: IncidentDetail }) {
  const { data: me } = useMe();
  const change = useChangeIncidentStatus(incident.id);
  const [closing, setClosing] = useState(false);
  const [resolution, setResolution] = useState<Resolution>("true_positive");
  const canUpdate = hasPermission(me, "incident:update");
  const canResolve = hasPermission(me, "incident:resolve");

  const submit = (status: IncidentStatus, chosen?: Resolution) =>
    change.mutate(
      { status, resolution: chosen, version: incident.version },
      {
        onSuccess: (updated) => {
          toast.success(`Incident ${STATUS_LABELS[updated.status].toLowerCase()}`);
          setClosing(false);
        },
        onError: (error) =>
          toast.error(
            error instanceof ApiError && error.status === 409
              ? "Someone else changed this incident. It has been reloaded; try again."
              : errorMessage(error),
          ),
      },
    );

  if (closing) {
    return (
      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(event: FormEvent) => {
          event.preventDefault();
          submit("closed", resolution);
        }}
      >
        <div className="space-y-1">
          <Label htmlFor="resolution">Resolution</Label>
          <Select
            id="resolution"
            value={resolution}
            onChange={(e) => setResolution(e.currentTarget.value as Resolution)}
          >
            {Object.entries(RESOLUTION_LABELS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </Select>
        </div>
        <Button type="submit" disabled={change.isPending}>
          Close incident
        </Button>
        <Button variant="ghost" onClick={() => setClosing(false)}>
          Cancel
        </Button>
      </form>
    );
  }
  return (
    <div className="flex flex-wrap gap-2">
      {incident.status === "new" && canUpdate ? (
        <Button disabled={change.isPending} onClick={() => submit("investigating")}>
          Start investigating
        </Button>
      ) : null}
      {incident.status !== "closed" && canResolve ? (
        <Button variant="secondary" disabled={change.isPending} onClick={() => setClosing(true)}>
          Close…
        </Button>
      ) : null}
      {incident.status === "closed" && canResolve ? (
        <Button variant="secondary" disabled={change.isPending} onClick={() => submit("investigating")}>
          Reopen
        </Button>
      ) : null}
    </div>
  );
}

function Summary({ incident }: { incident: IncidentDetail }) {
  return (
    <Card className="mb-4 space-y-4 p-4">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Badge tone={severityTone(incident.severity_id)}>{incident.severity}</Badge>
        <Badge tone={statusTone(incident.status)}>
          {STATUS_LABELS[incident.status]}
          {incident.resolution ? ` · ${RESOLUTION_LABELS[incident.resolution]}` : ""}
        </Badge>
        <span className="text-muted">
          {formatDateTime(incident.first_seen)} → {formatDateTime(incident.last_seen)}
        </span>
        <span className="text-muted">
          · {incident.finding_count} findings · {incident.event_count} events
        </span>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {incident.tactics.map((tactic) => (
          <Badge key={tactic}>{tactic.replaceAll("_", " ")}</Badge>
        ))}
        {incident.techniques.map((technique) => (
          <Badge key={technique} tone="primary" className="font-mono">
            {technique}
          </Badge>
        ))}
      </div>
      <div>
        <p className="mb-1 text-xs font-medium uppercase tracking-wide text-muted">Why this severity</p>
        <ul className="space-y-0.5 text-sm">
          {incident.assessment.map((entry) => (
            <li key={String(entry.rule)}>
              <Badge tone={severityTone(Number(entry.severity_id))} className="mr-2">
                {String(entry.rule)}
              </Badge>
              {String(entry.because)}
            </li>
          ))}
        </ul>
      </div>
    </Card>
  );
}

function LinksTable({
  incident,
  selectedId,
  onSelect,
}: {
  incident: IncidentDetail;
  selectedId: string | null;
  onSelect: (selection: Selection) => void;
}) {
  return (
    <Table aria-label="Findings and correlation links">
      <THead>
        <tr>
          <TH>Rule</TH>
          <TH>What and why</TH>
          <TH>Shared entities</TH>
          <TH className="text-right">Events</TH>
        </tr>
      </THead>
      <TBody>
        {incident.links.map((link) => {
          const id = `link:${link.id}`;
          const title =
            link.kind === "finding" ? String(link.detail.rule_title ?? "Finding") : "Successful logon";
          return (
            <TR
              key={link.id}
              className={cn("cursor-pointer", selectedId === id && "bg-primary/10")}
              onClick={() => onSelect({ id, label: title, events: link.evidence })}
            >
              <TD>
                <Badge tone={link.rule === "auth-success-after-failures" ? "danger" : "neutral"}>
                  {RULE_LABELS[link.rule] ?? link.rule}
                </Badge>
              </TD>
              <TD className="min-w-64">
                <p className="font-medium">{title}</p>
                <p className="text-xs text-muted">{link.reason}</p>
              </TD>
              <TD className="font-mono text-xs">{link.matched.map((m) => m.key).join(", ") || "—"}</TD>
              <TD className="text-right tabular-nums">{link.evidence.length}</TD>
            </TR>
          );
        })}
      </TBody>
    </Table>
  );
}

function EntitiesTable({
  incident,
  selectedId,
  onSelect,
}: {
  incident: IncidentDetail;
  selectedId: string | null;
  onSelect: (selection: Selection) => void;
}) {
  return (
    <Table aria-label="Entities">
      <THead>
        <tr>
          <TH>Type</TH>
          <TH>Value</TH>
          <TH>Joins incidents</TH>
          <TH>Seen</TH>
          <TH className="text-right">Events</TH>
        </tr>
      </THead>
      <TBody>
        {incident.entities.map((entity) => {
          const id = `entity:${entity.key}`;
          return (
            <TR
              key={entity.key}
              className={cn("cursor-pointer", selectedId === id && "bg-primary/10")}
              onClick={() => onSelect({ id, label: `${entity.type} ${entity.value}`, events: entity.events })}
            >
              <TD className="text-muted">{entity.type}</TD>
              <TD className="break-all font-mono text-xs">{entityValue(entity.key)}</TD>
              <TD>{entity.links ? "yes" : "context"}</TD>
              <TD className="whitespace-nowrap text-xs text-muted">{formatDateTime(entity.first_seen)}</TD>
              <TD className="text-right tabular-nums">{entity.events.length}</TD>
            </TR>
          );
        })}
      </TBody>
    </Table>
  );
}

function Notes({ incidentId }: { incidentId: string }) {
  const { data: me } = useMe();
  const notes = useIncidentNotes(incidentId);
  const add = useAddNote(incidentId);
  const [draft, setDraft] = useState("");

  return (
    <div className="space-y-4 p-4">
      <p className="text-xs text-muted">
        Notes are analyst statements, not evidence. They can&apos;t be edited or deleted, and each one is
        recorded in the audit log.
      </p>
      {notes.isError ? <p className="text-sm text-danger">{errorMessage(notes.error)}</p> : null}
      <ol className="space-y-3">
        {(notes.data ?? []).map((note) => (
          <li key={note.id} className="rounded-md border border-border p-3">
            <p className="mb-1 text-xs text-muted">
              {note.author_email} · {formatDateTime(note.created_at)}
            </p>
            <p className="whitespace-pre-wrap text-sm">{note.body}</p>
          </li>
        ))}
      </ol>
      {notes.data?.length === 0 ? <p className="text-sm text-muted">No notes yet.</p> : null}
      {hasPermission(me, "incident:update") ? (
        <form
          className="space-y-2"
          onSubmit={(event) => {
            event.preventDefault();
            if (!draft.trim()) return;
            add.mutate(draft, {
              onSuccess: () => setDraft(""),
              onError: (error) => toast.error(errorMessage(error)),
            });
          }}
        >
          <Label htmlFor="note-body">Add a note</Label>
          <textarea
            id="note-body"
            value={draft}
            maxLength={10_000}
            rows={3}
            onChange={(e) => setDraft(e.target.value)}
            className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
          />
          <Button type="submit" size="sm" disabled={add.isPending || !draft.trim()}>
            Add note
          </Button>
        </form>
      ) : null}
    </div>
  );
}

function Workspace({ incidentId }: { incidentId: string }) {
  const { data: me } = useMe();
  const incident = useIncident(incidentId);
  const timeline = useIncidentTimeline(incidentId);
  const graph = useIncidentGraph(incidentId);
  const evidence = useIncidentEvidence(incidentId);
  const [tab, setTab] = useState<Tab>("timeline");
  const [selection, setSelection] = useState<Selection | null>(null);

  if (incident.isPending) return <p className="text-sm text-muted">Loading incident…</p>;
  if (incident.isError) return <p className="text-sm text-danger">{errorMessage(incident.error)}</p>;
  const detail = incident.data;
  const selectedId = selection?.id ?? null;

  return (
    <>
      <div className="mb-4 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 space-y-1">
          <Link
            to="/incidents"
            className="inline-flex items-center gap-1 text-sm text-muted hover:text-foreground"
          >
            <ArrowLeft className="size-4" /> Incidents
          </Link>
          <h1 className="text-xl font-semibold tracking-tight">{detail.title}</h1>
        </div>
        <StatusActions incident={detail} />
      </div>
      <Summary incident={detail} />
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,380px)]">
        <Card className="min-w-0">
          <div
            role="tablist"
            aria-label="Incident views"
            className="flex gap-1 overflow-x-auto border-b border-border p-2"
          >
            {TABS.map((name) => (
              <button
                key={name}
                role="tab"
                type="button"
                aria-selected={tab === name}
                onClick={() => setTab(name)}
                className={cn(
                  "whitespace-nowrap rounded-md px-3 py-1.5 text-sm",
                  tab === name ? "bg-surface-raised text-foreground" : "text-muted hover:text-foreground",
                )}
              >
                {TAB_LABELS[name]}
              </button>
            ))}
          </div>
          <div role="tabpanel" aria-label={TAB_LABELS[tab]}>
            {tab === "timeline" ? (
              timeline.isError ? (
                <p className="p-4 text-sm text-danger">{errorMessage(timeline.error)}</p>
              ) : timeline.data ? (
                <Timeline
                  steps={timeline.data.steps}
                  unresolved={timeline.data.unresolved_events}
                  selectedId={selectedId}
                  onSelect={setSelection}
                />
              ) : (
                <p className="p-4 text-sm text-muted">Loading timeline…</p>
              )
            ) : null}
            {tab === "graph" ? (
              graph.isError ? (
                <p className="p-4 text-sm text-danger">{errorMessage(graph.error)}</p>
              ) : graph.data ? (
                <EntityGraphView graph={graph.data} selectedId={selectedId} onSelect={setSelection} />
              ) : (
                <p className="p-4 text-sm text-muted">Loading graph…</p>
              )
            ) : null}
            {tab === "links" ? (
              <LinksTable incident={detail} selectedId={selectedId} onSelect={setSelection} />
            ) : null}
            {tab === "entities" ? (
              <EntitiesTable incident={detail} selectedId={selectedId} onSelect={setSelection} />
            ) : null}
            {tab === "notes" ? <Notes incidentId={incidentId} /> : null}
          </div>
        </Card>
        <div className="lg:sticky lg:top-4 lg:self-start">
          {evidence.isError ? (
            <Card className="p-4 text-sm text-danger">{errorMessage(evidence.error)}</Card>
          ) : (
            <Inspector
              selection={selection}
              events={evidence.data?.events ?? []}
              links={detail.links}
              canReadEvents={hasPermission(me, "event:read")}
              onClear={() => setSelection(null)}
            />
          )}
        </div>
      </div>
    </>
  );
}

export function IncidentPage({ incidentId }: { incidentId: string }) {
  return (
    <RequirePermission permission="incident:read">
      <Workspace incidentId={incidentId} />
    </RequirePermission>
  );
}
