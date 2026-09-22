import { Database, X } from "lucide-react";
import { useState } from "react";

import { ApiError, errorMessage } from "@/api/errors";
import { useStoredEvent } from "@/api/hooks";
import type { EvidenceEvent, IncidentLink } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { formatDateTime } from "@/lib/utils";

import { entityValue, RULE_LABELS, shortUid } from "./format";
import type { Selection } from "./selection";

const ROLE_LABELS: Record<string, string> = {
  host: "Host",
  dst_host: "Destination host",
  user: "User",
  src_ip: "Source IP",
  dst_ip: "Destination IP",
  host_ip: "Host IP",
  process: "Process",
  parent_process: "Parent process",
  actor_process: "Logged by",
  file: "File",
  hash: "Hash",
  domain: "Domain",
  answer: "Resolved to",
};

function StoredEvent({ uid, canRead }: { uid: string; canRead: boolean }) {
  const [open, setOpen] = useState(false);
  const stored = useStoredEvent(uid, open && canRead);
  if (!canRead) return null;
  if (!open) {
    return (
      <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
        <Database /> Load stored event
      </Button>
    );
  }
  if (stored.isPending) return <p className="text-xs text-muted">Loading from the event store…</p>;
  if (stored.isError) {
    const unavailable = stored.error instanceof ApiError && stored.error.status === 503;
    return (
      <p className="text-xs text-warning">
        {unavailable
          ? "The event store is unavailable, so the stored event can't be shown. The digest above is what correlation recorded from it."
          : errorMessage(stored.error)}
      </p>
    );
  }
  return (
    <pre className="max-h-72 overflow-auto rounded bg-background p-2 font-mono text-[11px] leading-snug">
      {JSON.stringify(stored.data, null, 2)}
    </pre>
  );
}

function EventCard({
  event,
  links,
  canReadEvents,
}: {
  event: EvidenceEvent;
  links: Map<string, IncidentLink>;
  canReadEvents: boolean;
}) {
  return (
    <li className="space-y-2 rounded-md border border-border p-3 text-sm">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <span className="font-medium">
          {event.action}
          {event.outcome ? (
            <Badge className="ml-2" tone={event.outcome === "failure" ? "warning" : "success"}>
              {event.outcome}
            </Badge>
          ) : null}
        </span>
        <span className="font-mono text-xs text-muted">{formatDateTime(event.time)}</span>
      </div>
      <p className="font-mono text-[11px] text-muted" title={event.event_uid}>
        event_uid {event.event_uid}
      </p>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs">
        {Object.entries(event.roles).map(([role, keys]) => (
          <div key={role} className="contents">
            <dt className="text-muted">{ROLE_LABELS[role] ?? role}</dt>
            <dd className="break-all font-mono">{keys.map(entityValue).join(", ")}</dd>
          </div>
        ))}
        {typeof event.detail.dst_port === "number" ? (
          <>
            <dt className="text-muted">Port</dt>
            <dd className="font-mono">{String(event.detail.dst_port)}</dd>
          </>
        ) : null}
      </dl>
      {typeof event.detail.cmd_line === "string" ? (
        <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded bg-background p-2 font-mono text-[11px]">
          {event.detail.cmd_line}
        </pre>
      ) : null}
      {event.raw ? (
        <div>
          <p className="mb-1 text-xs text-muted">Original record (excerpt)</p>
          <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-background p-2 font-mono text-[11px]">
            {event.raw}
          </pre>
        </div>
      ) : event.message ? (
        <p className="text-xs text-muted">{event.message}</p>
      ) : null}
      <div className="flex flex-wrap gap-1.5">
        {event.cited_by.map((linkId) => {
          const link = links.get(linkId);
          const title =
            link?.kind === "finding"
              ? String(link.detail.rule_title ?? "Finding")
              : RULE_LABELS[link?.rule ?? ""];
          return (
            <Badge key={linkId} tone="primary" title={link?.reason}>
              {title ?? shortUid(linkId)}
            </Badge>
          );
        })}
      </div>
      <StoredEvent uid={event.event_uid} canRead={canReadEvents} />
    </li>
  );
}

export function Inspector({
  selection,
  events,
  links,
  canReadEvents,
  onClear,
}: {
  selection: Selection | null;
  events: EvidenceEvent[];
  links: IncidentLink[];
  canReadEvents: boolean;
  onClear: () => void;
}) {
  if (!selection) {
    return (
      <Card className="p-4 text-sm text-muted">
        Select a timeline step, a graph node or relationship, a link or an entity to see the stored events
        behind it.
      </Card>
    );
  }
  const byUid = new Map(events.map((event) => [event.event_uid, event]));
  const shown = selection.events
    .map((uid) => byUid.get(uid))
    .filter((e): e is EvidenceEvent => e !== undefined);
  const missing = selection.events.filter((uid) => !byUid.has(uid));
  const linkMap = new Map(links.map((link) => [link.id, link]));

  return (
    <Card aria-label="Evidence inspector" role="region">
      <div className="flex items-start justify-between gap-2 border-b border-border p-4">
        <div className="min-w-0">
          <p className="text-xs uppercase tracking-wide text-muted">Evidence</p>
          <p className="truncate font-medium" title={selection.label}>
            {selection.label}
          </p>
          <p className="text-xs text-muted">
            {selection.events.length} event{selection.events.length === 1 ? "" : "s"}
          </p>
        </div>
        <Button variant="ghost" size="icon" aria-label="Clear selection" onClick={onClear}>
          <X />
        </Button>
      </div>
      <ol className="max-h-[70vh] space-y-2 overflow-y-auto p-3">
        {shown.map((event) => (
          <EventCard key={event.event_uid} event={event} links={linkMap} canReadEvents={canReadEvents} />
        ))}
        {missing.map((uid) => (
          <li key={uid} className="rounded-md border border-dashed border-border p-3 text-xs text-muted">
            <span className="font-mono">event_uid {uid}</span>: cited, but correlation could not read this
            event when linking, so there is no digest.
            {canReadEvents ? " Load it from the event store:" : ""}
            <div className="mt-2">
              <StoredEvent uid={uid} canRead={canReadEvents} />
            </div>
          </li>
        ))}
      </ol>
    </Card>
  );
}
