import { Link } from "@tanstack/react-router";
import { useState } from "react";

import { errorMessage } from "@/api/errors";
import { type IncidentFilters, useIncidents } from "@/api/hooks";
import type { IncidentStatus } from "@/api/types";
import { PageHeader, RequirePermission } from "@/components/RequirePermission";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Label, Select } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { formatDateTime } from "@/lib/utils";

import { STATUS_LABELS, severityTone, statusTone } from "./format";

function IncidentsContent() {
  const [filters, setFilters] = useState<IncidentFilters>({});
  const incidents = useIncidents(filters);
  const items = incidents.data?.pages.flatMap((page) => page.items) ?? [];

  return (
    <>
      <div className="mb-4 flex flex-wrap items-end gap-3">
        <div className="space-y-1.5">
          <Label htmlFor="incident-status">Status</Label>
          <Select
            id="incident-status"
            value={filters.status ?? ""}
            onChange={(e) =>
              setFilters({
                ...filters,
                status: (e.currentTarget.value || undefined) as IncidentStatus | undefined,
              })
            }
          >
            <option value="">All</option>
            <option value="new">New</option>
            <option value="investigating">Investigating</option>
            <option value="closed">Closed</option>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="incident-severity">Minimum severity</Label>
          <Select
            id="incident-severity"
            value={filters.severity_min ?? ""}
            onChange={(e) =>
              setFilters({
                ...filters,
                severity_min: e.currentTarget.value ? Number(e.currentTarget.value) : undefined,
              })
            }
          >
            <option value="">Any</option>
            <option value="3">Medium and above</option>
            <option value="4">High and above</option>
            <option value="5">Critical</option>
          </Select>
        </div>
      </div>
      <Card>
        <Table>
          <THead>
            <tr>
              <TH>Severity</TH>
              <TH>Incident</TH>
              <TH>Status</TH>
              <TH className="text-right">Findings</TH>
              <TH className="text-right">Events</TH>
              <TH>Last activity</TH>
            </tr>
          </THead>
          <TBody>
            {items.map((incident) => (
              <TR key={incident.id}>
                <TD>
                  <Badge tone={severityTone(incident.severity_id)}>{incident.severity}</Badge>
                </TD>
                <TD className="min-w-72">
                  <Link
                    to="/incidents/$incidentId"
                    params={{ incidentId: incident.id }}
                    className="font-medium hover:text-primary hover:underline"
                  >
                    {incident.title}
                  </Link>
                  <p className="mt-0.5 font-mono text-xs text-muted">{incident.techniques.join(" · ")}</p>
                </TD>
                <TD>
                  <Badge tone={statusTone(incident.status)}>{STATUS_LABELS[incident.status]}</Badge>
                </TD>
                <TD className="text-right tabular-nums">{incident.finding_count}</TD>
                <TD className="text-right tabular-nums">{incident.event_count}</TD>
                <TD className="whitespace-nowrap text-muted">{formatDateTime(incident.last_seen)}</TD>
              </TR>
            ))}
          </TBody>
        </Table>
        {incidents.isPending ? <p className="p-4 text-sm text-muted">Loading incidents…</p> : null}
        {incidents.isError ? (
          <p className="p-4 text-sm text-danger">{errorMessage(incidents.error)}</p>
        ) : null}
        {!incidents.isPending && !incidents.isError && items.length === 0 ? (
          <p className="p-4 text-sm text-muted">
            No incidents match. Incidents open when correlation joins detection findings.
          </p>
        ) : null}
        {incidents.hasNextPage ? (
          <div className="border-t border-border p-3 text-center">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => void incidents.fetchNextPage()}
              disabled={incidents.isFetchingNextPage}
            >
              Load more
            </Button>
          </div>
        ) : null}
      </Card>
    </>
  );
}

export function IncidentsPage() {
  return (
    <>
      <PageHeader
        title="Incidents"
        description="Findings and events joined by correlation. Every link cites the events behind it."
      />
      <RequirePermission permission="incident:read">
        <IncidentsContent />
      </RequirePermission>
    </>
  );
}
