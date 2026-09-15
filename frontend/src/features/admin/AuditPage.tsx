import { ChevronDown, ChevronRight, ShieldCheck, ShieldX } from "lucide-react";
import { Fragment, useState } from "react";

import { errorMessage } from "@/api/errors";
import { type AuditFilters, useAuditLog, useAuditVerification } from "@/api/hooks";
import type { AuditEntry } from "@/api/types";
import { PageHeader, RequirePermission } from "@/components/RequirePermission";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input, Label, Select } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { formatDateTime } from "@/lib/utils";

function VerificationBanner() {
  const verification = useAuditVerification(true);
  const result = verification.data;

  return (
    <Card className="mb-4 flex flex-wrap items-center justify-between gap-3 p-4">
      {result ? (
        result.valid ? (
          <p className="flex items-center gap-2 text-sm">
            <ShieldCheck className="size-5 text-success" />
            Hash chain intact across {result.entries_checked} entries.
          </p>
        ) : (
          <p className="flex items-center gap-2 text-sm text-danger">
            <ShieldX className="size-5" />
            Integrity failure at entry #{result.broken_at_index}: {result.reason}
          </p>
        )
      ) : (
        <p className="text-sm text-muted">
          {verification.isError ? errorMessage(verification.error) : "Verifying chain…"}
        </p>
      )}
      <Button
        size="sm"
        variant="secondary"
        onClick={() => void verification.refetch()}
        disabled={verification.isFetching}
      >
        Re-verify
      </Button>
    </Card>
  );
}

function Json({ label, value }: { label: string; value: unknown }) {
  if (value === null || value === undefined) return null;
  return (
    <div>
      <p className="mb-1 text-xs font-medium uppercase tracking-wide text-muted">{label}</p>
      <pre className="overflow-x-auto rounded bg-background p-3 font-mono text-xs">
        {JSON.stringify(value, null, 2)}
      </pre>
    </div>
  );
}

function AuditRow({ entry }: { entry: AuditEntry }) {
  const [open, setOpen] = useState(false);
  return (
    <Fragment>
      <TR className="cursor-pointer" onClick={() => setOpen(!open)} aria-expanded={open}>
        <TD className="w-8 text-muted">
          {open ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}
        </TD>
        <TD className="font-mono text-muted">#{entry.chain_index}</TD>
        <TD className="whitespace-nowrap">{formatDateTime(entry.ts)}</TD>
        <TD>
          <code className="font-mono">{entry.action}</code>
        </TD>
        <TD>
          <Badge>{entry.resource_type}</Badge>{" "}
          <span className="font-mono text-xs text-muted">{entry.resource_id?.slice(0, 8)}</span>
        </TD>
        <TD>
          <Badge tone={entry.actor_type === "system" ? "warning" : "neutral"}>{entry.actor_type}</Badge>{" "}
          <span className="font-mono text-xs text-muted">{entry.actor_id?.slice(0, 8)}</span>
        </TD>
      </TR>
      {open ? (
        <tr>
          <td colSpan={6} className="bg-surface-raised/40 px-4 py-3">
            <div className="grid gap-3 lg:grid-cols-3">
              <Json label="Before" value={entry.before} />
              <Json label="After" value={entry.after} />
              <Json label="Context" value={entry.context} />
            </div>
            <p className="mt-3 font-mono text-xs text-muted">
              entry_hash {entry.entry_hash} · correlation {entry.correlation_id ?? "—"}
            </p>
          </td>
        </tr>
      ) : null}
    </Fragment>
  );
}

function AuditContent() {
  const [filters, setFilters] = useState<AuditFilters>({});
  const [draftAction, setDraftAction] = useState("");
  const log = useAuditLog(filters);
  const entries = log.data?.pages.flatMap((page) => page.items) ?? [];

  return (
    <>
      <VerificationBanner />
      <form
        className="mb-4 flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          setFilters({ ...filters, action: draftAction.trim() });
        }}
      >
        <div className="space-y-1.5">
          <Label htmlFor="audit-action">Action</Label>
          <Input
            id="audit-action"
            placeholder="e.g. auth.login_failed"
            className="w-64 font-mono"
            value={draftAction}
            onChange={(e) => setDraftAction(e.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="audit-resource">Resource</Label>
          <Select
            id="audit-resource"
            value={filters.resource_type ?? ""}
            onChange={(e) => setFilters({ ...filters, resource_type: e.currentTarget.value })}
          >
            <option value="">All</option>
            <option value="user">user</option>
            <option value="role">role</option>
            <option value="org">org</option>
          </Select>
        </div>
        <Button type="submit" variant="secondary">
          Apply
        </Button>
      </form>
      <Card>
        <Table>
          <THead>
            <tr>
              <TH />
              <TH>Index</TH>
              <TH>Time</TH>
              <TH>Action</TH>
              <TH>Resource</TH>
              <TH>Actor</TH>
            </tr>
          </THead>
          <TBody>
            {entries.map((entry) => (
              <AuditRow key={entry.id} entry={entry} />
            ))}
          </TBody>
        </Table>
        {log.isPending ? <p className="p-4 text-sm text-muted">Loading audit log…</p> : null}
        {log.isError ? <p className="p-4 text-sm text-danger">{errorMessage(log.error)}</p> : null}
        {!log.isPending && entries.length === 0 ? (
          <p className="p-4 text-sm text-muted">No matching entries.</p>
        ) : null}
        {log.hasNextPage ? (
          <div className="border-t border-border p-3 text-center">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => void log.fetchNextPage()}
              disabled={log.isFetchingNextPage}
            >
              Load older entries
            </Button>
          </div>
        ) : null}
      </Card>
    </>
  );
}

export function AuditPage() {
  return (
    <>
      <PageHeader
        title="Audit log"
        description="Append-only and tamper-evident. Every authentication, RBAC and configuration change is recorded."
      />
      <RequirePermission permission="audit:read">
        <AuditContent />
      </RequirePermission>
    </>
  );
}
