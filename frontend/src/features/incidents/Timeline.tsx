import { Fragment, type ReactNode } from "react";

import type { TimelineStep } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

import { formatDay, formatSpan, RULE_LABELS } from "./format";
import { type Selection, stepSelection } from "./selection";

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <span className="whitespace-nowrap">
      <span className="text-muted">{label} </span>
      {children}
    </span>
  );
}

function StepRow({
  step,
  selected,
  onSelect,
}: {
  step: TimelineStep;
  selected: boolean;
  onSelect: (selection: Selection) => void;
}) {
  const dot =
    step.outcome === "failure" ? "bg-warning" : step.outcome === "success" ? "bg-success" : "bg-muted";
  const isLogon = step.action === "Logged on" || step.action === "Failed logon";
  return (
    <button
      type="button"
      aria-pressed={selected}
      onClick={() => onSelect(stepSelection(step))}
      className={cn(
        "flex w-full gap-3 rounded-md border px-3 py-2.5 text-left text-sm transition-colors",
        selected ? "border-primary bg-primary/10" : "border-transparent hover:bg-surface-raised",
      )}
    >
      <span aria-hidden className={cn("mt-1.5 size-2.5 shrink-0 rounded-full", dot)} />
      <span className="min-w-0 flex-1 space-y-1">
        <span className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <span className="font-mono text-xs text-muted tabular-nums">
            {formatSpan(step.first_seen, step.last_seen)}
          </span>
          <span className="font-medium">{step.action}</span>
          {step.events.length > 1 ? <Badge>×{step.events.length}</Badge> : null}
        </span>
        <span className="flex flex-wrap gap-x-4 gap-y-0.5 text-xs">
          {step.host ? <Fact label="host">{step.host}</Fact> : null}
          {step.users.length ? <Fact label="user">{step.users.join(", ")}</Fact> : null}
          {step.process ? (
            <Fact label="process">
              {step.parent_process ? `${step.parent_process} → ` : ""}
              {step.process}
            </Fact>
          ) : null}
          {step.remote ? (
            <Fact label={isLogon ? "from" : "to"}>
              {step.remote}
              {step.remote_ports.length ? `:${step.remote_ports.join(",")}` : ""}
            </Fact>
          ) : null}
          {step.domains.length ? <Fact label="domain">{step.domains.join(", ")}</Fact> : null}
        </span>
        {step.command_lines.map((command) => (
          <code key={command} className="block truncate rounded bg-background px-2 py-1 font-mono text-xs">
            {command}
          </code>
        ))}
        <span className="flex flex-wrap gap-1.5">
          {step.citations.map((citation) =>
            citation.rule === "auth-success-after-failures" ? (
              <Badge key={citation.link_id} tone="danger">
                {RULE_LABELS[citation.rule]}
              </Badge>
            ) : (
              <Badge key={citation.link_id} tone="primary">
                {citation.title}
                {citation.techniques.length ? ` · ${citation.techniques.join(", ")}` : ""}
              </Badge>
            ),
          )}
        </span>
      </span>
    </button>
  );
}

export function Timeline({
  steps,
  unresolved,
  selectedId,
  onSelect,
}: {
  steps: TimelineStep[];
  unresolved: string[];
  selectedId: string | null;
  onSelect: (selection: Selection) => void;
}) {
  if (steps.length === 0 && unresolved.length === 0) {
    return <p className="p-4 text-sm text-muted">No evidence digests were recorded for this incident.</p>;
  }
  const days = steps.map((step) => formatDay(step.first_seen));
  return (
    <div className="p-2">
      <ol className="space-y-1" aria-label="Attack timeline">
        {steps.map((step, index) => (
          <Fragment key={step.id}>
            {index === 0 || days[index] !== days[index - 1] ? (
              <li aria-hidden className="px-3 pb-1 pt-2 text-xs font-medium uppercase text-muted">
                {days[index]}
              </li>
            ) : null}
            <li>
              <StepRow step={step} selected={selectedId === `step:${step.id}`} onSelect={onSelect} />
            </li>
          </Fragment>
        ))}
      </ol>
      {unresolved.length ? (
        <p role="note" className="px-3 pt-3 text-xs text-warning">
          {unresolved.length} cited event{unresolved.length === 1 ? " is" : "s are"} missing from the
          timeline: correlation could not read {unresolved.length === 1 ? "it" : "them"} from the event store
          when linking. The Findings &amp; links tab still lists every cited event ID.
        </p>
      ) : null}
    </div>
  );
}
