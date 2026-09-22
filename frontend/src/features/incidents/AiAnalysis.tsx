import { ChevronDown, ChevronRight, Sparkles } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { errorMessage } from "@/api/errors";
import { useAnalyses, useAssistantStatus, useMe, useRequestAnalysis } from "@/api/hooks";
import type { Analysis } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { hasPermission } from "@/features/auth/auth";
import { formatDateTime } from "@/lib/utils";

import { shortUid } from "./format";
import type { Selection } from "./selection";

interface Statement {
  kind: "FACT" | "INFERENCE" | "UNCERTAINTY";
  text: string;
  evidence?: string[];
  reasoning?: string;
  confidence?: string;
  missing?: string;
}

interface Technique {
  technique_id: string;
  evidence: string[];
  kind: string;
}

interface Output {
  summary: string | null;
  statements: Statement[];
  techniques: Technique[];
  next_steps: string[];
}

const KIND_TONE = { FACT: "success", INFERENCE: "primary", UNCERTAINTY: "warning" } as const;

function Citations({
  events,
  label,
  onSelect,
}: {
  events: string[];
  label: string;
  onSelect: (selection: Selection) => void;
}) {
  if (!events.length) return null;
  return (
    <button
      type="button"
      className="text-xs text-primary hover:underline"
      onClick={() => onSelect({ id: `analysis:${label}:${events.join(",")}`, label, events })}
    >
      {events.length === 1 ? `1 cited event (${shortUid(events[0] ?? "")})` : `${events.length} cited events`}
    </button>
  );
}

function AnalysisView({
  analysis,
  onSelect,
}: {
  analysis: Analysis;
  onSelect: (selection: Selection) => void;
}) {
  const [showDropped, setShowDropped] = useState(false);
  const output = analysis.output as Output | null;

  return (
    <article aria-label="AI analysis" className="space-y-4">
      <p className="text-xs text-muted">
        {analysis.provider}/{analysis.model} · {analysis.prompt_version} · evidence{" "}
        {analysis.bundle_hash.slice(0, 12)} · {formatDateTime(analysis.created_at)} ·{" "}
        {(analysis.duration_ms / 1000).toFixed(1)} s
        {analysis.citation_validity !== null
          ? ` · ${Math.round(analysis.citation_validity * 100)}% of citations valid`
          : ""}
      </p>
      {analysis.status !== "completed" ? (
        <p role="alert" className="rounded-md border border-warning/40 bg-warning/10 p-3 text-sm">
          {analysis.status === "unavailable" ? "AI analysis unavailable: " : "AI analysis rejected: "}
          {analysis.reason}. Nothing was guessed; the rest of the workspace is unaffected.
        </p>
      ) : null}
      {output?.summary ? (
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-muted">
            Summary, in the assistant&apos;s words
          </p>
          <p className="mt-1 text-sm">{output.summary}</p>
        </div>
      ) : null}
      {output ? (
        <ol className="space-y-2" aria-label="Statements">
          {output.statements.map((statement, index) => (
            <li key={index} className="space-y-1 rounded-md border border-border p-3 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <Badge tone={KIND_TONE[statement.kind]}>{statement.kind}</Badge>
                {statement.confidence ? (
                  <span className="text-xs text-muted">{statement.confidence} confidence</span>
                ) : null}
              </div>
              <p>{statement.text}</p>
              {statement.reasoning ? (
                <p className="text-xs text-muted">Reasoning: {statement.reasoning}</p>
              ) : null}
              {statement.missing ? (
                <p className="text-xs text-muted">Would resolve it: {statement.missing}</p>
              ) : null}
              <Citations
                events={statement.evidence ?? []}
                label={`${statement.kind}: ${statement.text}`}
                onSelect={onSelect}
              />
            </li>
          ))}
        </ol>
      ) : null}
      {output?.techniques.length ? (
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-muted">Techniques that may apply</p>
          <ul className="mt-1 flex flex-wrap gap-2">
            {output.techniques.map((technique) => (
              <li key={technique.technique_id} className="flex items-center gap-1.5">
                <Badge tone="primary" className="font-mono">
                  {technique.technique_id}
                </Badge>
                <Citations events={technique.evidence} label={technique.technique_id} onSelect={onSelect} />
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {output?.next_steps.length ? (
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-muted">
            Suggested next steps (for the analyst; the assistant cannot run anything)
          </p>
          <ul className="mt-1 list-disc space-y-0.5 pl-5 text-sm">
            {output.next_steps.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {analysis.dropped.length ? (
        <div className="text-sm">
          <button
            type="button"
            className="inline-flex items-center gap-1 text-muted hover:text-foreground"
            aria-expanded={showDropped}
            onClick={() => setShowDropped(!showDropped)}
          >
            {showDropped ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}
            {analysis.dropped.length} item{analysis.dropped.length === 1 ? " was" : "s were"} removed by
            validation
          </button>
          {showDropped ? (
            <ul className="mt-2 space-y-1 text-xs">
              {analysis.dropped.map((item, index) => (
                <li key={index} className="rounded bg-background p-2">
                  <span className="text-warning">{String(item.reason)}</span>
                  <pre className="mt-1 whitespace-pre-wrap break-all font-mono text-muted">
                    {JSON.stringify(item.item)}
                  </pre>
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}
    </article>
  );
}

export function AiAnalysis({
  incidentId,
  onSelect,
}: {
  incidentId: string;
  onSelect: (selection: Selection) => void;
}) {
  const { data: me } = useMe();
  const status = useAssistantStatus();
  const analyses = useAnalyses(incidentId);
  const request = useRequestAnalysis(incidentId);
  const [chosen, setChosen] = useState<string | null>(null);
  const history = analyses.data ?? [];
  const shown = history.find((analysis) => analysis.id === chosen) ?? history[0];
  const canAsk = hasPermission(me, "assistant:use") && status.data?.enabled;

  return (
    <div className="space-y-4 p-4">
      <p className="text-xs text-muted">
        The assistant explains what the evidence shows; it never detects, decides or acts. It sees only this
        incident&apos;s evidence, and every statement it keeps is labelled FACT, INFERENCE or UNCERTAINTY and
        cites stored events. Statements citing anything else are removed before you see them.
      </p>
      <div className="flex flex-wrap items-center gap-3">
        {canAsk ? (
          <Button
            disabled={request.isPending}
            onClick={() =>
              request.mutate(undefined, {
                onSuccess: (analysis) => setChosen(analysis.id),
                onError: (error) => toast.error(errorMessage(error)),
              })
            }
          >
            <Sparkles /> {request.isPending ? "Analysing…" : "Analyse with AI"}
          </Button>
        ) : null}
        {status.data && !status.data.enabled ? (
          <p className="text-sm text-muted">
            The AI assistant is not configured (<code className="font-mono">SENTINELX_AI_PROVIDER</code>).
            Everything else in the workspace works without it.
          </p>
        ) : null}
        {status.data?.enabled ? (
          <span className="text-xs text-muted">
            {status.data.provider}/{status.data.model}
          </span>
        ) : null}
      </div>
      {request.isPending ? (
        <p className="text-sm text-muted">
          A local model can take a few minutes. The result is recorded either way.
        </p>
      ) : null}
      {analyses.isError ? <p className="text-sm text-danger">{errorMessage(analyses.error)}</p> : null}
      {shown ? <AnalysisView analysis={shown} onSelect={onSelect} /> : null}
      {!shown && analyses.data ? (
        <p className="text-sm text-muted">No analysis has been requested yet.</p>
      ) : null}
      {history.length > 1 ? (
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-muted">Earlier analyses</p>
          <ul className="mt-1 space-y-0.5 text-xs">
            {history.map((analysis) => (
              <li key={analysis.id}>
                <button
                  type="button"
                  className={analysis.id === shown?.id ? "text-foreground" : "text-primary hover:underline"}
                  onClick={() => setChosen(analysis.id)}
                >
                  {formatDateTime(analysis.created_at)} · {analysis.status} · {analysis.model}
                </button>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
