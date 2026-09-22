import { ExternalLink } from "lucide-react";

import { errorMessage } from "@/api/errors";
import type { IntelProvider, IntelResult } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { formatDateTime } from "@/lib/utils";

import { verdictTone } from "./intel";
import type { Selection } from "./selection";

function ResultCard({ result }: { result: IntelResult }) {
  return (
    <li className="space-y-1.5 rounded-md border border-border p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={verdictTone(result.verdict)}>{result.verdict}</Badge>
        {result.confidence !== null ? (
          <span className="text-xs text-muted">confidence {result.confidence}</span>
        ) : null}
        <span className="text-xs text-muted">
          {result.provider} · asked {formatDateTime(result.retrieved_at)}
        </span>
      </div>
      <p>{result.summary}</p>
      {result.status === "error" ? (
        <p className="text-xs text-warning">
          The provider could not be reached ({result.error}); it will be asked again.
        </p>
      ) : null}
      {result.tags.length ? (
        <div className="flex flex-wrap gap-1">
          {result.tags.map((tag) => (
            <Badge key={tag}>{tag}</Badge>
          ))}
        </div>
      ) : null}
      {result.related.length ? (
        <div className="text-xs">
          <p className="text-muted">Related, according to {result.provider}:</p>
          <ul className="mt-0.5 space-y-0.5">
            {result.related.map((related) => (
              <li key={`${related.type}:${related.value}:${related.relation}`}>
                <span className="text-muted">{related.relation}</span>{" "}
                <span className="font-mono">{related.value}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {result.references.length ? (
        <ul className="space-y-0.5 text-xs">
          {result.references.map((reference) => (
            <li key={reference}>
              {reference.startsWith("https://") ? (
                <a
                  href={reference}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-primary hover:underline"
                >
                  <ExternalLink className="size-3" />
                  {reference}
                </a>
              ) : (
                <span className="font-mono">{reference}</span>
              )}
            </li>
          ))}
        </ul>
      ) : null}
    </li>
  );
}

export function ThreatIntel({
  providers,
  results,
  error,
  entityEvents,
  onSelect,
}: {
  providers: IntelProvider[] | undefined;
  results: IntelResult[] | undefined;
  error: unknown;
  entityEvents: Map<string, string[]>;
  onSelect: (selection: Selection) => void;
}) {
  if (error) return <p className="p-4 text-sm text-danger">{errorMessage(error)}</p>;
  if (providers && providers.length === 0) {
    return (
      <p className="p-4 text-sm text-muted">
        No threat-intelligence providers are configured, so this incident&apos;s indicators have not been
        looked up. Set <code className="font-mono">SENTINELX_TI_LOCAL_FEED</code> or{" "}
        <code className="font-mono">SENTINELX_OTX_API_KEY</code> to enable one.
      </p>
    );
  }
  const answered = (results ?? []).filter((result) => result.status !== "not_found");
  const byIndicator = new Map<string, IntelResult[]>();
  for (const result of answered) {
    byIndicator.set(result.indicator, [...(byIndicator.get(result.indicator) ?? []), result]);
  }
  const asked = new Set((results ?? []).map((result) => result.indicator));

  return (
    <div className="space-y-4 p-4">
      <p className="text-xs text-muted">
        What each provider said about this incident&apos;s external addresses, domains and hashes, and when it
        was asked. This is context from named sources, not evidence: providers are never merged into one
        verdict. Hosts, users and internal addresses are never sent to a provider.
      </p>
      {providers ? (
        <p className="text-xs text-muted">
          Providers: {providers.map((provider) => provider.title).join(", ")}
        </p>
      ) : null}
      {[...byIndicator.entries()].map(([indicator, found]) => (
        <section key={indicator} aria-label={`Intel for ${indicator}`} className="space-y-2">
          <button
            type="button"
            className="font-mono text-sm font-medium hover:text-primary"
            onClick={() =>
              onSelect({
                id: `entity:${indicator}`,
                label: indicator,
                events: entityEvents.get(indicator) ?? [],
              })
            }
          >
            {indicator}
          </button>
          <ul className="space-y-2">
            {found.map((result) => (
              <ResultCard key={`${result.provider}:${result.indicator}`} result={result} />
            ))}
          </ul>
        </section>
      ))}
      {results && byIndicator.size === 0 ? (
        <p className="text-sm text-muted">
          {asked.size
            ? `No provider knows anything about the ${asked.size} indicator${asked.size === 1 ? "" : "s"} it was asked about.`
            : "No indicator of this incident has been looked up yet."}
        </p>
      ) : null}
    </div>
  );
}
