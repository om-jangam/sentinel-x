import { api } from "@/api/client";
import { unwrap } from "@/api/errors";

/** The two formats MITRE's own tools read: a Navigator layer and a STIX Attack Flow bundle. */
export const EXPORTS = {
  "attack-navigator": {
    label: "ATT&CK Navigator layer",
    hint: "Opens in mitre-attack.github.io/attack-navigator",
    suffix: "attack-navigator-layer",
  },
  "attack-flow": {
    label: "Attack Flow (STIX 2.1)",
    hint: "Opens in the CTID Attack Flow builder",
    suffix: "attack-flow",
  },
  report: {
    label: "Incident report",
    hint: "Markdown: timeline, findings, entities and notes, every line citing its events",
    suffix: "report",
  },
} as const;

export type ExportKind = keyof typeof EXPORTS;

function fileName(incidentId: string, kind: ExportKind): string {
  const extension = kind === "report" ? "md" : "json";
  return `sentinel-x-${incidentId.slice(0, 8)}-${EXPORTS[kind].suffix}.${extension}`;
}

/** Saves the export as a file. The document is built by the API; nothing is assembled in the browser. */
export async function downloadExport(incidentId: string, kind: ExportKind): Promise<string> {
  const params = { params: { path: { incident_id: incidentId } } };
  let blob: Blob;
  if (kind === "report") {
    const markdown = unwrap(
      await api.GET("/api/v1/incidents/{incident_id}/exports/report.md", {
        ...params,
        parseAs: "text",
      }),
    );
    blob = new Blob([markdown as string], { type: "text/markdown" });
  } else {
    const path =
      kind === "attack-navigator"
        ? "/api/v1/incidents/{incident_id}/exports/attack-navigator"
        : "/api/v1/incidents/{incident_id}/exports/attack-flow";
    blob = new Blob([JSON.stringify(unwrap(await api.GET(path, params)), null, 2)], {
      type: "application/json",
    });
  }
  const url = URL.createObjectURL(blob);
  const name = fileName(incidentId, kind);
  try {
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = name;
    anchor.click();
  } finally {
    URL.revokeObjectURL(url);
  }
  return name;
}
