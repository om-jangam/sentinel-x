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
} as const;

export type ExportKind = keyof typeof EXPORTS;

function fileName(incidentId: string, kind: ExportKind): string {
  return `sentinel-x-${incidentId.slice(0, 8)}-${EXPORTS[kind].suffix}.json`;
}

/** Saves the export as a file. The document is built by the API; nothing is assembled in the browser. */
export async function downloadExport(incidentId: string, kind: ExportKind): Promise<string> {
  const path =
    kind === "attack-navigator"
      ? "/api/v1/incidents/{incident_id}/exports/attack-navigator"
      : "/api/v1/incidents/{incident_id}/exports/attack-flow";
  const document_ = unwrap(await api.GET(path, { params: { path: { incident_id: incidentId } } }));
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(document_, null, 2)], { type: "application/json" }),
  );
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
