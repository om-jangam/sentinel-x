import type { IncidentStatus, Resolution } from "@/api/types";

type Tone = "neutral" | "primary" | "success" | "warning" | "danger";

export function severityTone(severityId: number): Tone {
  if (severityId >= 4) return "danger";
  if (severityId === 3) return "warning";
  if (severityId === 2) return "primary";
  return "neutral";
}

export const STATUS_LABELS: Record<IncidentStatus, string> = {
  new: "New",
  investigating: "Investigating",
  closed: "Closed",
};

export function statusTone(status: IncidentStatus): Tone {
  return status === "new" ? "warning" : status === "investigating" ? "primary" : "neutral";
}

export const RESOLUTION_LABELS: Record<Resolution, string> = {
  true_positive: "True positive",
  benign_positive: "Benign positive",
  false_positive: "False positive",
};

export const RULE_LABELS: Record<string, string> = {
  opened: "Opened the incident",
  "shared-entity": "Shared entity",
  "auth-success-after-failures": "Logon after failures",
};

const time = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const day = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });

export function formatTime(value: string): string {
  return time.format(new Date(value));
}

export function formatDay(value: string): string {
  return day.format(new Date(value));
}

/** "09:40:11" or "09:40:11 – 09:40:21" */
export function formatSpan(first: string, last: string): string {
  return first === last ? formatTime(first) : `${formatTime(first)} – ${formatTime(last)}`;
}

/** `ip:203.0.113.45` → `203.0.113.45` */
export function entityValue(key: string): string {
  const index = key.indexOf(":");
  return index === -1 ? key : key.slice(index + 1);
}

export function entityType(key: string): string {
  const index = key.indexOf(":");
  return index === -1 ? "" : key.slice(0, index);
}

export function shortUid(uid: string): string {
  return uid.slice(0, 8);
}
