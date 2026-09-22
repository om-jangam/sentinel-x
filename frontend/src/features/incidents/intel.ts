import type { IntelResult } from "@/api/types";

type Tone = "neutral" | "primary" | "success" | "warning" | "danger";

export function verdictTone(verdict: string): Tone {
  if (verdict === "malicious") return "danger";
  if (verdict === "suspicious") return "warning";
  if (verdict === "benign") return "success";
  return "neutral";
}

const RANK: Record<string, number> = { malicious: 3, suspicious: 2, benign: 1, unknown: 0 };

/** The most severe thing any provider said about each indicator, for badges; the tab shows every answer. */
export function worstVerdicts(results: IntelResult[] | undefined): Map<string, IntelResult> {
  const worst = new Map<string, IntelResult>();
  for (const result of results ?? []) {
    if (result.status !== "found") continue;
    const current = worst.get(result.indicator);
    if (!current || (RANK[result.verdict] ?? 0) > (RANK[current.verdict] ?? 0))
      worst.set(result.indicator, result);
  }
  return worst;
}
