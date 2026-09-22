import type { TimelineStep } from "@/api/types";

/** What the analyst picked (a timeline step, graph node or edge, link or entity) and the events behind it. */
export interface Selection {
  id: string;
  label: string;
  events: string[];
}

export function stepSelection(step: TimelineStep): Selection {
  const count = step.events.length > 1 ? ` ×${step.events.length}` : "";
  return { id: `step:${step.id}`, label: `${step.action}${count}`, events: step.events };
}
