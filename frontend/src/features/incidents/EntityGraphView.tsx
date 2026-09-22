import type { KeyboardEvent } from "react";

import type { EntityGraph, GraphNode, IntelResult } from "@/api/types";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { cn } from "@/lib/utils";

import {
  connectionSelection,
  connections,
  layout,
  NODE_H,
  NODE_W,
  nodeSelection,
  type Placed,
} from "./graphLayout";
import type { Selection } from "./selection";

function path(from: Placed, to: Placed): string {
  const sy = from.y + NODE_H / 2;
  const ty = to.y + NODE_H / 2;
  if (to.x > from.x) {
    const sx = from.x + NODE_W;
    const mid = (sx + to.x) / 2;
    return `M ${sx} ${sy} C ${mid} ${sy}, ${mid} ${ty}, ${to.x} ${ty}`;
  }
  if (to.x === from.x) {
    // Same column (a process spawning a process): loop out to the right.
    const sx = from.x + NODE_W;
    return `M ${sx} ${sy} C ${sx + 48} ${sy}, ${sx + 48} ${ty}, ${sx} ${ty}`;
  }
  // Backwards (a domain resolving to an address further left): leave left, arrive on the right.
  const tx = to.x + NODE_W;
  const bend = Math.max(48, (from.x - tx) / 2);
  return `M ${from.x} ${sy} C ${from.x - bend} ${sy}, ${tx + bend} ${ty}, ${tx} ${ty}`;
}

function nodeTone(node: GraphNode): string {
  if (node.external) return "stroke-danger";
  if (node.type === "host") return "stroke-primary";
  if (node.type === "user") return "stroke-warning";
  if (node.type === "process") return "stroke-success";
  return "stroke-border";
}

function truncate(text: string, max = 22): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function activate(handler: () => void) {
  return (event: KeyboardEvent) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      handler();
    }
  };
}

const NO_INTEL = new Map<string, IntelResult>();

export function EntityGraphView({
  graph,
  intel = NO_INTEL,
  selectedId,
  onSelect,
}: {
  graph: EntityGraph;
  intel?: Map<string, IntelResult>;
  selectedId: string | null;
  onSelect: (selection: Selection) => void;
}) {
  if (graph.nodes.length === 0) {
    return <p className="p-4 text-sm text-muted">No relationships were recorded for this incident.</p>;
  }
  const { placed, width, height } = layout(graph.nodes);
  const links = connections(graph.edges).filter((c) => placed.has(c.source) && placed.has(c.target));

  return (
    <div>
      <div className="overflow-x-auto p-2">
        <svg
          role="group"
          aria-label="Entity graph"
          viewBox={`0 0 ${width} ${height}`}
          // Scale to the card, but never below a readable size: past that, scroll sideways instead.
          style={{ width: "100%", minWidth: Math.min(width, 760), maxWidth: width, height: "auto" }}
        >
          <defs>
            <marker
              id="arrow"
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="7"
              markerHeight="7"
              orient="auto"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" className="fill-muted" />
            </marker>
          </defs>
          {links.map((connection) => {
            const from = placed.get(connection.source);
            const to = placed.get(connection.target);
            if (!from || !to) return null;
            const selection = connectionSelection(connection, placed);
            const selected = selectedId === selection.id;
            return (
              <g
                key={connection.id}
                role="button"
                tabIndex={0}
                aria-label={`${selection.label}: ${connection.labels.join("; ")}`}
                aria-pressed={selected}
                className="cursor-pointer focus:outline-none"
                onClick={() => onSelect(selection)}
                onKeyDown={activate(() => onSelect(selection))}
              >
                <title>{`${selection.label}\n${connection.labels.join("\n")}`}</title>
                <path d={path(from, to)} className="fill-none stroke-transparent" strokeWidth={12} />
                <path
                  d={path(from, to)}
                  markerEnd="url(#arrow)"
                  className={cn("fill-none", selected ? "stroke-primary" : "stroke-muted/60")}
                  strokeWidth={selected ? 2.5 : 1.25 + Math.min(connection.eventCount, 6) * 0.25}
                />
              </g>
            );
          })}
          {[...placed.values()].map(({ node, x, y }) => {
            const selection = nodeSelection(node);
            const selected = selectedId === selection.id;
            const flag = intel.get(node.key);
            const flagged =
              flag && (flag.verdict === "malicious" || flag.verdict === "suspicious") ? flag : null;
            const events = `${node.event_count} event${node.event_count === 1 ? "" : "s"}`;
            return (
              <g
                key={node.key}
                role="button"
                tabIndex={0}
                aria-label={`${node.type} ${node.value}, ${events}${
                  flagged ? `, ${flagged.verdict} according to ${flagged.provider}` : ""
                }`}
                aria-pressed={selected}
                className="cursor-pointer focus:outline-none"
                transform={`translate(${x} ${y})`}
                onClick={() => onSelect(selection)}
                onKeyDown={activate(() => onSelect(selection))}
              >
                <title>{`${node.type}: ${node.value}`}</title>
                <rect
                  width={NODE_W}
                  height={NODE_H}
                  rx={6}
                  className={cn("fill-surface-raised", nodeTone(node), selected && "fill-primary/20")}
                  strokeWidth={selected ? 2.5 : 1.5}
                />
                <text x={10} y={14} className="fill-muted text-[10px] uppercase tracking-wide">
                  {node.external ? `${node.type} · external` : node.type}
                </text>
                <text x={10} y={29} className="fill-foreground font-mono text-[12px]">
                  {truncate(node.value)}
                </text>
                {flagged ? (
                  <circle
                    cx={NODE_W - 10}
                    cy={10}
                    r={4.5}
                    className={flagged.verdict === "malicious" ? "fill-danger" : "fill-warning"}
                  >
                    <title>{`${flagged.verdict} according to ${flagged.provider}`}</title>
                  </circle>
                ) : null}
              </g>
            );
          })}
        </svg>
      </div>
      <div className="border-t border-border">
        <Table aria-label="Relationships">
          <THead>
            <tr>
              <TH>From</TH>
              <TH>Relationship</TH>
              <TH>To</TH>
              <TH className="text-right">Events</TH>
            </tr>
          </THead>
          <TBody>
            {links.map((connection) => {
              const selection = connectionSelection(connection, placed);
              return (
                <TR
                  key={connection.id}
                  className={cn("cursor-pointer", selectedId === selection.id && "bg-primary/10")}
                  onClick={() => onSelect(selection)}
                >
                  <TD className="font-mono text-xs">{placed.get(connection.source)?.node.value}</TD>
                  <TD className="text-xs text-muted">{connection.labels.join("; ")}</TD>
                  <TD className="font-mono text-xs">{placed.get(connection.target)?.node.value}</TD>
                  <TD className="text-right tabular-nums">{connection.eventCount}</TD>
                </TR>
              );
            })}
          </TBody>
        </Table>
      </div>
    </div>
  );
}
