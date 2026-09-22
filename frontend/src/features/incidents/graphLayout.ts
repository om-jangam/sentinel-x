import type { GraphEdge, GraphNode } from "@/api/types";

import type { Selection } from "./selection";

/** Left to right: where an attack usually starts to where it ends (matches the API's node order). */
const TYPE_ORDER = ["ip", "host", "user", "process", "file", "hash", "domain"];
export const NODE_W = 172;
export const NODE_H = 38;
const COL_GAP = 56;
const ROW_GAP = 14;
const PAD = 16;

export interface Placed {
  node: GraphNode;
  x: number;
  y: number;
}

/** Edges between the same two entities (e.g. a failed logon and a logon) are drawn as one line. */
export interface Connection {
  id: string;
  source: string;
  target: string;
  labels: string[];
  events: string[];
  eventCount: number;
  ports: number[];
}

export function connections(edges: GraphEdge[]): Connection[] {
  const byPair = new Map<string, Connection>();
  for (const edge of edges) {
    const id = `${edge.source}→${edge.target}`;
    const pair = byPair.get(id) ?? {
      id,
      source: edge.source,
      target: edge.target,
      labels: [],
      events: [],
      eventCount: 0,
      ports: [],
    };
    const ports = Array.isArray(edge.detail.ports) ? (edge.detail.ports as number[]) : [];
    const detail = ports.length ? `${edge.label} :${ports.join(",")}` : edge.label;
    pair.labels.push(`${detail} (${edge.event_count})`);
    pair.events = [...new Set([...pair.events, ...edge.events])];
    pair.eventCount += edge.event_count;
    pair.ports = [...new Set([...pair.ports, ...ports])];
    byPair.set(id, pair);
  }
  return [...byPair.values()];
}

export function layout(nodes: GraphNode[]): { placed: Map<string, Placed>; width: number; height: number } {
  const types = [...new Set(nodes.map((node) => node.type))].sort((a, b) => {
    const rank = (type: string) => (TYPE_ORDER.includes(type) ? TYPE_ORDER.indexOf(type) : TYPE_ORDER.length);
    return rank(a) - rank(b);
  });
  const columns = types.map((type) => nodes.filter((node) => node.type === type));
  const rows = Math.max(1, ...columns.map((column) => column.length));
  const placed = new Map<string, Placed>();
  columns.forEach((column, col) => {
    const offset = ((rows - column.length) * (NODE_H + ROW_GAP)) / 2;
    column.forEach((node, row) => {
      placed.set(node.key, {
        node,
        x: PAD + col * (NODE_W + COL_GAP),
        y: PAD + offset + row * (NODE_H + ROW_GAP),
      });
    });
  });
  return {
    placed,
    width: PAD * 2 + columns.length * (NODE_W + COL_GAP) - COL_GAP,
    height: PAD * 2 + rows * (NODE_H + ROW_GAP) - ROW_GAP,
  };
}

export function nodeSelection(node: GraphNode): Selection {
  return { id: `node:${node.key}`, label: `${node.type} ${node.value}`, events: node.events };
}

export function connectionSelection(connection: Connection, placed: Map<string, Placed>): Selection {
  const name = (key: string) => placed.get(key)?.node.value ?? key;
  return {
    id: `edge:${connection.id}`,
    label: `${name(connection.source)} → ${name(connection.target)}`,
    events: connection.events,
  };
}
