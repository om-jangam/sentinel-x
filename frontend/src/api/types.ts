import type { components } from "./schema";

type Schemas = components["schemas"];

export type Me = Schemas["MeResponse"];
export type UserRead = Schemas["UserRead"];
export type UserCreate = Schemas["UserCreate"];
export type UserUpdate = Schemas["UserUpdate"];
export type RoleRead = Schemas["RoleRead"];
export type RoleCreate = Schemas["RoleCreate"];
export type RoleUpdate = Schemas["RoleUpdate"];
export type PermissionRead = Schemas["PermissionRead"];
export type AuditEntry = Schemas["AuditEntryRead"];
export type AuditVerification = Schemas["AuditVerificationRead"];
export type HealthReport = Schemas["HealthReport"];
export type Incident = Schemas["IncidentRead"];
export type IncidentDetail = Schemas["IncidentDetailRead"];
export type IncidentLink = Schemas["IncidentLinkRead"];
export type IncidentEntity = Schemas["IncidentEntityRead"];
export type IncidentStatus = Incident["status"];
export type Resolution = NonNullable<Incident["resolution"]>;
export type TimelineStep = Schemas["TimelineStepRead"];
export type Timeline = Schemas["TimelineResponse"];
export type EntityGraph = Schemas["GraphResponse"];
export type GraphNode = Schemas["GraphNodeRead"];
export type GraphEdge = Schemas["GraphEdgeRead"];
export type EvidenceEvent = Schemas["EvidenceEventRead"];
export type Evidence = Schemas["EvidenceResponse"];
export type Note = Schemas["NoteRead"];

export type PermissionName =
  | "platform:read"
  | "audit:read"
  | "user:read"
  | "user:manage"
  | "role:read"
  | "role:manage"
  | "event:read"
  | "source:read"
  | "source:manage"
  | "ingest:write"
  | "finding:read"
  | "rule:read"
  | "incident:read"
  | "incident:update"
  | "incident:resolve";
