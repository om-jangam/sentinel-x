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

export type SourceRead = Schemas["SourceRead"];
export type SourceCreate = Schemas["SourceCreate"];
export type SourceWithToken = Schemas["SourceWithToken"];
export type SourceHealth = SourceRead["health"];
export type ParserRead = Schemas["ParserRead"];
export type EventSearchRequest = Schemas["EventSearchRequest"];
export type EventPage = Schemas["EventPageResponse"];

/** The event store returns whole OCSF documents; only the fields the console reads are named. */
export interface SecurityEvent {
  "@timestamp": string;
  time: number;
  class_uid: number;
  class_name?: string;
  activity_name?: string;
  category_name?: string;
  severity_id: number;
  severity?: string;
  status_id?: number;
  status?: string;
  message?: string;
  metadata?: { product?: { name?: string; vendor_name?: string }; log_name?: string };
  user?: { name?: string; domain?: string };
  actor?: { user?: { name?: string }; process?: { name?: string } };
  device?: { hostname?: string; ip?: string };
  src_endpoint?: { ip?: string; port?: number; hostname?: string };
  dst_endpoint?: { ip?: string; port?: number; hostname?: string };
  process?: { name?: string; pid?: number; cmd_line?: string };
  query?: { hostname?: string; type?: string };
  raw_data?: string;
  observables?: { name: string; type_id: number; value: string }[];
  sx: { org_id: string; source_id: string; event_uid: string; ingested_at: string; fingerprint: string };
  [key: string]: unknown;
}

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
  | "ingest:write";
