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
