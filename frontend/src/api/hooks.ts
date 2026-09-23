import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./client";
import { unwrap } from "./errors";
import type { IncidentStatus, Resolution, RoleCreate, RoleUpdate, UserCreate, UserUpdate } from "./types";

const PAGE_SIZE = 50;

export const queryKeys = {
  me: ["me"] as const,
  users: ["users"] as const,
  roles: ["roles"] as const,
  permissions: ["permissions"] as const,
  health: ["health"] as const,
  audit: (filters: AuditFilters) => ["audit", filters] as const,
  auditVerification: ["audit", "verification"] as const,
  incidents: (filters: IncidentFilters) => ["incidents", filters] as const,
  incident: (id: string) => ["incident", id] as const,
  incidentPart: (id: string, part: "timeline" | "graph" | "evidence" | "notes" | "novelty") =>
    ["incident", id, part] as const,
  event: (uid: string) => ["event", uid] as const,
  intelProviders: ["intel", "providers"] as const,
  assistant: ["assistant"] as const,
  analyses: (id: string) => ["incident", id, "analyses"] as const,
  intel: (keys: string[]) => ["intel", "results", keys] as const,
};

export async function fetchMe() {
  return unwrap(await api.GET("/api/v1/me"));
}

export function useMe() {
  return useQuery({ queryKey: queryKeys.me, queryFn: fetchMe });
}

export function useHealth(enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.health,
    queryFn: async () => unwrap(await api.GET("/api/v1/health")),
    enabled,
    refetchInterval: 30_000,
  });
}

// ------------------------------------------------------------------ users
export function useUsers() {
  return useInfiniteQuery({
    queryKey: queryKeys.users,
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) =>
      unwrap(await api.GET("/api/v1/users", { params: { query: { limit: PAGE_SIZE, cursor: pageParam } } })),
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  });
}

export function useCreateUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: UserCreate) => unwrap(await api.POST("/api/v1/users", { body })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.users }),
  });
}

export function useUpdateUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ userId, body }: { userId: string; body: UserUpdate }) =>
      unwrap(await api.PATCH("/api/v1/users/{user_id}", { params: { path: { user_id: userId } }, body })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.users }),
  });
}

export function useSetUserRoles() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ userId, roles }: { userId: string; roles: string[] }) =>
      unwrap(
        await api.PUT("/api/v1/users/{user_id}/roles", {
          params: { path: { user_id: userId } },
          body: { roles },
        }),
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.users });
      void queryClient.invalidateQueries({ queryKey: queryKeys.me });
    },
  });
}

// ------------------------------------------------------------------ roles
export function useRoles(enabled = true) {
  return useQuery({
    queryKey: queryKeys.roles,
    queryFn: async () => unwrap(await api.GET("/api/v1/roles")),
    enabled,
  });
}

export function usePermissions(enabled = true) {
  return useQuery({
    queryKey: queryKeys.permissions,
    queryFn: async () => unwrap(await api.GET("/api/v1/permissions")),
    enabled,
    staleTime: Infinity,
  });
}

export function useCreateRole() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: RoleCreate) => unwrap(await api.POST("/api/v1/roles", { body })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.roles }),
  });
}

export function useUpdateRole() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ roleId, body }: { roleId: string; body: RoleUpdate }) =>
      unwrap(await api.PATCH("/api/v1/roles/{role_id}", { params: { path: { role_id: roleId } }, body })),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.roles });
      void queryClient.invalidateQueries({ queryKey: queryKeys.me });
    },
  });
}

// ------------------------------------------------------------------ audit
export interface AuditFilters {
  action?: string;
  resource_type?: string;
}

export function useAuditLog(filters: AuditFilters) {
  return useInfiniteQuery({
    queryKey: queryKeys.audit(filters),
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) =>
      unwrap(
        await api.GET("/api/v1/audit", {
          params: {
            query: {
              limit: PAGE_SIZE,
              cursor: pageParam,
              action: filters.action || undefined,
              resource_type: filters.resource_type || undefined,
            },
          },
        }),
      ),
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  });
}

export function useAuditVerification(enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.auditVerification,
    queryFn: async () => unwrap(await api.GET("/api/v1/audit/verify")),
    enabled,
    staleTime: 0,
  });
}

// ------------------------------------------------------------------ incidents
export interface IncidentFilters {
  status?: IncidentStatus;
  severity_min?: number;
}

export function useIncidents(filters: IncidentFilters) {
  return useInfiniteQuery({
    queryKey: queryKeys.incidents(filters),
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) =>
      unwrap(
        await api.GET("/api/v1/incidents", {
          params: {
            query: {
              limit: PAGE_SIZE,
              cursor: pageParam,
              status: filters.status,
              severity_min: filters.severity_min,
            },
          },
        }),
      ),
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  });
}

const incidentPath = (id: string) => ({ params: { path: { incident_id: id } } });

export function useIncident(id: string) {
  return useQuery({
    queryKey: queryKeys.incident(id),
    queryFn: async () => unwrap(await api.GET("/api/v1/incidents/{incident_id}", incidentPath(id))),
  });
}

/** What the organisation had seen before of what this incident involves: context, never detection. */
export function useIncidentNovelty(id: string) {
  return useQuery({
    queryKey: queryKeys.incidentPart(id, "novelty"),
    queryFn: async () => unwrap(await api.GET("/api/v1/incidents/{incident_id}/novelty", incidentPath(id))),
  });
}

export function useIncidentTimeline(id: string) {
  return useQuery({
    queryKey: queryKeys.incidentPart(id, "timeline"),
    queryFn: async () => unwrap(await api.GET("/api/v1/incidents/{incident_id}/timeline", incidentPath(id))),
  });
}

export function useIncidentGraph(id: string) {
  return useQuery({
    queryKey: queryKeys.incidentPart(id, "graph"),
    queryFn: async () => unwrap(await api.GET("/api/v1/incidents/{incident_id}/graph", incidentPath(id))),
  });
}

export function useIncidentEvidence(id: string) {
  return useQuery({
    queryKey: queryKeys.incidentPart(id, "evidence"),
    queryFn: async () => unwrap(await api.GET("/api/v1/incidents/{incident_id}/evidence", incidentPath(id))),
  });
}

export function useIncidentNotes(id: string) {
  return useQuery({
    queryKey: queryKeys.incidentPart(id, "notes"),
    queryFn: async () => unwrap(await api.GET("/api/v1/incidents/{incident_id}/notes", incidentPath(id))),
  });
}

export function useAddNote(id: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: string) =>
      unwrap(
        await api.POST("/api/v1/incidents/{incident_id}/notes", { ...incidentPath(id), body: { body } }),
      ),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.incidentPart(id, "notes") }),
  });
}

export function useChangeIncidentStatus(id: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: { status: IncidentStatus; resolution?: Resolution; version: number }) =>
      unwrap(await api.PATCH("/api/v1/incidents/{incident_id}", { ...incidentPath(id), body })),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.incident(id) });
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
    },
  });
}

/** The stored event itself, from the event store: the final hop from a step or edge to raw evidence. */
export function useStoredEvent(uid: string | null, enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.event(uid ?? ""),
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/events/{event_uid}", { params: { path: { event_uid: uid ?? "" } } })),
    enabled: enabled && uid !== null,
    retry: false,
  });
}

// ------------------------------------------------------------------ threat intelligence
export function useIntelProviders(enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.intelProviders,
    queryFn: async () => unwrap(await api.GET("/api/v1/intel/providers")),
    enabled,
    staleTime: 5 * 60_000,
  });
}

/** Cached answers only: reading never makes Sentinel-X contact a provider. */
export function useIntel(keys: string[], enabled: boolean) {
  const sorted = [...new Set(keys)].sort();
  return useQuery({
    queryKey: queryKeys.intel(sorted),
    queryFn: async () => unwrap(await api.POST("/api/v1/intel/lookup", { body: { indicators: sorted } })),
    enabled: enabled && sorted.length > 0,
  });
}

// ------------------------------------------------------------------ AI assistant
export function useAssistantStatus() {
  return useQuery({
    queryKey: queryKeys.assistant,
    queryFn: async () => unwrap(await api.GET("/api/v1/assistant")),
    staleTime: 60_000,
  });
}

export function useAnalyses(id: string) {
  return useQuery({
    queryKey: queryKeys.analyses(id),
    queryFn: async () => unwrap(await api.GET("/api/v1/incidents/{incident_id}/analyses", incidentPath(id))),
  });
}

/** Can take minutes with a local model; the result is recorded whatever it is. */
export function useRequestAnalysis(id: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () =>
      unwrap(await api.POST("/api/v1/incidents/{incident_id}/analyses", incidentPath(id))),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.analyses(id) }),
  });
}
