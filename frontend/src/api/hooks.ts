import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./client";
import { unwrap } from "./errors";
import type { RoleCreate, RoleUpdate, UserCreate, UserUpdate } from "./types";

const PAGE_SIZE = 50;

export const queryKeys = {
  me: ["me"] as const,
  users: ["users"] as const,
  roles: ["roles"] as const,
  permissions: ["permissions"] as const,
  health: ["health"] as const,
  audit: (filters: AuditFilters) => ["audit", filters] as const,
  auditVerification: ["audit", "verification"] as const,
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
