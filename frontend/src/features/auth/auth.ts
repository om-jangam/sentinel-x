import type { QueryClient } from "@tanstack/react-query";

import { api } from "@/api/client";
import { unwrap } from "@/api/errors";
import { fetchMe, queryKeys } from "@/api/hooks";
import type { Me, PermissionName } from "@/api/types";
import { refreshAccessToken, session } from "@/lib/session";

/** Restores a session from the refresh cookie if needed, then loads the current principal. */
export async function ensureSession(queryClient: QueryClient): Promise<Me | null> {
  if (!session.getToken() && !(await refreshAccessToken())) {
    return null;
  }
  try {
    return await queryClient.ensureQueryData({ queryKey: queryKeys.me, queryFn: fetchMe });
  } catch {
    return null;
  }
}

export async function login(queryClient: QueryClient, email: string, password: string): Promise<void> {
  const tokens = unwrap(await api.POST("/api/v1/auth/login", { body: { email, password } }));
  queryClient.clear();
  session.accept(tokens);
}

/**
 * Changes the signed-in user's own password. The server signs out every other session and issues this
 * browser a fresh one, so the new access token replaces the current one.
 */
export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  const tokens = unwrap(
    await api.POST("/api/v1/auth/password", {
      body: { current_password: currentPassword, new_password: newPassword },
    }),
  );
  session.accept(tokens);
}

export async function logout(queryClient: QueryClient): Promise<void> {
  try {
    await api.POST("/api/v1/auth/logout");
  } finally {
    session.clear();
    queryClient.clear();
  }
}

export function hasPermission(me: Me | undefined, permission: PermissionName): boolean {
  return me?.permissions.includes(permission) ?? false;
}

/** Only same-origin relative paths are honoured, preventing open redirects via ?redirect=. */
export function safeRedirect(target: unknown): string {
  return typeof target === "string" && target.startsWith("/") && !target.startsWith("//") ? target : "/";
}
