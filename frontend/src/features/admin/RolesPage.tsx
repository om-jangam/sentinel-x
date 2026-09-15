import { Lock, Plus } from "lucide-react";
import { type FormEvent, useState } from "react";
import { toast } from "sonner";

import { errorMessage } from "@/api/errors";
import { useCreateRole, useMe, usePermissions, useRoles, useUpdateRole } from "@/api/hooks";
import type { PermissionRead, RoleRead } from "@/api/types";
import { PageHeader, RequirePermission } from "@/components/RequirePermission";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { hasPermission } from "@/features/auth/auth";

function PermissionChecklist({
  permissions,
  selected,
  onChange,
}: {
  permissions: PermissionRead[];
  selected: string[];
  onChange: (next: string[]) => void;
}) {
  return (
    <div className="grid gap-2 sm:grid-cols-2">
      {permissions.map((permission) => (
        <label key={permission.name} className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-1 accent-(--color-primary)"
            checked={selected.includes(permission.name)}
            onChange={(e) =>
              onChange(
                e.target.checked
                  ? [...selected, permission.name]
                  : selected.filter((p) => p !== permission.name),
              )
            }
          />
          <span>
            <code className="font-mono">{permission.name}</code>
            <span className="block text-xs text-muted">{permission.description}</span>
          </span>
        </label>
      ))}
    </div>
  );
}

function RoleCard({
  role,
  permissions,
  canManage,
}: {
  role: RoleRead;
  permissions: PermissionRead[];
  canManage: boolean;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<string[]>(role.permissions);
  const updateRole = useUpdateRole();

  const save = () =>
    updateRole.mutate(
      { roleId: role.id, body: { permissions: draft } },
      {
        onSuccess: () => {
          toast.success(`Updated ${role.name}`);
          setEditing(false);
        },
        onError: (error) => toast.error(errorMessage(error)),
      },
    );

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between gap-4">
        <div>
          <CardTitle className="flex items-center gap-2 font-mono">
            {role.name}
            {role.is_system ? (
              <Badge title="Defined by the platform; cannot be modified">
                <Lock className="mr-1 size-3" /> system
              </Badge>
            ) : (
              <Badge tone="primary">custom</Badge>
            )}
          </CardTitle>
          <CardDescription>{role.description || "No description"}</CardDescription>
        </div>
        {canManage && !role.is_system && !editing ? (
          <Button size="sm" variant="outline" onClick={() => setEditing(true)}>
            Edit permissions
          </Button>
        ) : null}
      </CardHeader>
      <CardContent>
        {editing ? (
          <div className="space-y-3">
            <PermissionChecklist permissions={permissions} selected={draft} onChange={setDraft} />
            <div className="flex gap-2">
              <Button size="sm" onClick={save} disabled={updateRole.isPending}>
                Save
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  setDraft(role.permissions);
                  setEditing(false);
                }}
              >
                Cancel
              </Button>
            </div>
          </div>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {role.permissions.length ? (
              role.permissions.map((p) => (
                <Badge key={p} className="font-mono">
                  {p}
                </Badge>
              ))
            ) : (
              <span className="text-sm text-muted">No permissions</span>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function CreateRoleCard({ permissions }: { permissions: PermissionRead[] }) {
  const createRole = useCreateRole();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [selected, setSelected] = useState<string[]>([]);

  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    createRole.mutate(
      { name, description, permissions: selected },
      {
        onSuccess: (role) => {
          toast.success(`Created role ${role.name}`);
          setName("");
          setDescription("");
          setSelected([]);
        },
        onError: (error) => toast.error(errorMessage(error)),
      },
    );
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Create a custom role</CardTitle>
        <CardDescription>
          Lowercase letters, digits and underscores. System roles stay untouched.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form className="space-y-4" onSubmit={onSubmit}>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="role-name">Name</Label>
              <Input
                id="role-name"
                required
                pattern="[a-z][a-z0-9_]{2,63}"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="role-description">Description</Label>
              <Input
                id="role-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>
          </div>
          <PermissionChecklist permissions={permissions} selected={selected} onChange={setSelected} />
          <Button type="submit" disabled={createRole.isPending}>
            <Plus /> Create role
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

function RolesContent() {
  const { data: me } = useMe();
  const canManage = hasPermission(me, "role:manage");
  const roles = useRoles();
  const permissions = usePermissions();
  const permissionList = permissions.data ?? [];

  if (roles.isError) return <p className="text-sm text-danger">{errorMessage(roles.error)}</p>;

  return (
    <div className="space-y-4">
      {canManage ? <CreateRoleCard permissions={permissionList} /> : null}
      <div className="grid gap-4 lg:grid-cols-2">
        {(roles.data ?? []).map((role) => (
          <RoleCard key={role.id} role={role} permissions={permissionList} canManage={canManage} />
        ))}
      </div>
    </div>
  );
}

export function RolesPage() {
  return (
    <>
      <PageHeader
        title="Roles & permissions"
        description="Least privilege by default. Changes apply to signed-in users immediately and are audited."
      />
      <RequirePermission permission="role:read">
        <RolesContent />
      </RequirePermission>
    </>
  );
}
