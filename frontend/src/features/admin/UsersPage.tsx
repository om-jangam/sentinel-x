import { UserPlus } from "lucide-react";
import { type FormEvent, useState } from "react";
import { toast } from "sonner";

import { errorMessage } from "@/api/errors";
import { useCreateUser, useMe, useRoles, useSetUserRoles, useUpdateUser, useUsers } from "@/api/hooks";
import type { RoleRead, UserRead } from "@/api/types";
import { PageHeader, RequirePermission } from "@/components/RequirePermission";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { hasPermission } from "@/features/auth/auth";
import { formatDateTime } from "@/lib/utils";

function RolePicker({
  roles,
  selected,
  onChange,
}: {
  roles: RoleRead[];
  selected: string[];
  onChange: (next: string[]) => void;
}) {
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1.5">
      {roles.map((role) => (
        <label key={role.id} className="flex items-center gap-1.5 text-sm" title={role.description}>
          <input
            type="checkbox"
            className="accent-(--color-primary)"
            checked={selected.includes(role.name)}
            onChange={(e) =>
              onChange(e.target.checked ? [...selected, role.name] : selected.filter((r) => r !== role.name))
            }
          />
          {role.name}
        </label>
      ))}
    </div>
  );
}

function CreateUserCard({ roles }: { roles: RoleRead[] }) {
  const createUser = useCreateUser();
  const [form, setForm] = useState({ email: "", full_name: "", password: "" });
  const [selectedRoles, setSelectedRoles] = useState<string[]>(["analyst"]);

  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    createUser.mutate(
      { ...form, roles: selectedRoles },
      {
        onSuccess: (user) => {
          toast.success(`Created ${user.email}`);
          setForm({ email: "", full_name: "", password: "" });
        },
        onError: (error) => toast.error(errorMessage(error)),
      },
    );
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Invite an analyst</CardTitle>
        <CardDescription>Passwords need at least 12 characters. Share them out of band.</CardDescription>
      </CardHeader>
      <CardContent>
        <form className="grid gap-4 md:grid-cols-3" onSubmit={onSubmit}>
          <div className="space-y-1.5">
            <Label htmlFor="new-email">Email</Label>
            <Input
              id="new-email"
              type="email"
              required
              value={form.email}
              onChange={(e) => setForm({ ...form, email: e.target.value })}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="new-name">Full name</Label>
            <Input
              id="new-name"
              required
              value={form.full_name}
              onChange={(e) => setForm({ ...form, full_name: e.target.value })}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="new-password">Initial password</Label>
            <Input
              id="new-password"
              type="password"
              autoComplete="new-password"
              required
              minLength={12}
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
            />
          </div>
          <div className="md:col-span-3">
            <RolePicker roles={roles} selected={selectedRoles} onChange={setSelectedRoles} />
          </div>
          <div className="md:col-span-3">
            <Button type="submit" disabled={createUser.isPending}>
              <UserPlus /> Create user
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function UserRow({
  user,
  roles,
  canManage,
  isSelf,
}: {
  user: UserRead;
  roles: RoleRead[];
  canManage: boolean;
  isSelf: boolean;
}) {
  const [editing, setEditing] = useState(false);
  const [draftRoles, setDraftRoles] = useState<string[]>(user.roles);
  const setRoles = useSetUserRoles();
  const updateUser = useUpdateUser();

  const saveRoles = () =>
    setRoles.mutate(
      { userId: user.id, roles: draftRoles },
      {
        onSuccess: () => {
          toast.success(`Updated roles for ${user.email}`);
          setEditing(false);
        },
        onError: (error) => toast.error(errorMessage(error)),
      },
    );

  const toggleActive = () =>
    updateUser.mutate(
      { userId: user.id, body: { is_active: !user.is_active } },
      {
        onSuccess: (updated) =>
          toast.success(`${updated.email} ${updated.is_active ? "reactivated" : "deactivated"}`),
        onError: (error) => toast.error(errorMessage(error)),
      },
    );

  return (
    <TR>
      <TD>
        <p className="font-medium">{user.full_name}</p>
        <p className="text-xs text-muted">{user.email}</p>
      </TD>
      <TD className="min-w-64">
        {editing ? (
          <div className="space-y-2">
            <RolePicker roles={roles} selected={draftRoles} onChange={setDraftRoles} />
            <div className="flex gap-2">
              <Button size="sm" onClick={saveRoles} disabled={setRoles.isPending}>
                Save
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  setDraftRoles(user.roles);
                  setEditing(false);
                }}
              >
                Cancel
              </Button>
            </div>
          </div>
        ) : (
          <div className="flex flex-wrap gap-1">
            {user.roles.length ? (
              user.roles.map((r) => <Badge key={r}>{r}</Badge>)
            ) : (
              <span className="text-muted">none</span>
            )}
          </div>
        )}
      </TD>
      <TD>
        <Badge tone={user.is_active ? "success" : "danger"}>
          {user.is_active ? "active" : "deactivated"}
        </Badge>
      </TD>
      <TD className="whitespace-nowrap text-muted">{formatDateTime(user.last_login_at)}</TD>
      {canManage ? (
        <TD className="whitespace-nowrap text-right">
          {!editing ? (
            <Button size="sm" variant="outline" onClick={() => setEditing(true)}>
              Edit roles
            </Button>
          ) : null}{" "}
          <Button
            size="sm"
            variant={user.is_active ? "destructive" : "secondary"}
            onClick={toggleActive}
            disabled={isSelf || updateUser.isPending}
            title={isSelf ? "You cannot deactivate your own account" : undefined}
          >
            {user.is_active ? "Deactivate" : "Reactivate"}
          </Button>
        </TD>
      ) : null}
    </TR>
  );
}

function UsersContent() {
  const { data: me } = useMe();
  const canManage = hasPermission(me, "user:manage");
  const users = useUsers();
  const roles = useRoles(hasPermission(me, "role:read"));
  const roleList = roles.data ?? [];
  const rows = users.data?.pages.flatMap((page) => page.items) ?? [];

  return (
    <div className="space-y-6">
      {canManage ? <CreateUserCard roles={roleList} /> : null}
      <Card>
        <Table>
          <THead>
            <tr>
              <TH>User</TH>
              <TH>Roles</TH>
              <TH>Status</TH>
              <TH>Last sign-in</TH>
              {canManage ? <TH className="text-right">Actions</TH> : null}
            </tr>
          </THead>
          <TBody>
            {rows.map((user) => (
              <UserRow
                key={user.id}
                user={user}
                roles={roleList}
                canManage={canManage}
                isSelf={user.id === me?.id}
              />
            ))}
          </TBody>
        </Table>
        {users.isPending ? <p className="p-4 text-sm text-muted">Loading users…</p> : null}
        {users.isError ? <p className="p-4 text-sm text-danger">{errorMessage(users.error)}</p> : null}
        {users.hasNextPage ? (
          <div className="border-t border-border p-3 text-center">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => void users.fetchNextPage()}
              disabled={users.isFetchingNextPage}
            >
              Load more
            </Button>
          </div>
        ) : null}
      </Card>
    </div>
  );
}

export function UsersPage() {
  return (
    <>
      <PageHeader
        title="Users"
        description="Accounts are deactivated, never deleted, so the audit trail stays attributable."
      />
      <RequirePermission permission="user:read">
        <UsersContent />
      </RequirePermission>
    </>
  );
}
