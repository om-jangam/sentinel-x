import { KeyRound } from "lucide-react";
import { type FormEvent, useState } from "react";
import { toast } from "sonner";

import { errorMessage } from "@/api/errors";
import { useMe } from "@/api/hooks";
import { PageHeader } from "@/components/RequirePermission";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { changePassword } from "@/features/auth/auth";

const MIN_LENGTH = 12;

function ChangePasswordForm() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (next !== confirm) {
      setError("The new passwords don't match");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await changePassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      toast.success("Password changed. Every other session has been signed out.");
    } catch (err) {
      setError(errorMessage(err));
      setCurrent("");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Card className="max-w-md">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound className="size-4" aria-hidden /> Change password
        </CardTitle>
        <CardDescription>
          At least {MIN_LENGTH} characters, and not based on your email. Changing it signs out your other
          sessions; this one stays signed in.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form className="space-y-4" onSubmit={(e) => void onSubmit(e)}>
          <div className="space-y-1.5">
            <Label htmlFor="current-password">Current password</Label>
            <Input
              id="current-password"
              type="password"
              autoComplete="current-password"
              required
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="new-password">New password</Label>
            <Input
              id="new-password"
              type="password"
              autoComplete="new-password"
              required
              minLength={MIN_LENGTH}
              maxLength={128}
              value={next}
              onChange={(e) => setNext(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="confirm-password">Confirm new password</Label>
            <Input
              id="confirm-password"
              type="password"
              autoComplete="new-password"
              required
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
            />
          </div>
          {error ? (
            <p role="alert" className="text-sm text-danger">
              {error}
            </p>
          ) : null}
          <Button type="submit" disabled={submitting}>
            {submitting ? "Changing…" : "Change password"}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

export function AccountPage() {
  const { data: me } = useMe();
  return (
    <>
      <PageHeader title="Your account" description={me ? `${me.full_name} · ${me.email}` : undefined} />
      <ChangePasswordForm />
    </>
  );
}
