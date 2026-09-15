import type { InputHTMLAttributes, LabelHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "flex h-9 w-full rounded-md border border-border bg-background px-3 py-1 text-sm placeholder:text-muted disabled:opacity-50",
        className,
      )}
      {...props}
    />
  );
}

export function Label({ className, ...props }: LabelHTMLAttributes<HTMLLabelElement>) {
  return <label className={cn("text-sm font-medium text-foreground", className)} {...props} />;
}

export function Select({ className, ...props }: InputHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={cn("h-9 rounded-md border border-border bg-background px-2 text-sm", className)}
      {...props}
    />
  );
}
