// Text inputs and native selects in the shadcn/ui style (see LICENSE here).
// A native <select> is used on purpose: script-driven selects inject styles,
// which the strict Content-Security-Policy does not allow.
import type { ComponentProps } from "react";

import { cn } from "../../lib/utils";

const field =
  "flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm";

export function Input({ className, ...props }: ComponentProps<"input">) {
  return <input className={cn(field, className)} {...props} />;
}

export function Select({ className, ...props }: ComponentProps<"select">) {
  return <select className={cn(field, "w-auto bg-background py-2 pr-8", className)} {...props} />;
}
