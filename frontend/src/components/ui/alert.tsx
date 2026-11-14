// Inline messages in the shadcn/ui alert style (see LICENSE here).
import { cva, type VariantProps } from "class-variance-authority";
import type { ComponentProps } from "react";

import { cn } from "../../lib/utils";

const alertVariants = cva("relative w-full rounded-2xl border px-4 py-3 text-sm [&_p+p]:mt-1", {
  variants: {
    tone: {
      // What needs no attention is a tile like any other; a warning keeps its frame.
      info: "border-transparent bg-card text-card-foreground shadow-tile",
      warning: "border-warning/40 bg-warning-background text-foreground",
      error: "border-destructive/50 bg-failed-background text-foreground",
    },
  },
  defaultVariants: { tone: "info" },
});

/** `live` makes the message a live region, which screen readers announce when
 * it appears or changes: for news, such as an error or a saved setting. Text
 * that is part of the page is none; it would be read out each time it changes. */
export function Alert({
  className,
  tone,
  live = false,
  ...props
}: ComponentProps<"div"> & VariantProps<typeof alertVariants> & { live?: boolean }) {
  const role = live ? (tone === "error" ? "alert" : "status") : undefined;
  return <div role={role} className={cn(alertVariants({ tone }), className)} {...props} />;
}
