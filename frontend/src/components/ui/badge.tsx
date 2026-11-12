// Badges in the shadcn/ui style (see LICENSE here), plus Garrison's status
// tones. A tone is never the only signal: callers always add a word.
import { cva, type VariantProps } from "class-variance-authority";
import type { ComponentProps } from "react";

import { cn } from "../../lib/utils";

export const badgeVariants = cva(
  "inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors [&_svg]:size-3.5 [&_svg]:shrink-0",
  {
    variants: {
      tone: {
        default: "border-transparent bg-primary text-primary-foreground shadow",
        secondary: "border-transparent bg-secondary text-secondary-foreground",
        outline: "text-foreground",
        ok: "border-transparent bg-ok-background text-ok",
        warning: "border-transparent bg-warning-background text-warning",
        failed: "border-transparent bg-failed-background text-failed",
        unknown: "border-transparent bg-unknown-background text-unknown",
      },
    },
    defaultVariants: { tone: "outline" },
  },
);

export type BadgeTone = NonNullable<VariantProps<typeof badgeVariants>["tone"]>;

export function Badge({ className, tone, ...props }: ComponentProps<"span"> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}
