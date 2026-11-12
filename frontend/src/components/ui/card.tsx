// Cards as the Stalwart WebUI lays them out: tiles that float on the page, with
// a large radius and a soft shadow in place of a border (see LICENSE here).
import type { ComponentProps } from "react";

import { cn } from "../../lib/utils";

/** The card frame, for an element that cannot be a section, such as a list group. */
export const CARD = "rounded-2xl bg-card text-card-foreground shadow-tile";

export function Card({ className, ...props }: ComponentProps<"section">) {
  return <section className={cn(CARD, className)} {...props} />;
}

export function CardHeader({ className, ...props }: ComponentProps<"header">) {
  return <header className={cn("flex flex-col gap-1.5 p-6", className)} {...props} />;
}

/** Cards sit right below the page title, so their titles are the next level. */
export function CardTitle({ className, ...props }: ComponentProps<"h2">) {
  return <h2 className={cn("font-semibold leading-none tracking-tight", className)} {...props} />;
}

export function CardDescription({ className, ...props }: ComponentProps<"p">) {
  return <p className={cn("text-sm text-muted-foreground", className)} {...props} />;
}

export function CardContent({ className, ...props }: ComponentProps<"div">) {
  return <div className={cn("p-6 pt-0", className)} {...props} />;
}

export function CardFooter({ className, ...props }: ComponentProps<"footer">) {
  return <footer className={cn("flex items-center p-6 pt-0", className)} {...props} />;
}
