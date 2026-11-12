// Tables as the Stalwart WebUI lays out its lists: a tile of its own on the
// page, a framed inset inside a card, with a muted header row and row hover.
// Built on shadcn/ui conventions (see LICENSE here).
import { useEffect, useRef, useState, type ComponentProps, type RefObject } from "react";

import { cn } from "../../lib/utils";

/** Whether the frame's content is wider than the frame, kept current as either resizes. */
function useScrolls(frame: RefObject<HTMLDivElement | null>): boolean {
  const [scrolls, setScrolls] = useState(false);
  useEffect(() => {
    const element = frame.current;
    if (!element) return;
    const observer = new ResizeObserver(() => setScrolls(element.scrollWidth > element.clientWidth));
    observer.observe(element);
    if (element.firstElementChild) observer.observe(element.firstElementChild);
    return () => observer.disconnect();
  }, [frame]);
  return scrolls;
}

export function Table({ className, ...props }: ComponentProps<"table">) {
  const frame = useRef<HTMLDivElement>(null);
  // A table wider than the screen scrolls sideways; then the keyboard reaches it too.
  const scrolls = useScrolls(frame);
  return (
    // Inside a card (a section) the tile would float on a tile: there it is a framed inset.
    <div className="overflow-hidden rounded-2xl bg-card text-card-foreground shadow-tile [section_&]:rounded-xl [section_&]:border [section_&]:shadow-none">
      <div
        ref={frame}
        tabIndex={scrolls ? 0 : undefined}
        className="overflow-x-auto focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-ring"
      >
        <table className={cn("w-full text-sm", className)} {...props} />
      </div>
    </div>
  );
}

export function TableHeader(props: ComponentProps<"thead">) {
  return <thead {...props} />;
}

export function TableBody({ className, ...props }: ComponentProps<"tbody">) {
  return <tbody className={cn("[&_tr:last-child]:border-0", className)} {...props} />;
}

export function TableRow({ className, ...props }: ComponentProps<"tr">) {
  return <tr className={cn("border-b transition-colors hover:bg-muted/50", className)} {...props} />;
}

export function TableHeadRow({ className, ...props }: ComponentProps<"tr">) {
  return <tr className={cn("border-b bg-muted", className)} {...props} />;
}

export function TableHead({ className, ...props }: ComponentProps<"th">) {
  return <th scope="col" className={cn("px-3 py-3 text-left font-medium text-muted-foreground", className)} {...props} />;
}

export function TableCell({ className, ...props }: ComponentProps<"td">) {
  return <td className={cn("px-3 py-2 align-top", className)} {...props} />;
}

/** One full-width row for "nothing matches" messages. */
export function TableEmpty({ columns, children }: { columns: number; children: string }) {
  return (
    <tr>
      <td colSpan={columns} className="px-3 py-6 text-center text-muted-foreground">
        {children}
      </td>
    </tr>
  );
}
