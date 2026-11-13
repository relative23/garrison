// The Garrison logo. The mark is the design source from xtask/src/brand.rs; the
// words are real text, so they follow the theme and stay readable for everyone.
const MARK = "M6 4h4v4h4V4h4v4h4V4h4v8H10v12h12v-4h-6v-4h10v12H6z";

// The product name and the byline are names, not interface text: they read the
// same in every language. The logo carries only Garrison's own name; Stalwart's
// is named in text, where it says what Garrison works with.
export const PRODUCT = "Garrison";
const BYLINE = "by relative23";

function BrandMark({ className }: { className: string }) {
  return (
    <svg className={className} viewBox="0 0 32 32" aria-hidden="true" focusable="false">
      <path fill="currentColor" d={MARK} />
    </svg>
  );
}

/** Compact logo for the header, 28 px high. Its word names the link it sits in. */
export function Brand() {
  return (
    <span className="flex h-7 items-center gap-2">
      <BrandMark className="h-7 w-7 shrink-0" />
      <span className="text-[17px] leading-none font-semibold tracking-tight">{PRODUCT}</span>
    </span>
  );
}

/** Large logo for the sign-in page; its heading names the product. */
export function BrandLarge() {
  return (
    <div className="flex items-center gap-4 text-left">
      <BrandMark className="h-[4.5rem] w-[4.5rem] shrink-0" />
      <div className="flex flex-col leading-none">
        <h1 className="text-[2rem] font-bold tracking-tight">{PRODUCT}</h1>
        <span className="mt-2 text-[0.85rem] text-muted-foreground">{BYLINE}</span>
      </div>
    </div>
  );
}
