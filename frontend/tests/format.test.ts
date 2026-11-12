import { boolean, bytes, days, duration, formatValue, gib, milliseconds, number, relative, safeUrl, text } from "../src/lib/format";
import { parse, href } from "../src/lib/router";

describe("formatting", () => {
  it("never turns missing values into zero or success", () => {
    for (const value of [null, undefined, "", Number.NaN]) {
      expect(formatValue(value, "number")).toBe("Unknown");
      expect(formatValue(value, "bytes")).toBe("Unknown");
      expect(formatValue(value, "boolean")).toBe("Unknown");
    }
    expect(text([])).toBe("");
  });

  it("shows characters that would hide or reorder a remote party's text", () => {
    expect(text("invoice\u202Efdp.exe")).toBe("invoice[U+202E]fdp.exe");
    expect(text("a\u200Bb\u0000c\uFEFF")).toBe("a[U+200B]b[U+0000]c[U+FEFF]");
    expect(text(["x\u2066y", "z"])).toBe("x[U+2066]y, z");
    expect(text({ name: "\u061Cq" })).toBe('{"name":"[U+061C]q"}');
    expect(text("Grüße, 你好 📬")).toBe("Grüße, 你好 📬");
  });

  it("formats sizes, durations and numbers", () => {
    expect(bytes(26214400)).toBe("25.0 MiB");
    // What a disk loses a day is a size with a sign, not an unknown one.
    expect(bytes(-209715200)).toBe("\u2212200.0 MiB");
    expect(bytes(Number.NaN)).toBe("Unknown");
    expect(duration(90)).toBe("2 min");
    expect(duration(7200)).toBe("2.0 h");
    expect(boolean(false)).toBe("No");
    expect(number(3)).toBe("3");
  });

  it("switches units at their exact boundaries", () => {
    expect([1023, 1024, 1024 ** 2].map((value) => bytes(value))).toEqual(["1,023 B", "1.0 KiB", "1.0 MiB"]);
    expect([59, 60, 3599, 3600, 86399, 86400].map((value) => duration(value))).toEqual([
      "59 s",
      "1 min",
      "60 min",
      "1.0 h",
      "24.0 h",
      "1.0 d",
    ]);
    expect([999, 1000, 1500, 60_000].map((value) => milliseconds(value))).toEqual(["999 ms", "1.0 s", "1.5 s", "1 min"]);
    expect([1, 2, -3].map((value) => days(value))).toEqual(["1 day", "2 days", "-3 days"]);
    expect(gib(1.234)).toBe("1.23 GiB");
  });

  it("describes times relative to now", () => {
    expect(relative(1000, 1000 * 1000 - 120_000)).toBe("in 2 min");
    expect(relative(1000, 1000 * 1000 + 30_000)).toBe("just now");
    expect(relative(1000, 1000 * 1000 + 3 * 3600_000)).toBe("3.0 h ago");
  });

  it("accepts only plain https links", () => {
    expect(safeUrl("https://mail.example.org/")).toBe("https://mail.example.org/");
    expect(safeUrl("javascript:alert(1)")).toBeNull();
    expect(safeUrl("https://user:pw@example.org/")).toBeNull();
  });
});

describe("routing", () => {
  it("maps paths to views and back", () => {
    expect(parse("/admin/")).toEqual({ view: "dashboard", detail: null });
    expect(parse("/admin/deliveries/337538776689541120")).toEqual({
      view: "deliveries",
      detail: "337538776689541120",
    });
    expect(href("sessions", "42")).toBe("/admin/sessions/42");
  });
});
