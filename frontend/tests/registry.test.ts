import modules from "../api/modules.json";
import en from "../src/i18n/en.json";
import { moduleText, NAV, VIEWS } from "../src/modules/registry";

describe("module registry", () => {
  it("has exactly one view per server module", () => {
    expect(Object.keys(VIEWS).sort()).toEqual(modules.map((module) => module.id).sort());
  });

  it("gives every module its own icon", () => {
    const icons = Object.values(VIEWS).map((view) => view.icon);
    expect(new Set(icons).size).toBe(icons.length);
  });

  it("lists every module exactly once in the menu", () => {
    const listed = NAV.flatMap((entry) => (entry.kind === "module" ? [entry.id] : entry.modules));
    expect([...listed].sort()).toEqual(modules.map((module) => module.id).sort());
    expect(new Set(listed).size).toBe(listed.length);
  });

  it("names and describes every module in English exactly as the server does", () => {
    expect(Object.keys(en.modules).sort()).toEqual(modules.map((module) => module.id).sort());
    for (const module of modules) {
      const text = en.modules[module.id as keyof typeof en.modules];
      expect({ label: text.label, description: text.description }).toEqual({
        label: module.label,
        description: module.description,
      });
      expect(text.intro).not.toBe("");
    }
  });

  it("starts with the dashboard", () => {
    expect(modules[0]).toMatchObject({ id: "dashboard", label: "Dashboard" });
  });

  it("keeps the server's text for a module this build does not know", () => {
    const future = { id: "future", label: "Future module", description: "Added later" };
    expect(moduleText(future, "label")).toBe("Future module");
    expect(moduleText(future, "description")).toBe("Added later");
    expect(moduleText(future, "intro")).toBe("");
  });
});
