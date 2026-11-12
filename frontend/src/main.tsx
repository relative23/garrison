import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

// The catalogs load first, so every view renders in the interface language.
import "./i18n";
import { App } from "./App";
import { prepare } from "./start";
import "./styles/index.css";

async function start(root: HTMLElement) {
  // The server drew this page's frame or the sign-in page into the HTML.
  const drawn = root.dataset.shell;
  const shell = drawn === "frame" || drawn === "sign-in" ? drawn : undefined;
  const initial = shell === "frame" ? await prepare(location.pathname) : undefined;
  createRoot(root).render(
    <StrictMode>
      <App shell={shell} initial={initial} />
    </StrictMode>,
  );
}

const root = document.getElementById("root");
if (root) void start(root);
