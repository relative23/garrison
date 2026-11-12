// A view that fails to render shows a notice instead of a blank page; the menu
// stays usable, and opening another page starts over (App keys it by route).
import { Component, type ReactNode } from "react";

import { useTranslation } from "../i18n";
import { Notice } from "./Status";

function Failed() {
  const { t } = useTranslation();
  return <Notice tone="error">{t("app.viewFailed")}</Notice>;
}

export class ViewBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  override state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  override render() {
    return this.state.failed ? <Failed /> : this.props.children;
  }
}
