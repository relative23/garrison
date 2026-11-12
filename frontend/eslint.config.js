import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

// Rendering untrusted values as HTML is never needed in this interface.
const NO_HTML = {
  selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
  message: "Render text, not HTML.",
};

// Visible text comes from src/i18n/en.json, so every language can translate it.
const CATALOG = "Put visible text in src/i18n/en.json and render it with t().";
const NO_LITERAL_TEXT = [
  { selector: "JSXText[value=/[A-Za-z]/]", message: CATALOG },
  {
    selector: "JSXAttribute[name.name=/^(aria-label|alt|label|placeholder|summary|title)$/] > Literal",
    message: CATALOG,
  },
];

// <Trans> parses its translation as markup, values included; dynamic text goes
// in as the child of a self-closing component tag such as <phrase/> instead.
const NO_TRANS_VALUES = {
  selector: "JSXOpeningElement[name.name='Trans'] > JSXAttribute[name.name='values']",
  message: "Pass dynamic text as a component's child (<phrase/>), not as Trans values.",
};

export default tseslint.config(
  { ignores: ["dist", "coverage", "node_modules", "src/api/schema.gen.ts"] },
  js.configs.recommended,
  ...tseslint.configs.strict,
  // Plain scripts served as they are, such as the Stalwart WebUI switch row.
  { files: ["public/**/*.js"], languageOptions: { globals: globals.browser } },
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: { globals: globals.browser },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "no-restricted-syntax": ["error", NO_HTML],
    },
  },
  {
    files: ["src/**/*.tsx"],
    rules: { "no-restricted-syntax": ["error", NO_HTML, NO_TRANS_VALUES, ...NO_LITERAL_TEXT] },
  },
);
