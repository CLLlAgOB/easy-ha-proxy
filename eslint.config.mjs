// ESLint for the admin panel's scripts and their tests. It runs in CI (the
// "JavaScript" job) with the recommended rules: a name nothing defines, a
// variable nothing reads, a duplicate key, unreachable code.
//
// The pages load plain scripts, not modules, so every name a script uses from
// another one is declared here, and only where it is defined.
import js from "@eslint/js";
import globals from "globals";

const PANEL = "docker/app/haproxy_admin/static/js";

export default [
  {
    files: [`${PANEL}/*.js`],
    ...js.configs.recommended,
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "script",
      globals: {
        ...globals.browser,
        // security.js defines it, and base.html loads security.js first on
        // every page.
        escapeHtml: "readonly",
      },
    },
    rules: {
      ...js.configs.recommended.rules,
      // An error that is caught to be ignored needs no name to be read.
      "no-unused-vars": ["error", { caughtErrors: "none" }],
    },
  },
  {
    // The parts kept apart from the page export themselves for node's tests.
    files: [
      `${PANEL}/*_core.js`,
      `${PANEL}/i18n.js`,
    ],
    languageOptions: {
      globals: { module: "readonly" },
    },
  },
  {
    files: [".tests/js/*.js"],
    ...js.configs.recommended,
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "commonjs",
      globals: { ...globals.node },
    },
    rules: {
      ...js.configs.recommended.rules,
      "no-unused-vars": ["error", { caughtErrors: "none" }],
    },
  },
];
