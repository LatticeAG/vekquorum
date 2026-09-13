import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default [
  { ignores: ["dist/**", "dist-test/**", "node_modules/**", "python/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.ts", "tests/ts/**/*.ts"],
    rules: {
      // Protocol values are RFC 8785 JSON — deliberately untyped `any` at the
      // validation boundary, mirroring the dynamic Python reference package.
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "no-console": "off"
    }
  }
];
