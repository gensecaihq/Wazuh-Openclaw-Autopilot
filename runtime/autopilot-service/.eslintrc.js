/**
 * ESLint Configuration for Wazuh OpenClaw Autopilot
 *
 * Rules focused on:
 * - Node.js best practices
 * - Security (no-eval, no-implied-eval, etc.)
 * - Code consistency
 */

module.exports = {
  env: {
    node: true,
    es2022: true,
  },

  parserOptions: {
    ecmaVersion: 2022,
    sourceType: "module",
  },

  extends: ["eslint:recommended"],

  rules: {
    // ==========================================================================
    // Possible Errors
    // ==========================================================================
    "no-console": "off", // Console is expected for CLI service
    "no-debugger": "error",
    "no-duplicate-imports": "error",
    "no-template-curly-in-string": "warn",

    // ==========================================================================
    // Best Practices
    // ==========================================================================
    "curly": ["error", "multi-line"],
    "default-case": "warn",
    "dot-notation": "error",
    "eqeqeq": ["error", "always", { null: "ignore" }],
    "no-caller": "error",
    "no-else-return": "warn",
    "no-empty-function": "warn",
    "no-eval": "error",
    "no-extend-native": "error",
    "no-extra-bind": "error",
    "no-floating-decimal": "error",
    "no-implied-eval": "error",
    "no-lone-blocks": "error",
    "no-loop-func": "error",
    "no-multi-spaces": "error",
    "no-new": "warn",
    "no-new-func": "error",
    "no-new-wrappers": "error",
    "no-octal-escape": "error",
    "no-param-reassign": "warn",
    "no-proto": "error",
    "no-return-assign": "error",
    "no-return-await": "error",
    "no-script-url": "error",
    "no-self-compare": "error",
    "no-sequences": "error",
    "no-throw-literal": "error",
    "no-unmodified-loop-condition": "error",
    "no-unused-expressions": "error",
    "no-useless-call": "error",
    "no-useless-concat": "error",
    "no-useless-return": "error",
    "no-void": "error",
    "prefer-promise-reject-errors": "error",
    "radix": "error",
    "require-await": "warn",
    "yoda": "error",

    // ==========================================================================
    // Variables
    // ==========================================================================
    "no-shadow": "warn",
    "no-unused-vars": [
      "error",
      {
        argsIgnorePattern: "^_",
        varsIgnorePattern: "^_",
      },
    ],
    "no-use-before-define": [
      "error",
      {
        functions: false,
        classes: true,
        variables: true,
      },
    ],

    // ==========================================================================
    // Node.js Specific
    // ==========================================================================
    "no-buffer-constructor": "error",
    "no-path-concat": "error",
    "no-process-exit": "off", // Used for graceful shutdown

    // ==========================================================================
    // Stylistic
    // ==========================================================================
    "array-bracket-spacing": ["error", "never"],
    "block-spacing": ["error", "always"],
    "brace-style": ["error", "1tbs", { allowSingleLine: true }],
    "comma-dangle": ["error", "always-multiline"],
    "comma-spacing": ["error", { before: false, after: true }],
    "comma-style": ["error", "last"],
    "computed-property-spacing": ["error", "never"],
    "eol-last": ["error", "always"],
    "func-call-spacing": ["error", "never"],
    "indent": ["error", 2, { SwitchCase: 1 }],
    "key-spacing": ["error", { beforeColon: false, afterColon: true }],
    "keyword-spacing": ["error", { before: true, after: true }],
    "linebreak-style": ["error", "unix"],
    "max-len": [
      "warn",
      {
        code: 120,
        ignoreUrls: true,
        ignoreStrings: true,
        ignoreTemplateLiterals: true,
        ignoreRegExpLiterals: true,
      },
    ],
    "no-multiple-empty-lines": ["error", { max: 2, maxEOF: 1 }],
    "no-trailing-spaces": "error",
    "object-curly-spacing": ["error", "always"],
    "quotes": ["error", "double", { avoidEscape: true }],
    "semi": ["error", "always"],
    "semi-spacing": ["error", { before: false, after: true }],
    "space-before-blocks": ["error", "always"],
    "space-before-function-paren": [
      "error",
      {
        anonymous: "always",
        named: "never",
        asyncArrow: "always",
      },
    ],
    "space-in-parens": ["error", "never"],
    "space-infix-ops": "error",
    "space-unary-ops": ["error", { words: true, nonwords: false }],

    // ==========================================================================
    // ES6+
    // ==========================================================================
    "arrow-spacing": ["error", { before: true, after: true }],
    "no-duplicate-imports": "error",
    "no-useless-computed-key": "error",
    "no-useless-constructor": "error",
    "no-useless-rename": "error",
    "no-var": "error",
    "object-shorthand": ["error", "always"],
    "prefer-arrow-callback": ["error", { allowNamedFunctions: true }],
    "prefer-const": ["error", { destructuring: "all" }],
    "prefer-rest-params": "error",
    "prefer-spread": "error",
    "prefer-template": "warn",
    "rest-spread-spacing": ["error", "never"],
    "template-curly-spacing": ["error", "never"],
  },

  overrides: [
    {
      files: ["*.test.js", "**/__tests__/**"],
      env: {
        node: true,
      },
      rules: {
        "no-unused-expressions": "off",
      },
    },
  ],
};
