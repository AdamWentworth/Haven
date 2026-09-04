import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/**/*.test.{ts,tsx}", "src/main.tsx", "src/icons.tsx", "src/types.ts", "src/vite-env.d.ts"],
      reporter: ["text", "json-summary"],
      thresholds: {
        statements: 40,
        branches: 35,
        functions: 45,
        lines: 40,
        "src/network.ts": { statements: 85, branches: 80, functions: 90, lines: 85 },
        "src/push.ts": { statements: 85, branches: 75, functions: 90, lines: 85 },
      },
    },
  },
});
