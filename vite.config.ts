/// <reference types="vitest" />
import { defineConfig } from "vite";

export default defineConfig({
  test: {
    hookTimeout: 1000 * 60 * 10,
    testTimeout: 1000 * 60 * 10,
  },
});
