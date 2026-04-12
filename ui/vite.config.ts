import { defineConfig } from "vite";
import { fresh } from "@fresh/plugin-vite";

const API_TARGET = process.env.API_BASE_URL ?? "http://localhost:8080";

export default defineConfig({
  plugins: [fresh()],
  server: {
    proxy: {
      "/api": {
        target: API_TARGET,
        changeOrigin: true,
      },
    },
  },
});
