import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host:  "0.0.0.0",
    port:  3000,
    proxy: {
      // Forward all /api/* calls to Flask backend
      "/api": {
        target:       "http://localhost:5000",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir:    "dist",
    sourcemap: false,
  },
});
