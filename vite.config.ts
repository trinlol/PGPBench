import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Vite options tailored for Tauri development
  //
  // 1. prevent Vite from obscuring Rust errors
  clearScreen: false,
  // 2. Tauri expects a fixed port; fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      // 3. tell Vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },
  // 4. Env variables starting with TAURI_ and VITE_ are exposed to the webview
  envPrefix: ["TAURI_", "VITE_"],
  build: {
    // Tauri uses WebView2 on Windows; Safari on macOS and WebKit on Linux
    target: "chrome105",
    minify: "esbuild",
    sourcemap: false,
  },
});
