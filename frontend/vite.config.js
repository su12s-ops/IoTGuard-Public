import { defineConfig, loadEnv } from "vite";
import { fileURLToPath } from "node:url";
import vue from "@vitejs/plugin-vue";

export default defineConfig(({ mode }) => {
const backendEnv = loadEnv(mode, fileURLToPath(new URL("../backend", import.meta.url)), "LINUXGUARD_");
return {
  plugins: [vue()],
  build: {
    assetsDir: "static",
    chunkSizeWarningLimit: 1200,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return;
          if (id.includes("vue-router") || id.includes("/vue/") || id.includes("\\vue\\")) return "vue";
        }
      }
    }
  },
  server: {
    proxy: { "/api": {
      target: "http://127.0.0.1:8000", changeOrigin: false,
      configure(proxy) {
        proxy.on("proxyReq", (proxyReq, request) => {
          if (request.headers["x-console-request"] === "1" && backendEnv.LINUXGUARD_CONTROL_TOKEN) {
            proxyReq.setHeader("X-Control-Token", backendEnv.LINUXGUARD_CONTROL_TOKEN);
          }
        });
      }
    } },
    port: 5173,
    host: "0.0.0.0",
    watch: {
      usePolling: true,
      interval: 1000
    }
  }
};
});
