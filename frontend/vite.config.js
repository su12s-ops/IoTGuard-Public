import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  plugins: [vue()],
  build: {
    chunkSizeWarningLimit: 1200,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return;
          if (id.includes("echarts")) return "charts";
          if (id.includes("element-plus") || id.includes("@element-plus")) return "element-plus";
          if (id.includes("vue-router") || id.includes("/vue/") || id.includes("\\vue\\")) return "vue";
        }
      }
    }
  },
  server: {
    port: 5173,
    host: "0.0.0.0",
    watch: {
      usePolling: true,
      interval: 1000
    }
  }
});
