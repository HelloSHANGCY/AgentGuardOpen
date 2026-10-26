import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

// 构建产物由 FastAPI 以 /console 前缀托管；开发服务器把 API 代理到本地网关。
export default defineConfig({
  base: "/console/",
  plugins: [vue()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    chunkSizeWarningLimit: 2000,
    rollupOptions: {
      output: {
        manualChunks: {
          vue: ["vue"],
          "element-plus": ["element-plus", "@element-plus/icons-vue"],
          echarts: ["echarts"],
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/v1": "http://127.0.0.1:8080",
      "/health": "http://127.0.0.1:8080",
    },
  },
});
