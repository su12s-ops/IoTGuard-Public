import { createApp } from "vue";
import App from "./App.vue";
import router from "./router";
import "@fontsource-variable/inter";
import "./styles/console.css";
import "./styles/app.css";
import "./styles/redesign/index.css"; // 改造层（Q1）：删除此行即回退到原设计

createApp(App).use(router).mount("#app");
