import { createApp } from "vue";
import App from "./App.vue";
import router from "./router";
import { initializeConsoleSession } from "./api";
import "@fontsource-variable/inter";
import "./styles/console.css";
import "./styles/app.css";

await initializeConsoleSession();
createApp(App).use(router).mount("#app");
