import { createApp } from "vue";
import App from "./App.vue";
import router from "./router";
import "@fontsource-variable/inter";
import "./styles/console.css";
import "./styles/app.css";

createApp(App).use(router).mount("#app");
