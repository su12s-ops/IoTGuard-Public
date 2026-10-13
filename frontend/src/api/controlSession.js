import { reactive } from "vue";

// Shared in-memory reference; never persisted in storage, URLs or downloaded reports.
export const controlSession = reactive({ token: "" });
export const controlRequest = () => ({ headers: { "X-Control-Token": controlSession.token } });
