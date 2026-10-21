import { reactive } from "vue";

// Shared in-memory reference; never persisted in storage, URLs or downloaded reports.
export const controlSession = reactive({ token: "" });
export const controlRequest = () => ({ headers: { "X-Control-Token": controlSession.token } });

// One token dialog for the whole application: the shell owns the UI, pages only
// ask for it, so the same credential is never rendered twice.
export const tokenDialog = reactive({ open: false });
