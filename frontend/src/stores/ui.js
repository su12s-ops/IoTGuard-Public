import { reactive } from "vue";

export const ui = reactive({
  tokenOpen: false,
  experimentOpen: false,
  toasts: []
});

let nextId = 1;

export function notify(message, type = "info") {
  const id = nextId++;
  ui.toasts.push({ id, message, type });
  window.setTimeout(() => {
    const index = ui.toasts.findIndex((item) => item.id === id);
    if (index >= 0) ui.toasts.splice(index, 1);
  }, type === "error" ? 6000 : 4200);
}

export function dismissToast(id) {
  const index = ui.toasts.findIndex((item) => item.id === id);
  if (index >= 0) ui.toasts.splice(index, 1);
}
