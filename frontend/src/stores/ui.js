import { reactive } from "vue";

export const ui = reactive({
  tokenOpen: false,
  experimentOpen: false,
  // 路由级加载指示：懒加载分块在慢网下可能耗时数百毫秒，这段时间需要给反馈
  routeLoading: false,
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
