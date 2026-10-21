<template>
  <Teleport to="body">
    <div v-if="open" class="modal-backdrop" @mousedown.self="$emit('close')">
      <section class="modal" :class="{ 'modal--wide': wide }" role="dialog" aria-modal="true" :aria-label="title">
        <header class="modal-head">
          <div>
            <h2>{{ title }}</h2>
            <p v-if="description">{{ description }}</p>
          </div>
          <button class="icon-close" type="button" aria-label="关闭" @click="$emit('close')">
            <Icon name="x" :size="17" />
          </button>
        </header>
        <div class="modal-body"><slot /></div>
        <footer v-if="$slots.footer" class="modal-foot"><slot name="footer" /></footer>
      </section>
    </div>
  </Teleport>
</template>

<script setup>
import { onMounted, onUnmounted } from "vue";
import Icon from "./Icon.vue";

const props = defineProps({
  open: { type: Boolean, default: false },
  title: { type: String, default: "" },
  description: { type: String, default: "" },
  wide: { type: Boolean, default: false }
});
const emit = defineEmits(["close"]);

function onKey(event) {
  if (event.key === "Escape" && props.open) emit("close");
}
onMounted(() => window.addEventListener("keydown", onKey));
onUnmounted(() => window.removeEventListener("keydown", onKey));
</script>
