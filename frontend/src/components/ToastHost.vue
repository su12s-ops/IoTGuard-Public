<template>
  <Teleport to="body">
    <div class="toast-stack" aria-live="polite">
      <div v-for="toast in ui.toasts" :key="toast.id" class="toast" :class="toast.type" @click="dismissToast(toast.id)">
        {{ toast.message }}
      </div>
    </div>
  </Teleport>
</template>

<script setup>
import { ui, dismissToast } from "../stores/ui";
</script>
