<template>
  <el-collapse class="device-control-config"><el-collapse-item title="设备操作配置" name="control"><el-form label-position="top"><el-form-item label="操作令牌"><el-input v-model="controlSession.token" type="password" show-password autocomplete="off" aria-label="设备操作令牌" placeholder="输入后端配置的操作令牌" /></el-form-item><p class="operation-help">令牌仅保留在当前页面会话内。设备操作需要令牌，Ubuntu 联调模式下资产与审计查询也需要令牌。</p></el-form></el-collapse-item></el-collapse>
</template>
<script setup>
import { controlSession } from "../api/deviceOperations";
</script>
