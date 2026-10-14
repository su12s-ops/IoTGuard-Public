# 第七阶段实验室接线（非上游组件）：补齐 CMSIS 头文件 include 路径。
# 上游 west 工作区中由 cmsis 模块注册完成；本工作区（源码包部署）显式补齐。
# 两个路径：
#   1) Zephyr 树内兼容层 modules/cmsis/（提供 <cmsis_core.h> 包装）
#   2) 真实 CMSIS 仓库内核头（CMSIS 5 布局：A 核 Core_A/Include，R 核 Core_R/Include）
if(CONFIG_CPU_AARCH32_CORTEX_A)
  zephyr_include_directories(${ZEPHYR_BASE}/modules/cmsis)
  zephyr_include_directories(${ZEPHYR_BASE}/modules/hal/cmsis/CMSIS/Core_A/Include)
elseif(CONFIG_CPU_AARCH32_CORTEX_R)
  zephyr_include_directories(${ZEPHYR_BASE}/modules/cmsis)
  zephyr_include_directories(${ZEPHYR_BASE}/modules/hal/cmsis/CMSIS/Core_R/Include)
endif()
