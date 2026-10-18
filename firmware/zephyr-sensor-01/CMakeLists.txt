# Zephyr-Sensor-01（IoTGuard 第七阶段）
# 构建（在 Ubuntu 侧）：
#   cmake -B build-arm -GNinja -DBOARD=qemu_cortex_a9 \
#         -DZephyr-sdk_DIR=<sdk>/cmake \
#         -DZEPHYR_TOOLCHAIN_VARIANT=zephyr -DZEPHYR_SDK_INSTALL_DIR=<sdk路径>
#   ninja -C build-arm
# 运行：系统 qemu-system-arm（见 start-qemu.sh；qemu_x86_64 路径已弃用）
cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(zephyr_sensor_01 LANGUAGES C)

# 诊断模式：-DUSE_DIAG=1 时编译 main_diag.c（无网络，最小集）
# 注意：qemu_x86_64 构建需在 Zephyr 源码树内执行（树外构建 locore 不兼容），
# 参见 start-qemu.sh 注释与 IOT_STAGE7_ZEPHYR_REPORT.md
if(USE_DIAG)
  target_sources(app PRIVATE main_diag.c)
else()
  target_sources(app PRIVATE main.c)
  target_sources_ifdef(CONFIG_APP_QEMU_HOST_ENTROPY app PRIVATE host_entropy.c)
endif()
