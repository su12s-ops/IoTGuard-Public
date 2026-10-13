# Zephyr-Sensor-01（IoTGuard 第七阶段）
# 构建（在 Ubuntu 侧）：
#   cmake -B build -GNinja -DBOARD=qemu_x86_64 \
#         -DZEPHYR_TOOLCHAIN_VARIANT=zephyr -DZEPHYR_SDK_INSTALL_DIR=<sdk路径>
#   ninja -C build
cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(zephyr_sensor_01 LANGUAGES C)

target_sources(app PRIVATE main.c)
