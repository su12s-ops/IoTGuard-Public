# QEMU 宿主签名更新

范围：受信任 Linux 宿主上的 `qemu_cortex_a9` 虚拟设备。此适配器不实现 Zephyr 设备侧 OTA 接收器、MCUboot、安全启动或实体断电恢复。

`scripts/virtual_firmware.py` 验证 Ed25519 签名、板型、设备身份、版本、镜像与 Kconfig 摘要；审批绑定完整 manifest 摘要。更新计数器只能增长，显式回滚只允许上一个已确认版本，回滚不降低最高计数器。磁盘状态原子替换，日志追加保存；未完成的更新阻止下一次更新，`recover` 重启并复验上次确认版本。

镜像目录只允许四个输入文件：`zephyr.elf`、`.config`、`manifest.json`、`manifest.sig`。manifest 为以下对象的 UTF-8 JSON，签名对象是键排序、无多余空格、`ensure_ascii=False` 的规范 JSON；签名文件为无换行的 Base64。信任公钥从操作员提供的 PEM 文件读取，不接受随镜像替换公钥。

```json
{
  "schema": 1,
  "board": "qemu_cortex_a9",
  "device_id": "YOUR-DEVICE-ID",
  "version": "YOUR-FIRMWARE-VERSION",
  "counter": 1,
  "files": {
    "zephyr.elf": "64-hex-sha256-of-elf",
    ".config": "64-hex-sha256-of-config"
  }
}
```

安装 Python 依赖后先验证，不启动设备：

```sh
python scripts/virtual_firmware_cli.py verify --store /var/lib/iotguard-firmware --public-key /etc/iotguard/firmware.pub --device-id YOUR-DEVICE-ID --bundle /srv/firmware/release
```

`activate`/`rollback` 还要求 `--approved-sha256`、绝对路径的 `--restart-helper`；helper 只接收一个已验签目录参数，必须先停止旧 guest 再启动新 guest。helper 属于管理员配置，不能来自 manifest；不得把路径拼成任意 shell 命令。`--probe-url` 只允许回环转发地址的 `/api/system`，恢复后必须匹配设备 ID 和固件版本。首次登记失败没有已确认回退版本，会保留 pending，不能宣称回退成功。重启宿主后应先执行 `recover`，不要直接启动 pending 镜像。状态目录、helper 与公钥必须仅允许可信操作员写入；宿主被攻陷不在此信任模型内。

## 独立虚拟机验收

```sh
python scripts/verify_qemu_firmware.py --build /path/to/build/zephyr --device-id YOUR-DEVICE-ID --version YOUR-FIRMWARE-VERSION --output /path/to/new-evidence-directory
```

脚本使用新回环端口和自己创建的 QEMU 子进程，不停止现有设备、不向产品登记克隆身份。临时实验签名私钥只存在进程内存，不能作为正式发布密钥。它测试同一真实镜像的不同签名发布、故意错误版本的失败回退、显式回滚和确认版本重启；不是不同应用版本或新固件缺陷的修复证明。

2026-10-20：在既有 Ubuntu VM 上使用现有 Zephyr 4.4.2 / 应用 0.3.0 镜像，以上五项实际 QEMU 检查通过。另有 8 项隔离测试覆盖篡改、错误板型、错误审批、计数器重放、故障回退和模拟宿主中断。原有 guest 未改动。证据保存在本地 `reports/delivery-20261020/`，不上传镜像、数据库或凭据。
