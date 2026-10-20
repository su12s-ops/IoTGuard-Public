# 协作二：Zephyr 公告适用性

- 官方快照 281 条；125 条进入开放复核队列。
- 当前分类：54 `potentially_affected`、71 `insufficient_data`、156 `not_in_reported_range`，确认 `affected=0`。
- 每项绑定公告哈希、ELF 哈希、`.config` 哈希，并保留组件、配置、链接/补丁和可达性补证要求。
- 缺少 west manifest、模块修订或源码 commit 时必须保留证据缺口，不从启动 banner 推测组件启用。
