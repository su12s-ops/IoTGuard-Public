# 参与维护

## 文件与命名

- 项目级入口保留标准名称 `README.md`、`CONTRIBUTING.md`；模块入口也使用 `README.md`。
- 当前文档使用小写英文和短横线，如 `docs/guides/openwrt-lan.md`。
- 使用指南放在 `docs/guides/`，实现说明放在 `docs/architecture/`，权限规则放在 `docs/reference/`，验证方法放在 `docs/validation/`。
- 历史记录使用 `docs/archive/YYYY-MM-DD-topic.md`，首段说明是历史窗口，不能混入当前状态说明。
- Python 使用 `snake_case.py`，Vue 组件使用 `PascalCase.vue`；已有代码入口、API 路径、配置变量和固件工具链文件名按现有约定维护，改名时同步引用与测试。

## 资料维护

变更功能时更新一处对应指南，并在 `docs/README.md` 中维护入口。`docs/status.md` 记录当前部署与开放问题，历史过程按日期归档；不要在根目录增加带项目长前缀的阶段报告。重复说明合并到对应主题，废弃原型与可重建清单不随源码保留。

公开文档不放真实令牌、私钥、数据库、原始设备配置或运行日志。示例地址必须说明用途，现场回执保存在忽略目录。删除资料前检查引用；删除代码前检查运行入口与测试。Git 历史用于追溯，不能通过改写旧失败记录制造通过结论。

## 验证与提交

```powershell
python -m pytest -q
npm --prefix frontend run build
node --test frontend/tests/*.test.js
npm --prefix frontend run test:e2e
python scripts/check_docs.py
git diff --check
```

完整命令、浏览器依赖和验证范围见 [验证方法](docs/validation/testing.md)。测试使用临时数据库和回环服务，不指向现场设备；实际设备和付费模型调用另行按授权范围执行。

提交前审查 `git diff --cached` 与新增文件；不得提交 `.env`、私钥、数据库、虚拟磁盘、依赖目录和测试输出。提交说明描述最终行为和验证结果，区分本地通过、现场实测和远端 CI。
