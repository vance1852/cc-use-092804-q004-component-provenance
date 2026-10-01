# 形成国产电子部件来源与兼容放行链基础平台

本项目是一套可离线运行的 Python 服务端平台，服务于具身智能机器人控制域、AI 计算域和国产电子部件质量域。平台管理控制计算节点、实时控制总线、资源时隙、机器人构建、验证测量、分析租约、部件批次与质量决定，业务状态、幂等结果和审计事件保存在 SQLite 中。

## 目录

- `src/robot_control/`：控制节点、实时总线、资源批次、时隙申请、容量分配和架构情景；
- `src/embodied_ai/`：机器人构建、验证协议、测量导入、排除复核、分析任务和准入决定；
- `src/component_qualification/`：国产电子部件批次、信号测量、统计分析、账号权限和质量审批；
- `src/release_chain/`：部件来源与兼容放行链——厂商声明、批次谱系、固件摘要、接口能力与检验结果的不可覆盖版本，硬件/软件/质量角色分别签署，替代料版本化批准，针对确定整机配置的装配放行，出厂结论冻结与序列号去向追溯；
- `fixtures/`：离线验收使用的验证协议与结构化测量；
- `tests/`：领域规则、事务、权限、HTTP API 和命令行验收测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 运行时仅使用 Python 标准库和 SQLite

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m robot_control.acceptance --workspace .
PYTHONPATH=src python3 -m embodied_ai.acceptance --workspace .
PYTHONPATH=src python3 -m component_qualification.acceptance
PYTHONPATH=src python3 -m release_chain.acceptance
```

四条命令会在临时 SQLite 数据库中完成控制资源分配、AI 验证分析、国产电子部件质量流程，以及部件证据签署、替代料放行、出厂冻结和返工追溯，不访问外部网络。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m robot_control.api --database robot-control.sqlite3 --host 127.0.0.1 --port 8080
PYTHONPATH=src python3 -m embodied_ai.api --database embodied-ai.sqlite3 --host 127.0.0.1 --port 8081
PYTHONPATH=src python3 -m component_qualification.api --database component.sqlite3 --host 127.0.0.1 --port 8082
PYTHONPATH=src python3 -m release_chain.api --database release-chain.sqlite3 --host 127.0.0.1 --port 8083
```

服务提供 JSON 接口与健康检查（放行链服务使用 `X-Actor-Id` 请求头标识操作者角色）。进程重启后可以继续读取 SQLite 中的业务状态和审计历史。
