# 基因组数据访问治理

这是一个只使用Python标准库和SQLite的模块化项目，默认端口为`8304`。所有业务规则集中在`src/rules.py`，`app.py`只负责组装依赖和启动服务。

## 模块结构

- `app.py`：命令行参数、依赖组装、启动和信号处理。
- `src/domain.py`：角色、数据结构、领域异常和基础校验。
- `src/rules.py`：状态机、权限、领域计算、冲突和跨对象校验。
- `src/repository.py`：SQLite建表、查询、事务和乐观锁。
- `src/service.py`：用例编排、幂等处理、版本控制和审计写入。
- `src/http_api.py`：HTTP路由、请求解析和统一错误响应。
- `src/audit.py`：实体操作审计时间线。
- `static/index.html`：最小演示页面。
- `tests/`：完整流程、规则和失败场景测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8304
```

服务启动时会自动建表。`--host`可修改监听地址，`--db`可指定其他SQLite文件。

## 核心对象

- `dataset`：受控数据集，data 内带 `policy_version` 与 `policy_history`。
- `application`：访问申请，提交时按数据集当前政策版本盖章。
- `grant`：限时数据使用凭证，创建时按当前政策版本签发。

## 政策变更治理批次

管理员通过 `POST /api/datasets/<id>/policy` 更新访问政策后，系统在同一事务内
生成治理批次（`policy_batch`），随后逐条独立事务处理受影响对象：

- **旧版凭证立即失效**：旧政策版本下 `active`/`issued` 的凭证转为
  `revoked_policy_change`，并生成按新政策签发的新版本凭证（`issued`，
  通过 `supersedes`/`superseded_by` 关联），新凭证走正常激活流程。
- **待审批申请退回复核**：`submitted`/`under_review` 的旧政策申请转为
  `returned_for_review`，复核后用 `resubmit` 按新政策重新提交。
- **晚到一方按新政策拒绝**：停用与激活都在 `BEGIN IMMEDIATE` 单事务内
  复查对方事实。停用先完成则晚到激活 403；激活先提交则晚到停用 409，
  已停用数据集上不可能留下有效凭证。
- **管理员权威**：`deactivate`/`reactivate`/`revoke_policy_change`/
  `return_for_review` 仅 admin 可执行，委员会不能绕过停用决定。
- **失败与重试**：单条失败回滚该条事务并标记 `failed`，批次状态为 `failed`，
  未处理对象原样保留；`POST /api/policy-batches/<id>/retry`（仅管理员）只
  续做 `pending`/`failed` 条目，`done`/`skipped` 不会重复吊销。每次运行
  记录在批次的 `runs` 中。
- **重启续做**：服务启动时自动恢复停留在 `processing` 的批次（崩溃中断点），
  只处理未完成条目；显式 `failed` 的批次需管理员手动重试。
- **旧数据兼容**：缺少 `policy_version` 的历史记录按原政策（第 1 版）兼容
  留档，治理视图中以 `policy_version_recorded:false` 标出；管理员可用
  `POST /api/datasets/<id>/backfill-policy` 补录（默认补为第 1 版，幂等）。

### 治理相关接口

- `POST /api/datasets/<id>/policy`：管理员提交政策变更，返回批次（含条目与运行结果）。
- `POST /api/policy-batches/<id>/retry`：管理员重试失败/中断批次。
- `GET /api/policy-batches?dataset_id=...`：列出批次。
- `GET /api/policy-batches/<id>`：批次详情（`items` 含结果/尝试次数/错误，`runs` 含失败与重试）。
- `GET /api/datasets/<id>/governance`：按数据集展示政策版本、政策历史、
  受影响申请与凭证（含新版本凭证 id）、批次与失败重试结果。
- `GET /api/audit?dataset_id=<id>`：按数据集聚合的审计时间线（含批次与新旧凭证）。
- `POST /api/datasets/<id>/backfill-policy`：旧数据补录政策版本。

### 新增状态动作

- dataset：`deactivate`（仅 admin）、`reactivate`（仅 admin）。
- application：`return_for_review`（批次/仅 admin）、`resubmit`。
- grant：`revoke_policy_change`（批次/仅 admin）。

## 主要接口

- `GET /health`：健康检查。
- `GET /api/<kind>`：按对象类型查询，可用`?status=`过滤。
- `POST /api/<kind>`：创建对象；请求体为JSON。
- `GET /api/entities/<id>`：读取对象当前版本。
- `POST /api/entities/<id>/actions`：提交`{"action":"动作名","data":{...},"expected_version":数字}`。
- `GET /api/audit`：读取审计记录。

请求身份通过`X-User-Id`和`X-Role`请求头传入。创建和动作的可执行角色由规则引擎控制。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 局限

数据目录和授权凭证是治理流程演示，不包含真实数据下载、加密或机构身份联邦。
