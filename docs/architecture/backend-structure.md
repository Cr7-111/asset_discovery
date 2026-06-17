# 后端结构说明

本文档用于说明当前项目的后端分层与重构结果，目标是：
- 逻辑清晰，便于维护
- 对外行为保持兼容，不影响现有功能
- 便于毕业设计答辩展示

## 当前后端目录树

```text
backend/
├─ run.py                          # Flask 启动入口（创建应用、初始化数据库）
└─ app/
   ├─ api/                         # 接口层：只处理请求/响应，不承载复杂业务
   │  ├─ auth_routes.py
   │  ├─ scan_routes.py
   │  ├─ asset_routes.py
   │  ├─ analysis_routes.py
   │  ├─ risk_routes.py
   │  ├─ ai_routes.py
   │  ├─ common.py
   │  └─ __init__.py
   ├─ services/                    # 服务层：业务编排与领域逻辑
   │  ├─ auth_service.py           # 认证相关服务门面
   │  ├─ asset_service.py          # 资产查询/删除服务门面
   │  ├─ scan_service.py           # 扫描执行与落库服务门面
   │  ├─ analysis_service.py       # 规则分析服务
   │  ├─ risk_service.py           # 风险评估服务
   │  ├─ ai_service.py             # AI 风险分析服务
   │  ├─ discovery/                # 资产发现子域
   │  │  ├─ orchestrator.py        # 编排入口（对外 run_* API）
   │  │  ├─ passive.py             # 被动发现链路
   │  │  ├─ active.py              # 主动发现与富化
   │  │  ├─ validation.py          # 验证与融合
   │  │  ├─ shared.py              # 公共工具/常量
   │  │  ├─ subdomain.py           # DNS 枚举
   │  │  ├─ probe.py               # HTTP/HTTPS 探测
   │  │  └─ traffic.py             # 流量线索提取
   │  └─ __init__.py
   ├─ repositories/                # 仓储层：数据库读写实现
   │  ├─ auth_repository.py
   │  ├─ asset_repository.py
   │  ├─ analysis_repository.py
   │  ├─ risk_repository.py
   │  ├─ ai_repository.py
   │  ├─ discovery_repository.py
   │  └─ __init__.py
   ├─ core/
   │  ├─ config.py                 # 配置加载
   │  ├─ db.py                     # 数据库初始化 + 兼容门面
   │  └─ __init__.py
   ├─ models/
   │  ├─ discovery_models.py
   │  └─ __init__.py
   ├─ rules/
   │  ├─ tag_rules.py
   │  ├─ risk_engine.py
   │  ├─ text_classifier.py
   │  └─ __init__.py
   └─ __init__.py
```

## 分层职责（中文）

- `api`：接收前端请求，做参数校验，调用服务层，返回 JSON。
- `services`：承载业务逻辑与流程编排。
- `repositories`：承载 SQL 与数据库读写细节。
- `core`：承载基础设施能力（配置、数据库初始化、连接池）。
- `models`：承载共享数据结构。
- `rules`：承载规则引擎与确定性判断逻辑。

## 典型请求流

```text
前端请求
-> API 路由层（api）
-> 业务服务层（services）
-> 规则层/发现子模块（rules/discovery）
-> 仓储层（repositories）
-> 数据库（MySQL）
-> 返回 JSON
```

## 入口与导入约定

- 后端统一实现路径：`backend/app/...`
- 启动入口建议使用：`backend/run.py`
- API 层优先依赖 `services`，不直接承载复杂业务
- `core/db.py` 作为数据库初始化与兼容门面，底层读写由 `repositories` 承担

## 阶段成果（已完成）

### 第 2 阶段

- 将原先聚合路由拆分为独立路由模块（auth/scan/asset/analysis/risk/ai）
- 保持外部 API 路径不变，前端调用不受影响

### 第 4 阶段

- 将数据库读写按业务拆分到仓储层：
  - `auth_repository.py`
  - `asset_repository.py`
  - `analysis_repository.py`
  - `risk_repository.py`
  - `ai_repository.py`
  - `discovery_repository.py`
- `core/db.py` 收敛为“初始化 + 兼容门面”

### 第 5 阶段

- API 层的 `auth/asset/scan` 路由不再直接导入 `core.db`
- 新增服务门面：
  - `auth_service.py`
  - `asset_service.py`
  - `scan_service.py`
- 分层边界更清晰，更适合展示与后续扩展
