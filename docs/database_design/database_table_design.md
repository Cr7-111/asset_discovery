# 数据库表结构设计

当前系统数据库共包含 10 张核心业务表，具体如下。

| 序号 | 表名 | 表含义 |
| --- | --- | --- |
| 1 | `user_account` | 用户账号表 |
| 2 | `asset` | 资产基础信息表 |
| 3 | `asset_analysis` | 资产类型分析表 |
| 4 | `asset_tag` | 资产标签表 |
| 5 | `risk_result` | 风险评估结果表 |
| 6 | `asset_ai_analysis` | AI 智能分析结果表 |
| 7 | `asset_ml_analysis` | 机器学习漏洞情报分析表 |
| 8 | `discovery_run` | 资产发现任务表 |
| 9 | `asset_discovery_record` | 资产发现记录表 |
| 10 | `asset_validation_record` | 资产验证记录表 |

## 表 4-1 user_account 用户账号表

| 列名 | 字段含义 | 数据类型 | 字段类型 | 长度 | 是否为空 | 默认值 |
| --- | --- | --- | --- | --- | --- | --- |
| id | 用户 ID | int unsigned | int |  | NO | 自增 |
| username | 用户名 | varchar(64) | varchar | 64 | NO |  |
| password_hash | 加密密码 | varchar(255) | varchar | 255 | NO |  |
| display_name | 显示名称 | varchar(100) | varchar | 100 | YES | NULL |
| avatar_url | 账号头像 | longtext | longtext |  | YES | NULL |
| role | 角色 | varchar(32) | varchar | 32 | NO | user |
| is_active | 是否启用 | tinyint(1) | tinyint | 1 | NO | 1 |
| created_at | 创建时间 | datetime | datetime |  | NO | CURRENT_TIMESTAMP |
| updated_at | 更新时间 | datetime | datetime |  | NO | CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP |
| last_login_at | 最后登录时间 | datetime | datetime |  | YES | NULL |

约束说明：`id` 为用户账号表主键，采用自增方式生成；`username` 设置唯一约束，用于保证登录用户名不重复；`avatar_url` 使用 `longtext` 类型保存头像地址或头像数据，避免普通 URL 或 Base64 数据超过固定长度限制。

## 表 4-2 asset 资产基础信息表

| 列名 | 字段含义 | 数据类型 | 字段类型 | 长度 | 是否为空 | 默认值 |
| --- | --- | --- | --- | --- | --- | --- |
| asset_id | 资产 ID | int unsigned | int |  | NO | 自增 |
| domain | 域名 | varchar(255) | varchar | 255 | NO |  |
| ip | IP 地址 | varchar(45) | varchar | 45 | YES | NULL |
| port | 端口 | smallint unsigned | smallint |  | YES | 80 |
| status_code | HTTP 状态码 | smallint unsigned | smallint |  | YES | NULL |
| title | 页面标题 | varchar(512) | varchar | 512 | YES | NULL |
| server | 服务信息 | varchar(255) | varchar | 255 | YES | NULL |
| first_seen | 首次发现时间 | datetime | datetime |  | NO | CURRENT_TIMESTAMP |
| last_seen | 最近发现时间 | datetime | datetime |  | NO | CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP |

约束说明：`asset_id` 为资产基础信息表主键，采用自增方式生成；系统通过 `domain`、`ip`、`port` 三个字段建立唯一约束，用于避免同一资产入口重复入库；`last_seen` 用于记录资产最近一次被发现或更新的时间。

## 表 4-3 asset_ml_analysis 机器学习漏洞情报分析表

| 列名 | 字段含义 | 数据类型 | 字段类型 | 长度 | 是否为空 | 默认值 |
| --- | --- | --- | --- | --- | --- | --- |
| id | 分析 ID | int unsigned | int |  | NO | 自增 |
| asset_id | 资产 ID | int unsigned | int |  | NO |  |
| component | 组件名称 | varchar(120) | varchar | 120 | YES | NULL |
| component_confidence | 组件置信度 | smallint | smallint |  | NO | 0 |
| match_evidence | 匹配证据 | json | json |  | YES | NULL |
| matched_cves | 匹配 CVE | json | json |  | YES | NULL |
| severity_counts | 严重性统计 | json | json |  | YES | NULL |
| ml_risk_score | 机器学习风险分值 | tinyint unsigned | tinyint |  | NO | 0 |
| ml_risk_level | 机器学习风险等级 | varchar(16) | varchar | 16 | NO | low |
| weak_points | 薄弱点 | json | json |  | YES | NULL |
| explanation | 分析说明 | text | text |  | YES | NULL |
| disclaimer | 免责声明 | text | text |  | YES | NULL |
| model_name | 模型名称 | varchar(120) | varchar | 120 | YES | NULL |
| created_at | 创建时间 | datetime | datetime |  | NO | CURRENT_TIMESTAMP |
| updated_at | 更新时间 | datetime | datetime |  | NO | CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP |

约束说明：`id` 为机器学习漏洞情报分析表主键，采用自增方式生成；`asset_id` 是关联 `asset` 表的资产编号，不是自增主键；系统为 `asset_id` 设置唯一约束，保证每个资产只有一条最新的机器学习漏洞情报分析结果，并通过外键关联 `asset(asset_id)`。

## asset_analysis 资产类型分析表

| 列名 | 字段含义 | 数据类型 | 字段类型 | 长度 | 是否为空 | 默认值 |
| --- | --- | --- | --- | --- | --- | --- |
| id | 分析 ID | int unsigned | int |  | NO | 自增 |
| asset_id | 资产 ID | int unsigned | int |  | NO |  |
| asset_type | 资产类型 | varchar(64) | varchar | 64 | NO | unknown |
| model_confidence | 模型置信度 | decimal(5,4) | decimal | 5,4 | NO | 0.0000 |
| analysis_time | 分析时间 | datetime | datetime |  | NO | CURRENT_TIMESTAMP |

## asset_tag 资产标签表

| 列名 | 字段含义 | 数据类型 | 字段类型 | 长度 | 是否为空 | 默认值 |
| --- | --- | --- | --- | --- | --- | --- |
| id | 标签 ID | int unsigned | int |  | NO | 自增 |
| asset_id | 资产 ID | int unsigned | int |  | NO |  |
| tag_name | 标签名称 | varchar(64) | varchar | 64 | NO |  |
| tag_source | 标签来源 | varchar(32) | varchar | 32 | NO | rule_engine |
| confidence | 置信度 | decimal(5,4) | decimal | 5,4 | NO | 1.0000 |
| matched_rule | 命中规则 | varchar(512) | varchar | 512 | YES | NULL |
| created_at | 创建时间 | datetime | datetime |  | NO | CURRENT_TIMESTAMP |

## risk_result 风险评估结果表

| 列名 | 字段含义 | 数据类型 | 字段类型 | 长度 | 是否为空 | 默认值 |
| --- | --- | --- | --- | --- | --- | --- |
| id | 风险 ID | int unsigned | int |  | NO | 自增 |
| asset_id | 资产 ID | int unsigned | int |  | NO |  |
| risk_score | 风险分值 | tinyint unsigned | tinyint |  | NO | 0 |
| risk_level | 风险等级 | varchar(16) | varchar | 16 | NO | low |
| score_detail | 评分详情 | text | text |  | YES | NULL |
| suggestions | 修复建议 | text | text |  | YES | NULL |
| assessed_at | 评估时间 | datetime | datetime |  | NO | CURRENT_TIMESTAMP |

## asset_ai_analysis AI 智能分析结果表

| 列名 | 字段含义 | 数据类型 | 字段类型 | 长度 | 是否为空 | 默认值 |
| --- | --- | --- | --- | --- | --- | --- |
| id | 分析 ID | int unsigned | int |  | NO | 自增 |
| asset_id | 资产 ID | int unsigned | int |  | NO |  |
| asset_type | 资产类型 | varchar(100) | varchar | 100 | YES | NULL |
| risk_reason | 风险原因 | text | text |  | YES | NULL |
| weak_points | 薄弱点 | json | json |  | YES | NULL |
| suggestions | 整改建议 | json | json |  | YES | NULL |
| report_summary | 报告摘要 | text | text |  | YES | NULL |
| model_name | 模型名称 | varchar(100) | varchar | 100 | YES | NULL |
| created_at | 创建时间 | datetime | datetime |  | NO | CURRENT_TIMESTAMP |
| updated_at | 更新时间 | datetime | datetime |  | NO | CURRENT_TIMESTAMP |

## discovery_run 资产发现任务表

| 列名 | 字段含义 | 数据类型 | 字段类型 | 长度 | 是否为空 | 默认值 |
| --- | --- | --- | --- | --- | --- | --- |
| id | 任务 ID | bigint unsigned | bigint |  | NO | 自增 |
| domain | 扫描域名 | varchar(255) | varchar | 255 | NO |  |
| mode | 扫描模式 | varchar(16) | varchar | 16 | NO | hybrid |
| status | 任务状态 | varchar(16) | varchar | 16 | NO | completed |
| options_json | 扫描参数 | longtext | longtext |  | YES | NULL |
| summary_json | 结果摘要 | longtext | longtext |  | YES | NULL |
| started_at | 开始时间 | datetime | datetime |  | NO | CURRENT_TIMESTAMP |
| finished_at | 完成时间 | datetime | datetime |  | NO | CURRENT_TIMESTAMP |

## asset_discovery_record 资产发现记录表

| 列名 | 字段含义 | 数据类型 | 字段类型 | 长度 | 是否为空 | 默认值 |
| --- | --- | --- | --- | --- | --- | --- |
| id | 记录 ID | bigint unsigned | bigint |  | NO | 自增 |
| run_id | 任务 ID | bigint unsigned | bigint |  | NO |  |
| stage | 发现阶段 | varchar(16) | varchar | 16 | NO |  |
| subdomain | 子域名 | varchar(255) | varchar | 255 | NO |  |
| ip | IP 地址 | varchar(45) | varchar | 45 | YES | NULL |
| source | 发现来源 | varchar(64) | varchar | 64 | NO |  |
| evidence_text | 证据文本 | text | text |  | YES | NULL |
| urls_json | URL 列表 | longtext | longtext |  | YES | NULL |
| js_endpoints_json | JS 端点列表 | longtext | longtext |  | YES | NULL |
| first_seen | 首次发现时间 | datetime | datetime |  | YES | NULL |
| last_seen | 最近发现时间 | datetime | datetime |  | YES | NULL |
| confidence_score | 置信度分值 | smallint | smallint |  | NO | 0 |
| validation_status | 验证状态 | varchar(16) | varchar | 16 | NO | discovered |
| raw_payload | 原始载荷 | longtext | longtext |  | YES | NULL |
| created_at | 创建时间 | datetime | datetime |  | NO | CURRENT_TIMESTAMP |

## asset_validation_record 资产验证记录表

| 列名 | 字段含义 | 数据类型 | 字段类型 | 长度 | 是否为空 | 默认值 |
| --- | --- | --- | --- | --- | --- | --- |
| id | 验证 ID | bigint unsigned | bigint |  | NO | 自增 |
| run_id | 任务 ID | bigint unsigned | bigint |  | NO |  |
| subdomain | 子域名 | varchar(255) | varchar | 255 | NO |  |
| ip | IP 地址 | varchar(45) | varchar | 45 | YES | NULL |
| port | 端口 | smallint unsigned | smallint |  | YES | NULL |
| scheme | 协议 | varchar(16) | varchar | 16 | YES | NULL |
| status_code | HTTP 状态码 | smallint unsigned | smallint |  | YES | NULL |
| title | 页面标题 | varchar(512) | varchar | 512 | YES | NULL |
| server | 服务信息 | varchar(255) | varchar | 255 | YES | NULL |
| success | 验证是否成功 | tinyint(1) | tinyint | 1 | NO | 0 |
| error_message | 错误信息 | text | text |  | YES | NULL |
| sources_json | 来源列表 | longtext | longtext |  | YES | NULL |
| urls_json | URL 列表 | longtext | longtext |  | YES | NULL |
| js_endpoints_json | JS 端点列表 | longtext | longtext |  | YES | NULL |
| cert_subject | 证书主题 | text | text |  | YES | NULL |
| cert_issuer | 证书颁发者 | text | text |  | YES | NULL |
| first_seen | 首次发现时间 | datetime | datetime |  | YES | NULL |
| last_seen | 最近发现时间 | datetime | datetime |  | YES | NULL |
| confidence_score | 置信度分值 | smallint | smallint |  | NO | 0 |
| validation_status | 验证状态 | varchar(16) | varchar | 16 | NO | discovered |
| raw_payload | 原始载荷 | longtext | longtext |  | YES | NULL |
| validated_at | 验证时间 | datetime | datetime |  | NO | CURRENT_TIMESTAMP |
