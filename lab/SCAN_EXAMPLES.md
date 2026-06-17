# 靶场扫描说明

本文档用于说明本地靶场的扫描样例，以及扫描后可以发现和展示的资产内容。靶场主域名为 `corp-demo.test`，所有目标均为本地仿真资产，不依赖公网环境。

## 一、扫描样例

### 1. 前端页面扫描

启动靶场后，访问前端页面：

```text
http://localhost:3000
```

使用默认账号登录：

```text
账号：admin
密码：Admin@123456
```

在系统中发起扫描时，目标域名填写：

```text
corp-demo.test
```

推荐选择混合扫描模式。混合扫描会同时启用主动 DNS、被动 DNS、搜索引擎模拟、流量日志解析、网页爬取、JS 提取和证书解析等发现方式，最适合展示系统的多源资产发现能力。

### 2. PowerShell 一键扫描

在项目根目录执行：

```powershell
.\lab\scripts\demo_scan.ps1
```

该脚本会自动完成以下操作：

1. 使用默认管理员账号登录后端接口。
2. 读取 `lab/data/payloads/hybrid_scan.json` 中的扫描参数。
3. 调用 `/api/scan` 接口发起一次完整的混合扫描。
4. 将扫描结果以 JSON 形式输出到终端。

### 3. 接口扫描样例

如果需要直接调用接口，可以先登录：

```powershell
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

$loginBody = @{
  username = "admin"
  password = "Admin@123456"
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:5000/api/auth/login" `
  -WebSession $session `
  -ContentType "application/json" `
  -Body $loginBody
```

再发起混合扫描：

```powershell
$scanBody = Get-Content ".\lab\data\payloads\hybrid_scan.json" -Raw

Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:5000/api/scan" `
  -WebSession $session `
  -ContentType "application/json" `
  -Body $scanBody
```

### 4. 混合扫描参数说明

`lab/data/payloads/hybrid_scan.json` 是默认扫描样例，主要参数如下：

| 参数 | 示例值 | 中文说明 |
| --- | --- | --- |
| `domain` | `corp-demo.test` | 本次扫描的主域名 |
| `mode` | `hybrid` | 使用混合扫描模式 |
| `nameservers` | `["172.28.0.53"]` | 使用靶场内 CoreDNS 服务器解析域名 |
| `ports` | `[[80, "http"], [443, "https"]]` | 探测 HTTP 和 HTTPS 服务 |
| `enable_passive_dns` | `true` | 启用伪被动 DNS 数据源 |
| `enable_search` | `true` | 启用伪搜索引擎结果解析 |
| `enable_traffic_sniff` | `true` | 启用流量日志资产提取 |
| `enable_crawl` | `true` | 启用网页爬取 |
| `enable_js_extract` | `true` | 启用 JS 中资产线索提取 |
| `enable_certificate_parse` | `true` | 启用证书 SAN 域名解析 |
| `traffic_log_path` | `/opt/lab-data/traffic/demo_traffic.log` | 靶场内置流量日志路径 |

## 二、可扫描到的资产

靶场内置的真实存活资产清单位于：

```text
lab/data/ground_truth/ground_truth.json
```

扫描 `corp-demo.test` 后，理论上可以发现以下资产。

| 域名 | 资产含义 | 主要发现来源 | 可展示内容 |
| --- | --- | --- | --- |
| `corp-demo.test` | 企业主站入口 | 主动 DNS、网页爬取 | 主域名解析、主页可访问 |
| `www.corp-demo.test` | 官方网站 | 主动 DNS、网页爬取 | 普通 Web 资产发现 |
| `api.corp-demo.test` | API 服务 | 主动 DNS、JS 提取、网页爬取 | API 资产、OpenAPI 文档线索 |
| `admin.corp-demo.test` | 管理后台 | 主动 DNS、网页爬取 | 管理后台标签、登录入口风险 |
| `dev.corp-demo.test` | 开发环境 | 主动 DNS、网页爬取 | 开发环境暴露标签 |
| `docs.corp-demo.test` | 文档站点 | 主动 DNS、网页爬取、搜索引擎 | 文档暴露、搜索结果发现 |
| `jenkins.corp-demo.test` | Jenkins 构建系统 | 主动 DNS、搜索引擎 | 中间件暴露、机器学习漏洞情报分析演示 |
| `manager.corp-demo.test` | 应用管理入口 | 主动 DNS、被动 DNS、搜索引擎、流量日志、证书解析 | Tomcat Manager 指纹、机器学习漏洞情报分析重点演示 |
| `console.corp-demo.test` | 企业控制台 | 被动 DNS、搜索引擎、证书解析 | 被动发现资产、管理入口 |
| `sso.corp-demo.test` | 单点登录系统 | 流量日志、证书解析、JS 提取 | 登录资产、认证入口发现 |
| `secure.corp-demo.test` | 安全访问入口 | 流量日志、证书解析、网页爬取 | 证书 SAN 和流量日志发现 |
| `status.corp-demo.test` | 状态监控页面 | 被动 DNS、搜索引擎、证书解析 | 搜索结果和证书发现 |
| `vpn-gw.corp-demo.test` | VPN 网关 | 流量日志、网页爬取 | 远程访问入口风险 |

## 三、陈旧资产样例

靶场还内置了一个陈旧资产：

| 域名 | 资产状态 | 主要发现来源 | 中文说明 |
| --- | --- | --- | --- |
| `legacy.corp-demo.test` | 不可解析或不可访问 | 被动 DNS | 用于模拟历史遗留资产、陈旧记录或失效子域名 |

该资产通常只能从被动 DNS 数据中被发现，但验证阶段可能无法成功访问。它适合用于展示系统如何区分“发现到的资产线索”和“验证存活的资产”。

## 四、扫描结果中建议展示的内容

完成扫描后，建议重点查看以下结果字段：

| 结果内容 | 中文说明 |
| --- | --- |
| `subdomains_found` | 发现到的子域名数量 |
| `probes_total` | 发起验证探测的总次数 |
| `active_summary` | 主动发现统计结果 |
| `passive_summary` | 被动发现统计结果 |
| `validation_summary` | 存活验证统计结果 |
| `source_stats` | 不同发现来源的贡献数量 |
| `sources` | 单个资产由哪些来源发现 |
| `urls` | 爬取或搜索得到的 URL 线索 |
| `js_endpoints` | JS 文件中提取到的接口或域名线索 |
| `cert_subject` | HTTPS 证书主题 |
| `cert_issuer` | HTTPS 证书颁发者 |

## 五、适合演示的扫描亮点

### 1. 主动 DNS 发现

`www.corp-demo.test`、`api.corp-demo.test`、`admin.corp-demo.test`、`dev.corp-demo.test` 等域名可以通过 DNS 解析直接发现，适合展示主动扫描能力。

### 2. 被动数据发现

`console.corp-demo.test`、`status.corp-demo.test`、`legacy.corp-demo.test` 可以通过伪被动 DNS 或伪搜索引擎发现，适合展示多源资产收集能力。

### 3. 流量日志发现

`sso.corp-demo.test`、`secure.corp-demo.test`、`vpn-gw.corp-demo.test` 来自内置流量日志，适合展示系统可以从历史访问记录中发现资产线索。

### 4. 证书发现

`console.corp-demo.test`、`sso.corp-demo.test`、`secure.corp-demo.test`、`status.corp-demo.test` 等资产可通过证书 SAN 信息补充发现，适合展示 HTTPS 证书中的资产泄露线索。

### 5. 机器学习漏洞情报分析演示

`jenkins.corp-demo.test` 页面标题包含 Jenkins 组件特征。扫描到该资产后，可以先执行资产分析，再执行机器学习漏洞情报分析。系统会尝试识别 Jenkins 组件，并从本地 CVE 知识库中匹配相关漏洞情报，生成机器学习辅助风险分数。

本靶场另外新增了 `manager.corp-demo.test`，专门用于展示机器学习漏洞情报分析模块。该目标表面上是普通企业应用管理入口，页面标题中包含 `Apache Tomcat Manager Login /manager/html` 指纹。扫描到该资产后，机器学习模块能够识别出 `Apache Tomcat` 组件，并基于本地 CVE 知识库生成风险分析结果。

推荐演示流程：

1. 扫描 `corp-demo.test`。
2. 在资产列表中找到 `manager.corp-demo.test`。
3. 执行资产分析，观察是否出现 `middleware_exposed`、`admin_panel` 等标签。
4. 执行机器学习漏洞情报分析。
5. 查看组件识别结果、匹配 CVE、严重等级统计和机器学习风险分值。

## 六、机器学习分析靶标新增配置

为体现机器学习分析模块的作用，靶场中新增了一个不影响原有资产的扫描目标：

```text
manager.corp-demo.test
```

该目标用于模拟企业内部应用管理入口。它不是实际部署的漏洞服务，而是由 Nginx 承载的静态页面，用于提供可识别的 Tomcat Manager 组件指纹，便于系统完成“资产发现 -> 资产分析 -> 机器学习漏洞情报分析”的演示闭环。

### 1. 新增文件与配置

| 配置文件 | 新增内容 | 中文说明 |
| --- | --- | --- |
| `lab/sites/manager/index.html` | 新增管理入口页面 | 页面标题包含 Tomcat Manager 指纹 |
| `lab/compose.yaml` | 新增 `manager` 服务 | Docker 靶场中新增应用管理入口容器 |
| `lab/compose.host.yaml` | 新增 `manager` 服务 | 宿主机模式下同步新增目标 |
| `lab/edge/nginx.conf` | 新增 Host 转发 | `manager.corp-demo.test` 转发到 `manager` 服务 |
| `lab/edge/nginx.host.conf` | 新增 Host 转发 | 宿主机模式同步转发 |
| `lab/dns/zones/corp-demo.test.db` | 新增 DNS 记录 | `manager` 解析到靶场边缘代理 |
| `lab/dns/zones/corp-demo.host.db` | 新增 DNS 记录 | 宿主机模式下解析到 `127.0.0.1` |
| `lab/intel-api/app.py` | 新增被动 DNS 与搜索结果 | 使混合扫描可从被动数据中发现该资产 |
| `lab/intel-nginx/default.conf` | 新增宿主机模式情报结果 | 宿主机情报服务同步返回该资产 |
| `lab/data/traffic/demo_traffic.log` | 新增访问日志线索 | 使流量日志解析能够发现该资产 |
| `lab/data/ground_truth/ground_truth.json` | 新增真实资产记录 | 用于统计发现率和演示对照 |
| `lab/cert-init/openssl.cnf` | 新增证书 SAN | 证书解析可补充发现该资产 |

### 2. 新目标扫描样例

完整演示仍然建议扫描主域名：

```text
corp-demo.test
```

推荐使用混合扫描参数：

```powershell
.\lab\scripts\demo_scan.ps1
```

也可以在前端页面中手动发起扫描：

```text
目标域名：corp-demo.test
扫描模式：hybrid
```

混合扫描完成后，应在结果中看到：

```text
manager.corp-demo.test
```

### 3. 预期发现来源

`manager.corp-demo.test` 设计为可被多个来源发现，便于演示多源融合效果。

| 发现来源 | 预期结果 | 中文说明 |
| --- | --- | --- |
| 主动 DNS | 可以发现 | DNS 区域文件中存在 `manager` 记录 |
| 被动 DNS | 可以发现 | 伪被动 DNS 情报返回该域名 |
| 搜索引擎 | 可以发现 | 伪搜索页面包含该域名链接 |
| 流量日志 | 可以发现 | `demo_traffic.log` 中包含该域名访问记录 |
| 证书解析 | 重建证书后可发现 | 证书 SAN 配置中包含该域名 |
| HTTP/HTTPS 验证 | 可以访问 | 由边缘代理转发到新增 `manager` 站点 |

### 4. 资产分析预期结果

扫描到 `manager.corp-demo.test` 后，执行资产分析模块，预期可命中以下标签：

| 标签 | 命中原因 |
| --- | --- |
| `admin_panel` | 域名前缀 `manager` 具有管理后台特征 |
| `login_page` | 页面标题包含 `Login` 登录特征 |
| `middleware_exposed` | 页面标题包含 `Tomcat` 中间件组件特征 |

### 5. 机器学习分析预期结果

对 `manager.corp-demo.test` 对应资产执行机器学习漏洞情报分析后，预期结果如下：

| 结果字段 | 预期值或效果 | 中文说明 |
| --- | --- | --- |
| `component` | `Apache Tomcat` | 识别出 Tomcat 组件 |
| `component_confidence` | 大于或等于 60 | 达到 CVE 情报匹配阈值 |
| `match_evidence` | 包含标题命中 Tomcat、manager/html 等证据 | 说明组件识别依据 |
| `matched_cves` | 存在匹配记录 | 从本地 CVE 知识库中匹配 Tomcat 相关漏洞 |
| `severity_counts` | 包含 HIGH、CRITICAL 等统计 | 体现模型对 CVE 严重等级的预测 |
| `ml_risk_score` | 中高分值 | 根据严重等级数量和组件置信度计算 |
| `ml_risk_level` | `medium`、`high` 或 `critical` | 取决于匹配 CVE 的严重等级分布 |
| `weak_points` | 远程代码执行、认证绕过、信息泄露等 | 从 CVE 描述中归纳薄弱点 |
| `explanation` | 说明识别到 Tomcat 并匹配 CVE 情报 | 用于前端展示和论文说明 |

### 6. 推荐展示顺序

1. 使用混合扫描扫描 `corp-demo.test`。
2. 在资产列表中找到 `manager.corp-demo.test`。
3. 查看该资产的发现来源，重点展示主动 DNS、被动 DNS、搜索引擎和流量日志来源。
4. 执行资产分析，展示 `admin_panel`、`login_page`、`middleware_exposed` 标签。
5. 执行机器学习漏洞情报分析。
6. 展示组件识别结果 `Apache Tomcat`。
7. 展示匹配 CVE、严重等级统计、机器学习风险分数和分析说明。

### 7. 重新启动靶场

新增靶标后，需要重新构建并启动靶场：

```powershell
docker compose -f lab/compose.yaml up -d --build
```

如果需要让证书 SAN 也包含 `manager.corp-demo.test`，建议重建证书卷：

```powershell
docker compose -f lab/compose.yaml down -v
docker compose -f lab/compose.yaml up -d --build
```

第一条命令会删除靶场卷数据，包括 MySQL 数据和证书卷；如果需要保留数据库数据，可只重新生成证书相关内容。

## 七、注意事项

1. 靶场域名为本地模拟域名，不能直接在公网 DNS 中解析。
2. 使用 Docker Compose 完整靶场时，后端容器内部会使用 `172.28.0.53` 作为 DNS。
3. 默认关闭公网证书透明日志查询，避免答辩或演示时受公网服务影响。
4. 如果扫描结果缺少部分资产，应先确认靶场容器是否全部启动成功。
5. 如果需要验证真实发现率，可将扫描结果与 `ground_truth.json` 对照。
