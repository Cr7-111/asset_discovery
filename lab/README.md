# Docker Compose 靶场

这套靶场面向你的“多源资产发现与风险评估系统”答辩演示，目标是同时满足三件事：

- 足够真实：包含 DNS、HTTP/HTTPS、多站点、搜索页、被动 DNS、流量样本
- 足够稳定：全部本地化，避免公网 API 和公网搜索结果波动
- 可量化：内置 `ground_truth.json`，可以做发现率和误报率评估

## 拓扑

- `db`：MySQL，承载你的系统业务数据
- `backend`：当前 Flask 后端
- `frontend`：当前 Vue 前端
- `dns`：CoreDNS，作为 `corp-demo.test` 的权威 DNS
- `edge`：统一入口，处理所有 `corp-demo.test` 子域名的 HTTP/HTTPS 请求
- `intel`：伪被动 DNS + 伪搜索页面
- `www/admin/api/dev/docs/jenkins/console/sso`：仿真资产站点

其中 `secure.corp-demo.test`、`status.corp-demo.test`、`vpn-gw.corp-demo.test` 不单独起容器，而是由 `edge` 转发到已有站点，用于制造“证书 SAN、被动日志、搜索结果才会浮现的资产”。

## 为什么这套结构适合你的项目

它能覆盖你代码里的核心发现链路：

- 主动发现：`active_dns` + `probe_targets`
- 被动发现：`passive_dns`、`search_engine`、`traffic_sniff`
- 验证增强：`web_crawl`、`js_extract`、`certificate`

并且能区分：

- 主动容易发现的资产：`www/api/admin/dev/docs/jenkins`
- 被动更容易发现的资产：`console/status`
- 流量和证书更容易发现的资产：`sso/secure/vpn-gw`
- 历史残留或陈旧资产：`legacy`

## 启动

在仓库根目录执行：

```powershell
docker compose -f lab/compose.yaml up -d --build
```

启动后：

- 前端：`http://localhost:3000`
- 后端：`http://localhost:5000`
- MySQL 映射：`localhost:3307`
- DNS 调试端口：`localhost:1053`
- 反向代理调试端口：`localhost:8088` / `https://localhost:8448`

## 一键演示扫描

PowerShell：

```powershell
.\lab\scripts\demo_scan.ps1
```

它会：

1. 登录后端
2. 读取 [hybrid_scan.json](/c:/Users/33431/Desktop/asset_discovery/lab/data/payloads/hybrid_scan.json:1)
3. 发起一次完整的 `hybrid` 扫描

## 推荐答辩演示顺序

1. 打开前端 `http://localhost:3000`
2. 登录默认账号 `admin / Admin@123456`
3. 发起一次 `corp-demo.test` 的扫描
4. 展示结果里的：
   - `active_summary`
   - `passive_summary`
   - `validation_summary`
   - 某个资产的 `sources`
   - 某个资产的 `js_endpoints`
   - 某个资产的 `cert_subject` / `cert_issuer`
5. 对照 [ground_truth.json](/c:/Users/33431/Desktop/asset_discovery/lab/data/ground_truth/ground_truth.json:1) 说明发现率

## 实验建议

建议至少做三组实验，每组跑 3 次取平均：

- `mode=active`
- `mode=passive`
- `mode=hybrid`

建议统计四类指标：

- 发现率：发现到的真实资产 / `ground_truth` 中 live assets
- 误报率：结果中不存在于 `ground_truth` 的资产比例
- 存活验证率：有响应资产 / 已发现资产
- 分源贡献：各 `source_stats` 的发现数量

## 这套靶场如何对应到真实场景

- `dns` 模拟企业域名和子域名解析
- `edge + 多站点` 模拟真实对外业务入口
- `intel` 模拟被动 DNS 平台与搜索引擎结果页
- `traffic/demo_traffic.log` 模拟办公网或出口设备采集到的历史访问线索
- 统一 SAN 证书模拟“证书里泄露更多资产名”的常见情况

## 注意事项

- 这套本地靶场默认关闭 `ct_log`，因为你答辩现场不应该依赖公网 `crt.sh`
- 如果你还要做论文里的“真实世界补充实验”，建议另外选一个你控制的小域名单独跑一组公网实验
- `legacy.corp-demo.test` 是故意保留的陈旧资产，用来验证被动发现后的失败探测与低可信度场景

