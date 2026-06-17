# 靶场拓扑图与数据流说明

这份文档用于答辩展示，回答两个问题：

- 靶场由哪些组件组成
- 资产发现的数据是如何在系统中流动的

## 拓扑图

```text
                               Host Machine
--------------------------------------------------------------------------------
 Browser
   |
   |  http://localhost:3000
   v
+-------------------+            http://backend:5000/api
| frontend          | ----------------------------------------------+
| Vue + Vite        |                                               |
| asset-lab-frontend|                                               |
+-------------------+                                               |
                                                                    v
                                                          +-------------------+
                                                          | backend           |
                                                          | Flask app         |
                                                          | asset-lab-backend |
                                                          +---------+---------+
                                                                    |
                           uses DNS 172.28.0.53                     | stores scan / asset / risk
                                                                    v
                                                          +-------------------+
                                                          | db                |
                                                          | MySQL 8.4         |
                                                          | asset-lab-db      |
                                                          +-------------------+


 Docker Network: lab_net (172.28.0.0/24)
--------------------------------------------------------------------------------

                         +-------------------+
                         | dns               |
                         | CoreDNS           |
                         | 172.28.0.53       |
                         +---------+---------+
                                   |
                                   | resolves *.corp-demo.test
                                   v
                         +-------------------+
                         | edge              |
                         | Nginx reverse proxy
                         | 172.28.0.10       |
                         +----+----+----+----+-------------------------------+
                              |    |    |    |                               |
                              |    |    |    |                               |
                              v    v    v    v                               v
                           +----+ +----+ +----+ +----+      +----------------------+
                           |www | |api | |dev | |docs| ...  | admin / jenkins /    |
                           +----+ +----+ +----+ +----+      | console / sso        |
                                                             +----------------------+

                         +-------------------+
                         | intel             |
                         | fake passive DNS  |
                         | fake search page  |
                         | 172.28.0.40       |
                         +-------------------+

                         +-------------------+
                         | cert-init         |
                         | self-signed cert  |
                         | SAN for many FQDN |
                         +-------------------+
```

## 域名与服务映射

```text
corp-demo.test            -> www
www.corp-demo.test        -> www
api.corp-demo.test        -> api
admin.corp-demo.test      -> admin
dev.corp-demo.test        -> dev
docs.corp-demo.test       -> docs
jenkins.corp-demo.test    -> jenkins
console.corp-demo.test    -> console
sso.corp-demo.test        -> sso
secure.corp-demo.test     -> sso      (用来模拟证书和被动发现)
status.corp-demo.test     -> docs     (用来模拟搜索和被动发现)
vpn-gw.corp-demo.test     -> sso      (用来模拟流量线索)
intel.corp-demo.test      -> intel
search.corp-demo.test     -> intel
legacy.corp-demo.test     -> 不存在真实服务，只用于陈旧资产验证
```

## 数据流说明

### 1. 基础设施启动流

```text
docker compose up
  -> cert-init 生成 SAN 证书
  -> dns 加载 corp-demo.test 区域
  -> edge 加载证书并按 Host 转发
  -> 各业务站点启动
  -> intel 启动伪被动情报接口
  -> db 启动
  -> backend 启动并连接 db
  -> frontend 启动并代理 /api 到 backend
```

这一段主要解决“靶场如何被建设起来”：

- `cert-init` 先生成一张包含多个子域名 SAN 的证书
- `dns` 负责把 `*.corp-demo.test` 解析到 `edge`
- `edge` 再根据 `Host` 头把流量转发到具体站点
- `backend` 的容器 DNS 指向 `172.28.0.53`，因此主动探测时会真正走靶场 DNS

### 2. 主动发现数据流

```text
User / demo script
  -> POST /api/scan
  -> backend.run_multi_source_scan()
  -> active discovery
  -> backend 向 dns 查询 corp-demo.test 子域名
  -> 获得解析结果后，对目标发起 HTTP/HTTPS 探测
  -> 请求进入 edge
  -> edge 按域名转发到 www/api/admin/dev/... 站点
  -> backend 收集状态码、标题、Server、URL
```

这条链路验证的是：

- 主动 DNS 枚举是否能发现子域名
- 存活探测是否能正确访问目标
- 标题、端口、协议、Server 等验证字段是否能被提取

### 3. 被动 DNS 与搜索引擎数据流

```text
backend
  -> 请求 http://intel.corp-demo.test/hostsearch/?q=corp-demo.test
  -> intel 返回伪 passive DNS 记录
  -> backend 合并 passive_dns 来源

backend
  -> 请求 http://search.corp-demo.test/search?q=...
  -> intel 返回带链接的 HTML 搜索结果页
  -> backend 解析链接，提取 search_engine 来源资产
```

这条链路验证的是：

- 被动 DNS 来源能否发现资产
- 搜索引擎 HTML 结果页能否被解析
- 不同来源是否能被正确合并到同一个目标记录

### 4. 流量日志被动发现数据流

```text
lab/data/traffic/demo_traffic.log
  -> 挂载到 backend 容器 /opt/lab-data/traffic/demo_traffic.log
  -> backend 读取 traffic_log_path
  -> 从 dns_query / sni / host / referer / url 中提取资产名
  -> 合并到 traffic_sniff 来源
```

这条链路验证的是：

- 系统是否能从历史流量文本中还原资产
- 是否能识别 DNS、SNI、Host、URL、Referer 等多种证据

### 5. 爬虫、JS 接口提取与证书解析数据流

```text
backend probe 成功
  -> 抓取页面 HTML
  -> 从 a/link/script/form 中发现更多 URL
  -> 拉取 JS 文件
  -> 提取 /api /graphql /swagger 等接口路径
  -> 对 HTTPS 站点读取证书
  -> 从 SAN 中扩展更多子域名
```

这条链路验证的是：

- `web_crawl` 是否能从页面链接扩展资产
- `js_extract` 是否能从 JS 中提取接口端点
- `certificate` 是否能从 SAN 中发现额外子域名

### 6. 融合、入库与展示数据流

```text
多源结果
  -> backend 融合为 TargetRecord
  -> 计算 confidence_score / validation_status
  -> 写入 discovery_run / asset_discovery_record / asset_validation_record
  -> upsert 到 asset
  -> frontend 查询并展示 active_summary / passive_summary / validation_summary
```

这里是答辩里最值得强调的部分：

- 不是单一来源发现资产
- 而是多源证据在同一记录上累积
- 最终通过 `confidence_score` 和 `validation_status` 体现“可信度提升”

## 建议的答辩讲解顺序

```text
1. 先讲拓扑：系统、DNS、反向代理、仿真站点、被动情报源
2. 再讲主动发现：DNS 枚举 -> HTTP/HTTPS 探测
3. 再讲被动发现：被动 DNS、搜索结果、流量日志
4. 再讲验证增强：爬虫、JS 提取、证书 SAN
5. 最后讲融合入库：可信度评分、验证状态、前端可视化
```

## 一句话版本

```text
这套靶场本质上是：
“一个本地企业域名空间 + 多个仿真业务站点 + 多个被动情报源 + 你的资产发现系统本身”
共同组成的一套可复现资产发现实验环境。
```

