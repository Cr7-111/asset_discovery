[README.md](https://github.com/user-attachments/files/29042801/README.md)
# 互联网资产发现与风险评估系统

本项目是一个面向互联网资产治理场景的资产发现与风险评估系统，支持主动发现、被动发现、资产存活验证、规则风险评估、机器学习漏洞严重性分类以及大模型辅助整改建议。系统采用前后端分离架构，后端基于 Flask 和 MySQL，前端基于 Vue 3、Element Plus 和 ECharts。

## 功能概览

- 主动资产发现：通过 DNS 枚举、端口探测、HTTP/HTTPS 探测等方式发现目标域名下的可访问资产。
- 被动资产发现：结合被动 DNS、搜索结果、流量日志、证书信息等线索补充主动扫描难以覆盖的资产。
- 多源融合验证：对不同来源发现的域名、IP、端口、标题、服务指纹和证书信息进行融合，并记录来源证据。
- 风险评估：基于资产类型、服务暴露、状态码、标签规则等信息生成风险分值、风险等级和处置建议。
- 机器学习分析：基于 NVD/CVE 数据构建漏洞严重性分类模型，对逻辑回归、线性 SVM、随机森林等模型进行对比。
- 大模型辅助整改：调用大模型接口生成资产风险原因、薄弱点分析、整改建议和摘要说明。
- 可视化管理：提供资产列表、资产详情、风险列表、仪表盘、用户管理等前端页面。

## 技术栈

后端：

- Python 3
- Flask
- MySQL
- scikit-learn
- pandas / numpy
- requests / dnspython / BeautifulSoup

前端：

- Vue 3
- Vite
- Element Plus
- ECharts
- Axios

实验环境：

- Docker Compose
- CoreDNS
- Nginx
- 本地模拟靶场 `corp-demo.test`

## 目录结构

```text
asset_discovery/
├── backend/                 # Flask 后端接口、服务层、数据访问层
├── frontend/                # Vue 前端项目
├── data/                    # 训练样本和 CVE 数据，部分大文件不纳入 Git
├── docs/                    # 数据库设计、模型评估和测试材料
├── lab/                     # 本地靶场和 Docker Compose 演示环境
├── models/                  # 机器学习模型文件，pkl 大文件不纳入 Git
├── tools/                   # CVE 数据抽取、模型训练脚本
├── test/                    # 后端单元测试和接口测试
├── .env.example             # 环境变量示例
├── requirements_final.txt   # Python 依赖
└── README.md
```

## 环境准备

### 1. 克隆项目

```powershell
git clone https://github.com/Cr7-111/asset_discovery.git
cd asset_discovery
```

### 2. 配置后端环境

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements_final.txt
```

复制环境变量示例文件：

```powershell
copy .env.example .env
```

根据本地环境修改 `.env`，常用配置如下：

```env
AI_API_KEY=your_deepseek_api_key_here
AI_BASE_URL=https://api.deepseek.com/v1
AI_MODEL=deepseek-chat
AI_TIMEOUT=30
AI_USE_ENV_PROXY=false

MYSQL_HOST=localhost
MYSQL_PORT=3307
MYSQL_USER=root
MYSQL_PASSWORD=password
MYSQL_DATABASE=asset_discovery
```

### 3. 配置前端环境

```powershell
cd frontend
npm install
cd ..
```

## 启动方式

### 方式一：使用本地靶场环境

如果需要完整演示资产发现流程，推荐使用 `lab` 目录下的 Docker Compose 环境：

```powershell
docker compose -f lab/compose.yaml up -d --build
```

默认访问地址：

- 前端：http://localhost:3000
- 后端：http://localhost:5000
- MySQL：localhost:3307
- 默认账号：admin
- 默认密码：Admin@123456

### 方式二：分别启动前后端

启动后端：

```powershell
.\venv\Scripts\activate
python -m backend.run
```

启动前端：

```powershell
cd frontend
npm run dev
```

## 核心流程

1. 用户输入目标域名并选择扫描模式：`active`、`passive` 或 `hybrid`。
2. 主动发现模块执行 DNS 枚举、端口探测、Web 探测等任务。
3. 被动发现模块从被动 DNS、搜索结果、流量日志和证书线索中补充资产。
4. 融合验证模块对多源结果去重、归并和存活验证。
5. 资产入库后，系统根据规则引擎生成资产标签和风险评分。
6. 机器学习模块结合 CVE 数据生成漏洞情报辅助分析。
7. 大模型模块根据资产画像、风险等级和弱点信息生成整改建议。
8. 前端通过仪表盘、列表和详情页展示资产、风险、模型分析和整改建议。

## 机器学习模型对比

项目中对三类模型进行了漏洞严重性分类实验，评估结果保存在 `docs/ml_eval/`。

| 模型 | 准确率 | Macro F1 | Weighted F1 | 训练耗时 |
| --- | ---: | ---: | ---: | ---: |
| Logistic Regression | 0.9512 | 0.9226 | 0.9521 | 41.21s |
| Linear SVM | 0.9279 | 0.9096 | 0.9277 | 50.84s |
| Random Forest | 0.9697 | 0.9544 | 0.9698 | 153.83s |

从结果看，随机森林在准确率和 F1 指标上表现最好，但训练耗时更长，模型文件也更大；逻辑回归训练速度较快，整体效果稳定；线性 SVM 在当前数据集上的综合指标略低。

## 测试

运行后端测试：

```powershell
.\venv\Scripts\activate
pytest
```

前端构建检查：

```powershell
cd frontend
npm run build
```

## 大文件说明

以下文件体积较大，不建议直接提交到普通 GitHub 仓库：

- `nvdcve-2.0/`
- `data/cve_knowledge_base.csv`
- `data/cve_samples.csv`
- `models/**/*.pkl`

这些文件已加入 `.gitignore`。如果确实需要托管大文件，建议使用 Git LFS，或者在 README 中提供数据来源和生成脚本说明。

## 安全说明

- 不要提交 `.env`、API Key、数据库密码等敏感信息。
- 系统只应在授权范围内进行资产发现和风险评估。
- 本地靶场用于演示和测试，不依赖真实公网目标。
- 大模型输出的整改建议用于辅助分析，最终处置方案应结合人工复核。

## 项目状态

当前项目主要用于毕业设计、论文答辩和本地演示，已覆盖资产发现、风险评估、机器学习分析、大模型建议和可视化展示等核心功能。
