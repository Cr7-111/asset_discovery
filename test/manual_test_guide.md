# 手工测试说明

## 前置条件
- 后端服务运行在 http://localhost:5000
- 数据库已初始化，asset 表有数据

---

## 测试用例清单

### TC-01 扫描接口
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"domain":"baidu.com"}'
```
**预期**：返回 subdomains_found > 0，saved > 0

---

### TC-02 查询全部资产
```bash
curl http://localhost:5000/api/assets
```
**预期**：返回 {"total": N, "assets": [...]}

---

### TC-03 单条资产智能分析
```bash
# 先获取一个 asset_id，然后：
curl -X POST http://localhost:5000/api/analyze/1
```
**预期**：返回 asset_type、confidence、tags 列表

---

### TC-04 批量分析
```bash
curl -X POST http://localhost:5000/api/analyze/all
```
**预期**：返回 {"total":N,"success":N,"failed":N}

---

### TC-05 单条风险评估
```bash
curl -X POST http://localhost:5000/api/risk/assess/1
```
**预期**：返回 risk_score(0-100)、risk_level、score_detail 列表

---

### TC-06 批量风险评估
```bash
curl -X POST http://localhost:5000/api/risk/assess/all
```
**预期**：所有资产均有评分，批量完成无崩溃

---

### TC-07 查询风险详情
```bash
curl http://localhost:5000/api/risk/1
```
**预期**：返回含 score_detail 数组和 suggestions 建议

---

### TC-08 按风险等级筛选
```bash
curl "http://localhost:5000/api/risks?risk_level=high&page=1&per_page=10"
```
**预期**：返回的 items 中 risk_level 均为 high

---

### TC-09 Dashboard 统计
```bash
curl http://localhost:5000/api/dashboard/stats
```
**预期**：包含 total_assets、level_counts 四个等级的计数

---

### TC-10 模型重训练
```bash
curl -X POST http://localhost:5000/api/model/retrain
curl -X POST http://localhost:5000/api/risk/rf/train
```
**预期**：返回 {"status":"ok","message":"..."}

---

### TC-11 前端 Dashboard
1. 打开 http://localhost:3000/dashboard
2. 检查4个统计卡片数值是否正确
3. 检查风险等级饼图是否渲染
4. 检查资产类型柱状图是否渲染
5. 输入域名点击「开始扫描」，检查 opResult 提示

---

### TC-12 资产列表页
1. 打开 http://localhost:3000/assets
2. 搜索域名，检查表格是否正确过滤
3. 按状态码筛选 200，检查结果
4. 点击行进入详情页

---

### TC-13 资产详情页
1. 在列表页点击任意行
2. 检查「基础信息」tab 数据
3. 点击「重新分析」，等待完成，检查标签是否刷新
4. 点击「重新评估」，检查风险分和整改建议

---

### TC-14 风险列表页
1. 打开 http://localhost:3000/risks
2. 按等级筛选「严重风险」
3. 检查评分进度条颜色（红色）
4. 点击「全量重新评估」

---

### TC-15 异常处理验证
```bash
# 查询不存在的资产
curl http://localhost:5000/api/assets/99999     # 预期 404
curl http://localhost:5000/api/risk/99999       # 预期 404
# 缺参数
curl -X POST http://localhost:5000/api/scan -H "Content-Type: application/json" -d '{}'
# 预期 400 + error 字段
```
