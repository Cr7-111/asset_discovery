<!-- 文件作用：资产详情页面，集中展示基础信息、风险评估、机器学习漏洞情报分析和综合风险研判。 -->
<template>
  <div v-loading="loading">
    <el-page-header @back="$router.back()" style="margin-bottom:20px;">
      <template #content>
        <span style="font-weight:600;">资产详情 #{{ assetId }}</span>
      </template>
    </el-page-header>

    <div v-if="asset" class="detail-grid">
      <!-- 核心展示区：按照“基础信息 -> 风险评估 -> 机器学习分析 -> 综合研判”的优先级展示 -->
        <!-- 基础信息 -->
        <el-card class="base-info-card" shadow="hover" style="margin-bottom:16px;">
          <template #header><span style="font-weight:600;">基础信息</span></template>
          <el-descriptions :column="2" border>
            <el-descriptions-item label="域名">{{ asset.domain }}</el-descriptions-item>
            <el-descriptions-item label="IP">{{ asset.ip || '-' }}</el-descriptions-item>
            <el-descriptions-item label="端口">{{ asset.port }}</el-descriptions-item>
            <el-descriptions-item label="状态码">
              <el-tag :type="statusType(asset.status_code)">{{ asset.status_code || '-' }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="Server" :span="2">{{ asset.server || '-' }}</el-descriptions-item>
            <el-descriptions-item label="页面标题" :span="2">{{ asset.title || '-' }}</el-descriptions-item>
            <el-descriptions-item label="首次发现">{{ asset.first_seen }}</el-descriptions-item>
            <el-descriptions-item label="最近更新">{{ asset.last_seen }}</el-descriptions-item>
          </el-descriptions>
        </el-card>

        <!-- 规则识别结果：作为辅助信息放在核心模块下方，用于解释资产类型和标签来源 -->
        <el-card class="rule-analysis-card" shadow="hover" style="margin-bottom:16px;">
          <template #header>
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <span style="font-weight:600;">规则识别</span>
              <el-button size="small" type="primary" :loading="analyzing" @click="doAnalyze">重新分析</el-button>
            </div>
          </template>
          <div v-if="analysis">
            <el-space class="analysis-summary-row">
              <span>资产类型：</span>
              <el-tag type="primary" size="large">{{ typeLabel(analysis.asset_type) }}</el-tag>
              <span style="color:#909399;">规则命中 {{ (analysis.model_confidence * 100).toFixed(1) }}%</span>
            </el-space>
            <div class="compact-tags-row">
              <span class="compact-tags-title">标签</span>
              <div v-if="tags.length" class="compact-tags-list">
                <el-tooltip v-for="tag in tags" :key="tag.id" :content="tag.matched_rule || tag.tag_source" placement="top">
                  <el-tag :type="tagType(tag.tag_name)" size="small" effect="plain" class="compact-tag">
                    {{ tagLabel(tag.tag_name) }}
                  </el-tag>
                </el-tooltip>
              </div>
              <span v-else class="compact-tags-empty">暂无</span>
            </div>
          </div>
          <el-empty v-else description="暂无分析结果，请点击「重新分析」" />
        </el-card>

        <!-- 综合风险研判：展示 AI/规则综合得到的风险原因、薄弱点和整改建议 -->
        <el-card class="ai-analysis-card" shadow="hover" style="margin-top:16px;">
          <template #header>
            <div class="card-header-enhanced">
              <div>
                <div class="card-title">综合风险研判</div>
                <div class="card-subtitle">结合资产指纹、规则识别和风险结果生成处置判断</div>
              </div>
              <el-button size="small" type="success" :loading="aiAnalyzing" @click="doAiAnalyze">生成分析</el-button>
            </div>
          </template>

          <div v-if="aiAnalysis">
            <div class="ai-hero">
              <div>
                <div class="ai-hero-label">研判结论</div>
                <div class="ai-hero-text">{{ aiAnalysis.report_summary || aiAnalysis.risk_reason || '-' }}</div>
              </div>
              <el-tag type="success" effect="dark" size="large">综合分析</el-tag>
            </div>
            <el-descriptions :column="1" border>
              <el-descriptions-item label="识别类型">{{ aiAnalysis.asset_type || '-' }}</el-descriptions-item>
              <el-descriptions-item label="模型">{{ aiAnalysis.model_name || '-' }}</el-descriptions-item>
              <el-descriptions-item label="风险原因">{{ aiAnalysis.risk_reason || '-' }}</el-descriptions-item>
            </el-descriptions>

            <el-divider>薄弱环节</el-divider>
            <el-tag
              v-for="item in aiWeakPoints"
              :key="item"
              type="danger"
              effect="plain"
              style="margin:0 8px 8px 0;"
            >
              {{ item }}
            </el-tag>

            <el-divider>整改建议</el-divider>
            <el-timeline>
              <el-timeline-item v-for="(item, index) in aiSuggestions" :key="index" type="success" size="small">
                <span style="font-size:13px;">{{ item }}</span>
              </el-timeline-item>
            </el-timeline>
          </div>

          <el-empty v-else description="暂无综合风险研判结果，请点击生成分析" />
        </el-card>

        <!-- 机器学习漏洞情报分析：展示组件识别、严重等级统计和模型辅助风险分 -->
        <el-card class="ml-analysis-card" shadow="hover" style="margin-top:16px;">
          <template #header>
            <div class="card-header-enhanced">
              <div>
                <div class="card-title">机器学习漏洞情报分析</div>
                <div class="card-subtitle">根据组件指纹匹配 CVE 情报，并调用模型预测严重等级</div>
              </div>
              <el-button size="small" type="primary" :loading="mlAnalyzing" @click="doMlAnalyze">生成分析</el-button>
            </div>
          </template>

          <div v-if="mlAnalysis">
            <div class="ml-hero">
              <div>
                <div class="ml-hero-label">识别组件</div>
                <div class="ml-hero-value">{{ mlAnalysis.component || '-' }}</div>
              </div>
              <div>
                <div class="ml-hero-label">机器学习风险分</div>
                <div class="ml-hero-score">{{ mlAnalysis.ml_risk_score ?? 0 }}</div>
              </div>
              <el-tag :type="levelTagType(mlAnalysis.ml_risk_level)" effect="dark" size="large">
                {{ levelLabel(mlAnalysis.ml_risk_level) }}
              </el-tag>
            </div>
            <el-descriptions :column="2" border>
              <el-descriptions-item label="识别组件">{{ mlAnalysis.component || '-' }}</el-descriptions-item>
              <el-descriptions-item label="模型">{{ mlAnalysis.model_name || '-' }}</el-descriptions-item>
              <el-descriptions-item label="组件置信度">{{ mlAnalysis.component_confidence ?? 0 }}</el-descriptions-item>
              <el-descriptions-item label="风险分">{{ mlAnalysis.ml_risk_score ?? 0 }}</el-descriptions-item>
              <el-descriptions-item label="风险等级">
                <el-tag :type="levelTagType(mlAnalysis.ml_risk_level)">
                  {{ levelLabel(mlAnalysis.ml_risk_level) }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="分析说明" :span="2">{{ mlAnalysis.explanation || '-' }}</el-descriptions-item>
            </el-descriptions>

            <el-divider>严重等级统计</el-divider>
            <el-space wrap>
              <el-tag type="info">LOW {{ mlSeverityCounts.LOW || 0 }}</el-tag>
              <el-tag type="warning">MEDIUM {{ mlSeverityCounts.MEDIUM || 0 }}</el-tag>
              <el-tag type="danger">HIGH {{ mlSeverityCounts.HIGH || 0 }}</el-tag>
              <el-tag type="danger" effect="dark">CRITICAL {{ mlSeverityCounts.CRITICAL || 0 }}</el-tag>
            </el-space>

            <el-divider>匹配依据</el-divider>
            <el-timeline>
              <el-timeline-item v-for="(item, index) in mlMatchEvidence" :key="index" type="primary" size="small">
                <span style="font-size:13px;">{{ item }}</span>
              </el-timeline-item>
            </el-timeline>

            <el-divider>薄弱环节</el-divider>
            <el-tag
              v-for="item in mlWeakPoints"
              :key="item"
              type="danger"
              effect="plain"
              style="margin:0 8px 8px 0;"
            >
              {{ item }}
            </el-tag>

            <el-alert
              v-if="mlAnalysis.disclaimer"
              style="margin-top:14px;"
              type="warning"
              :closable="false"
              :title="mlAnalysis.disclaimer"
            />
          </div>

          <el-empty v-else description="暂无机器学习漏洞情报分析结果，请点击生成分析" />
        </el-card>
      <!-- 风险评分：展示规则引擎计算出的分值、等级、命中规则和整改建议 -->
      <el-card class="risk-card" shadow="hover">
          <template #header>
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <span style="font-weight:600;">风险评估</span>
              <el-button size="small" type="danger" :loading="assessing" @click="doAssess">重新评估</el-button>
            </div>
          </template>

          <div v-if="risk">
            <!-- 风险仪表盘 -->
            <div style="text-align:center;padding:16px 0;">
              <div :style="{fontSize:'64px',fontWeight:700,color:levelColor(risk.risk_level)}">
                {{ risk.risk_score }}
              </div>
              <div style="font-size:13px;color:#909399;margin-top:4px;">风险总分（满分100）</div>
              <el-tag :type="levelTagType(risk.risk_level)" size="large" style="margin-top:8px;font-size:16px;padding:0 20px;">
                {{ levelLabel(risk.risk_level) }}
              </el-tag>
            </div>

            <el-divider>评分明细</el-divider>

            <!-- 评分明细 -->
            <div v-for="item in scoreDetail" :key="item.key" style="margin-bottom:10px;">
              <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
                <span style="font-size:13px;">{{ item.description }}</span>
                <el-tag type="danger" size="small">+{{ item.score }}</el-tag>
              </div>
              <el-progress
                :percentage="item.score"
                :stroke-width="8"
                :color="item.score >= 20 ? '#f56c6c' : item.score >= 10 ? '#e6a23c' : '#409eff'"
                :format="() => ''"
              />
            </div>

            <el-divider>整改建议</el-divider>

            <!-- 整改建议 -->
            <el-timeline>
              <el-timeline-item
                v-for="(s, i) in suggestions"
                :key="i"
                type="warning"
                size="small"
              >
                <span style="font-size:13px;">{{ s }}</span>
              </el-timeline-item>
            </el-timeline>
          </div>

          <el-empty v-else description="暂无风险评估结果，请点击「重新评估」" />
      </el-card>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import {
  analyzeAsset,
  assessAsset,
  generateAiAnalysis,
  generateMlAnalysis,
  getAiAnalysis,
  getAnalysis,
  getAsset,
  getMlAnalysis,
  getRisk,
  getTags,
} from '../api/index.js'

const route    = useRoute()
// 从路由参数中读取当前资产编号，后续所有接口调用都围绕该资产展开。
const assetId  = route.params.id
// 页面级加载状态和各模块按钮 loading 状态。
const loading  = ref(true)
const analyzing = ref(false)
const assessing = ref(false)
const aiAnalyzing = ref(false)
const mlAnalyzing = ref(false)
const asset    = ref(null)
const analysis = ref(null)
const tags     = ref([])
const risk     = ref(null)
const aiAnalysis = ref(null)
const mlAnalysis = ref(null)

const scoreDetail = computed(() => {
  // 风险评分明细后端返回数组；这里做类型兜底，避免异常数据影响页面渲染。
  if (!risk.value) return []
  const d = risk.value.score_detail
  return Array.isArray(d) ? d : []
})

const suggestions = computed(() => {
  // 整改建议可能是数组，也可能是换行字符串，统一转换为数组用于时间线展示。
  if (!risk.value?.suggestions) return []
  const s = risk.value.suggestions
  return typeof s === 'string' ? s.split('\n').filter(Boolean) : s
})
const aiWeakPoints = computed(() => Array.isArray(aiAnalysis.value?.weak_points) ? aiAnalysis.value.weak_points : [])
const aiSuggestions = computed(() => Array.isArray(aiAnalysis.value?.suggestions) ? aiAnalysis.value.suggestions : [])
// 机器学习模块的统计、薄弱点和匹配依据均做空值兜底，保证未生成分析时页面不报错。
const mlSeverityCounts = computed(() => mlAnalysis.value?.severity_counts || {})
const mlWeakPoints = computed(() => Array.isArray(mlAnalysis.value?.weak_points) ? mlAnalysis.value.weak_points : [])
const mlMatchEvidence = computed(() => Array.isArray(mlAnalysis.value?.match_evidence) ? mlAnalysis.value.match_evidence : [])

async function loadAll() {
  loading.value = true
  try {
    // 资产详情页一次性加载多个接口，Promise.allSettled 可避免单个模块失败导致整页不可用。
    const [a, an, t, r, ai, ml] = await Promise.allSettled([
      getAsset(assetId),
      getAnalysis(assetId),
      getTags(assetId),
      getRisk(assetId),
      getAiAnalysis(assetId),
      getMlAnalysis(assetId),
    ])
    if (a.status === 'fulfilled')  asset.value    = a.value
    if (an.status === 'fulfilled') analysis.value = an.value
    if (t.status === 'fulfilled')  tags.value     = t.value.tags || []
    if (r.status === 'fulfilled')  risk.value     = r.value
    if (ai.status === 'fulfilled') aiAnalysis.value = ai.value
    if (ml.status === 'fulfilled') mlAnalysis.value = ml.value
  } finally {
    loading.value = false
  }
}

async function doAnalyze() {
  analyzing.value = true
  try {
    // 重新执行资产分析后，立即刷新分析结果和标签列表。
    await analyzeAsset(assetId)
    ElMessage.success('分析完成')
    const [an, t] = await Promise.all([getAnalysis(assetId), getTags(assetId)])
    analysis.value = an; tags.value = t.tags || []
  } finally { analyzing.value = false }
}

async function doAssess() {
  assessing.value = true
  try {
    // 重新评估风险后，只刷新风险模块，避免无关区域闪烁。
    await assessAsset(assetId)
    ElMessage.success('风险评估完成')
    risk.value = await getRisk(assetId)
  } finally { assessing.value = false }
}

async function doAiAnalyze() {
  aiAnalyzing.value = true
  try {
    // 综合风险研判结果由后端生成并保存，前端直接展示返回值。
    aiAnalysis.value = await generateAiAnalysis(assetId)
    ElMessage.success('综合风险研判已生成')
  } finally { aiAnalyzing.value = false }
}

async function doMlAnalyze() {
  mlAnalyzing.value = true
  try {
    // 机器学习分析会触发组件识别、CVE 匹配、模型预测和结果入库。
    mlAnalysis.value = await generateMlAnalysis(assetId)
    ElMessage.success('机器学习漏洞情报分析已生成')
  } finally { mlAnalyzing.value = false }
}

// 辅助函数
function statusType(c) {
  // 根据 HTTP 状态码选择 Element Plus 标签颜色。
  if (!c) return 'info'; if (c < 300) return 'success'; if (c < 400) return 'warning'; return 'danger'
}
function levelColor(l) {
  // 风险分值主视觉颜色，与风险等级保持一致。
  return { low:'#67c23a', medium:'#e6a23c', high:'#f56c6c', critical:'#900' }[l] || '#909399'
}
function levelTagType(l) {
  return { low:'success', medium:'warning', high:'danger', critical:'danger' }[l] || 'info'
}
function levelLabel(l) {
  return { low:'低风险', medium:'中风险', high:'高风险', critical:'严重风险' }[l] || l
}
function typeLabel(t) {
  const m = { web_site:'普通网站', admin_panel:'管理后台', api_service:'API服务',
    dev_test_system:'开发测试', database_service:'数据库', middleware_service:'中间件', unknown:'未知' }
  return m[t] || t
}
function tagLabel(n) {
  const m = { admin_panel:'管理后台', dev_env:'开发环境', test_env:'测试环境',
    login_page:'登录页', api_service:'API服务', api_docs_exposed:'API文档暴露',
    database_exposed:'数据库暴露', default_page:'默认页', directory_listing:'目录遍历',
    middleware_exposed:'中间件暴露', backup_related:'备份相关', high_risk_port:'高危端口' }
  return m[n] || n
}
function tagType(n) {
  const danger = ['database_exposed','high_risk_port','directory_listing']
  const warn   = ['admin_panel','api_docs_exposed','dev_env','test_env','middleware_exposed']
  if (danger.includes(n)) return 'danger'
  if (warn.includes(n))   return 'warning'
  return 'info'
}

onMounted(loadAll)
</script>

<style scoped>
.detail-grid {
  /* 使用两列网格对齐四个核心模块，避免左右栏高度差导致页面混乱。 */
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 16px;
  align-items: stretch;
}

.detail-grid > .el-card {
  margin-top: 0 !important;
  margin-bottom: 0 !important;
}

.base-info-card {
  /* 第一优先级：基础信息。 */
  order: 1;
}

.risk-card {
  /* 第二优先级：风险评估。 */
  order: 2;
  border-top: 3px solid #d45a5a;
}

.ml-analysis-card {
  /* 第三优先级：机器学习漏洞情报分析。 */
  order: 3;
}

.ai-analysis-card {
  /* 第四优先级：综合风险研判。 */
  order: 4;
}

.rule-analysis-card {
  /* 辅助信息：横跨两列展示规则识别和紧凑标签。 */
  order: 5;
  grid-column: 1 / -1;
}

.card-header-enhanced {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
}

.card-title {
  font-size: 16px;
  font-weight: 700;
  color: #1f2d3d;
}

.card-subtitle {
  margin-top: 3px;
  font-size: 12px;
  color: #7a8699;
}

.ai-hero {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 16px 18px;
  margin-bottom: 14px;
  border: 1px solid #d6e6dc;
  border-radius: 8px;
  background: linear-gradient(135deg, #f7fbf8 0%, #eef7f2 100%);
}

.ai-hero-label {
  margin-bottom: 6px;
  font-size: 12px;
  color: #6b778c;
}

.ai-hero-text {
  font-size: 15px;
  line-height: 1.7;
  font-weight: 600;
  color: #263238;
}

.ml-hero {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 150px auto;
  align-items: center;
  gap: 18px;
  padding: 16px 18px;
  margin-bottom: 14px;
  border: 1px solid #dbe7f6;
  border-radius: 8px;
  background: linear-gradient(135deg, #f7f9fd 0%, #eef4fb 100%);
}

.ml-hero-label {
  margin-bottom: 6px;
  font-size: 12px;
  color: #6b778c;
}

.ml-hero-value {
  font-size: 17px;
  font-weight: 700;
  color: #24364b;
}

.ml-hero-score {
  font-size: 34px;
  line-height: 1;
  font-weight: 800;
  color: #2f6fb3;
}

.analysis-summary-row {
  margin-bottom: 12px;
}

.compact-tags-row {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding-top: 10px;
  border-top: 1px solid #edf0f5;
}

.compact-tags-title {
  flex: 0 0 auto;
  padding-top: 2px;
  font-size: 12px;
  color: #7a8699;
}

.compact-tags-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.compact-tag {
  cursor: pointer;
}

.compact-tags-empty {
  font-size: 12px;
  color: #a8abb2;
}

@media (max-width: 1100px) {
  .detail-grid {
    grid-template-columns: 1fr;
  }

  .rule-analysis-card {
    grid-column: auto;
  }
}
</style>
