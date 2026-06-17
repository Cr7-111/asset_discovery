<!-- 文件作用：系统仪表盘与资产发现控制台页面，负责发起扫描并展示扫描统计和发现结果。 -->
<template>
  <div class="dashboard-page">
    <section class="hero-panel glass-card">
      <!-- 顶部概览区：突出系统资产态势和最近扫描结果 -->
      <div class="hero-copy">
        <div class="eyebrow">资产概览</div>
        <h1 class="page-title">互联网暴露面监测</h1>
        <p class="page-subtitle">
          集中查看资产发现、验证结果和风险分布，辅助定位需要优先处理的暴露资产。
        </p>
      </div>
      <div class="hero-metrics">
        <div class="hero-pill">
          <span>来源类型</span>
          <strong>{{ sourceStatsList.length || 0 }}</strong>
        </div>
        <div class="hero-pill accent">
          <span>最近验证</span>
          <strong>{{ lastScan.probes_total || 0 }}</strong>
        </div>
      </div>
    </section>

    <el-row :gutter="18" class="stats-grid">
      <!-- 统计卡片：资产总数、已评估数量、高风险数量和平均风险分 -->
      <el-col :xs="24" :sm="12" :xl="6" v-for="card in statCards" :key="card.label">
        <el-card class="glass-card metric-card" shadow="never">
          <div class="metric-top">
            <div class="metric-icon" :style="{ background: card.bg }">{{ card.icon }}</div>
            <span class="metric-trend">{{ card.helper }}</span>
          </div>
          <div class="metric-label">{{ card.label }}</div>
          <div class="metric-value">{{ card.value }}</div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="18">
      <!-- 图表区：风险分布和资产类型分布，便于快速观察整体态势 -->
      <el-col :xs="24" :lg="12">
        <el-card class="glass-card chart-card" shadow="never">
          <template #header>
            <div class="card-head">
              <span class="section-title">风险分布</span>
              <span class="card-meta">快速查看高风险与严重风险资产数量</span>
            </div>
          </template>
          <div ref="riskPieRef" class="chart-box"></div>
        </el-card>
      </el-col>
      <el-col :xs="24" :lg="12">
        <el-card class="glass-card chart-card" shadow="never">
          <template #header>
            <div class="card-head">
              <span class="section-title">资产类型分布</span>
              <span class="card-meta">按识别出的服务类型进行统计</span>
            </div>
          </template>
          <div ref="typeBarRef" class="chart-box"></div>
        </el-card>
      </el-col>
    </el-row>

    <el-card class="glass-card scan-console" shadow="never">
      <!-- 扫描控制台：输入目标域名、选择模式，并触发扫描/批量分析/批量评估 -->
      <template #header>
        <div class="card-head">
          <span class="section-title">发现控制台</span>
          <span class="card-meta">发起多阶段扫描，并查看被动发现、主动发现与验证结果。</span>
        </div>
      </template>

      <div class="console-grid">
        <div class="console-left">
          <el-input v-model="scanDomainInput" size="large" placeholder="请输入目标域名，例如 example.com" clearable>
            <template #prepend>目标域名</template>
          </el-input>

          <div class="mode-row">
            <div>
              <div class="switch-title">扫描模式</div>
              <div class="switch-desc">选择仅执行被动发现、仅执行主动发现，或采用主动与被动结合的混合模式。</div>
            </div>
            <el-segmented v-model="scanMode" :options="modeOptions" />
          </div>

          <div class="action-row">
            <el-button type="primary" size="large" :loading="scanning" @click="doScan">开始扫描</el-button>
            <el-button type="warning" size="large" :loading="analyzing" @click="doAnalyzeAll">批量分析</el-button>
            <el-button type="danger" size="large" :loading="assessing" @click="doAssessAll">批量评估</el-button>
            <el-button size="large" @click="loadStats">刷新统计</el-button>
          </div>

          <el-alert
            v-if="opResult"
            class="result-alert"
            :title="opResult"
            type="success"
            show-icon
            :closable="false"
          />
        </div>

        <div class="console-right">
          <div class="mini-panel">
            <div class="mini-label">Run ID</div>
            <div class="mini-value mini-value-sm">{{ lastScan.run_id || '-' }}</div>
          </div>
          <div class="mini-panel">
            <div class="mini-label">模式</div>
            <div class="mini-value mini-value-sm">{{ modeLabel(lastScan.mode || scanMode) }}</div>
          </div>
          <div class="mini-panel">
            <div class="mini-label">合并目标</div>
            <div class="mini-value">{{ lastScan.subdomains_found || 0 }}</div>
          </div>
          <div class="mini-panel">
            <div class="mini-label">存活结果</div>
            <div class="mini-value">{{ lastScan.validation_summary?.alive_results || 0 }}</div>
          </div>
        </div>
      </div>

      <div v-if="lastScan.discovery_summary" class="scan-results">
        <!-- 扫描结果区：展示来源统计、分层目标和验证结果 -->
        <div class="run-meta-grid">
          <div class="run-meta-card">
            <div class="run-meta-label">被动发现目标</div>
            <div class="run-meta-value">{{ lastScan.passive_summary?.targets_found || 0 }}</div>
          </div>
          <div class="run-meta-card">
            <div class="run-meta-label">主动发现目标</div>
            <div class="run-meta-value">{{ lastScan.active_summary?.targets_found || 0 }}</div>
          </div>
          <div class="run-meta-card">
            <div class="run-meta-label">发现记录</div>
            <div class="run-meta-value">{{ lastScan.discovery_records_saved || 0 }}</div>
          </div>
          <div class="run-meta-card">
            <div class="run-meta-label">验证记录</div>
            <div class="run-meta-value">{{ lastScan.validation_records_saved || 0 }}</div>
          </div>
        </div>

        <div class="source-tags">
          <el-tag
            v-for="item in sourceStatsList"
            :key="item.source"
            class="source-chip"
            effect="plain"
          >
            {{ sourceLabel(item.source) }} · {{ item.count }}
          </el-tag>
        </div>

        <div class="layer-switch-row">
          <div class="layer-switch-copy">
            <div class="switch-title">分层结果</div>
            <div class="switch-desc">可在合并结果、被动发现、主动发现与验证结果之间切换查看。</div>
          </div>
          <el-segmented v-model="selectedLayer" :options="layerOptions" />
        </div>

        <el-table v-if="selectedLayer !== 'validated'" :data="displayTargets" class="result-table" stripe max-height="460">
          <el-table-column prop="subdomain" label="目标" min-width="220" show-overflow-tooltip />
          <el-table-column label="来源" min-width="220">
            <template #default="{ row }">
              <el-space wrap>
                <el-tag v-for="source in row.sources" :key="source" size="small" :type="sourceTagType(source)">
                  {{ sourceLabel(source) }}
                </el-tag>
              </el-space>
            </template>
          </el-table-column>
          <el-table-column label="IP" min-width="180">
            <template #default="{ row }">{{ (row.ips || []).join(', ') || '-' }}</template>
          </el-table-column>
          <el-table-column label="验证状态" width="120">
            <template #default="{ row }">
              <el-tag size="small" :type="validationTagType(row.validation_status)">
                {{ validationLabel(row.validation_status) }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="分值" width="90">
            <template #default="{ row }">{{ row.confidence_score ?? 0 }}</template>
          </el-table-column>
          <el-table-column label="富化信息" min-width="320">
            <template #default="{ row }">
              <div class="target-url">{{ row.urls?.[0] || '-' }}</div>
              <div class="target-meta">
                JS 接口 {{ row.js_endpoints?.length || 0 }}
                <span v-if="row.cert_subject"> · 证书 {{ row.cert_subject }}</span>
              </div>
            </template>
          </el-table-column>
          <el-table-column label="详情" width="90" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" @click="openTargetDetail(row, selectedLayer)">查看</el-button>
            </template>
          </el-table-column>
        </el-table>

        <el-table v-else :data="validationResults" class="result-table" stripe max-height="460">
          <el-table-column prop="subdomain" label="目标" min-width="220" show-overflow-tooltip />
          <el-table-column prop="ip" label="IP" width="150" />
          <el-table-column prop="scheme" label="协议" width="100" />
          <el-table-column prop="port" label="端口" width="90" />
          <el-table-column prop="status_code" label="HTTP" width="90" />
          <el-table-column label="结果" width="120">
            <template #default="{ row }">
              <el-tag size="small" :type="row.success ? 'success' : 'warning'">
                {{ row.success ? '存活' : '失败' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="来源" min-width="220">
            <template #default="{ row }">
              <el-space wrap>
                <el-tag v-for="source in row.sources || []" :key="source" size="small" :type="sourceTagType(source)">
                  {{ sourceLabel(source) }}
                </el-tag>
              </el-space>
            </template>
          </el-table-column>
          <el-table-column label="分值" width="90">
            <template #default="{ row }">{{ row.confidence_score ?? 0 }}</template>
          </el-table-column>
          <el-table-column label="标题 / 错误" min-width="260" show-overflow-tooltip>
            <template #default="{ row }">{{ row.title || row.error || '-' }}</template>
          </el-table-column>
          <el-table-column label="详情" width="90" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" @click="openTargetDetail(row, 'validated')">查看</el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </el-card>

    <el-drawer v-model="detailVisible" size="46%" :with-header="false">
      <!-- 目标详情抽屉：展示单个发现目标的来源、证据、URL、JS 和证书上下文 -->
      <div v-if="activeTarget" class="drawer-body">
        <div class="drawer-head">
          <div>
            <div class="drawer-title">{{ activeTarget.subdomain }}</div>
            <div class="drawer-subtitle">发现证据与验证上下文</div>
          </div>
          <el-tag type="primary" effect="dark">{{ layerLabel(activeTarget.layer) }}</el-tag>
        </div>

        <el-descriptions :column="1" border class="drawer-block">
          <el-descriptions-item label="Run ID">{{ lastScan.run_id || '-' }}</el-descriptions-item>
          <el-descriptions-item label="IPs">{{ (activeTarget.ips || []).join(', ') || '-' }}</el-descriptions-item>
          <el-descriptions-item label="验证状态">{{ validationLabel(activeTarget.validation_status) }}</el-descriptions-item>
          <el-descriptions-item label="可信度">{{ activeTarget.confidence_score ?? 0 }}</el-descriptions-item>
          <el-descriptions-item label="来源">{{ (activeTarget.sources || []).map(sourceLabel).join(', ') || '-' }}</el-descriptions-item>
          <el-descriptions-item label="证书主题">{{ activeTarget.cert_subject || '-' }}</el-descriptions-item>
          <el-descriptions-item label="证书签发者">{{ activeTarget.cert_issuer || '-' }}</el-descriptions-item>
          <el-descriptions-item label="证书 SAN">{{ (activeTarget.cert_sans || []).join(', ') || '-' }}</el-descriptions-item>
        </el-descriptions>

        <el-divider content-position="left">证据</el-divider>
        <el-timeline class="drawer-block">
          <el-timeline-item
            v-for="(item, index) in activeTarget.evidence || []"
            :key="`${item}-${index}`"
            size="small"
            type="primary"
          >
            {{ item }}
          </el-timeline-item>
          <el-timeline-item v-if="!(activeTarget.evidence || []).length" size="small" type="info">
            当前记录未保存直接证据文本。
          </el-timeline-item>
        </el-timeline>

        <el-divider content-position="left">附加信息</el-divider>
        <el-table :data="detailRows" stripe class="drawer-block">
          <el-table-column prop="kind" label="类型" width="100" />
          <el-table-column prop="value" label="内容" min-width="280" show-overflow-tooltip />
        </el-table>
      </div>
    </el-drawer>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, ref } from 'vue'
import * as echarts from 'echarts'
import { ElMessage } from 'element-plus'
import { analyzeAll, assessAll, getDashboardStats, scanDomain as apiScan } from '../api/index.js'

const stats = ref({})
// 扫描、批量分析和批量评估三个按钮分别维护 loading 状态。
const scanning = ref(false)
const analyzing = ref(false)
const assessing = ref(false)
const scanDomainInput = ref('')
const scanMode = ref('hybrid')
const selectedLayer = ref('merged')
const opResult = ref('')
const riskPieRef = ref(null)
const typeBarRef = ref(null)
const lastScan = ref({})
const detailVisible = ref(false)
const activeTarget = ref(null)

const modeOptions = [
  // 扫描模式与后端 mode 参数保持一致。
  { label: '混合', value: 'hybrid' },
  { label: '被动', value: 'passive' },
  { label: '主动', value: 'active' },
]

const layerOptions = [
  // 分层结果用于区分合并目标、被动来源、主动来源和验证结果。
  { label: '合并', value: 'merged' },
  { label: '被动', value: 'passive' },
  { label: '主动', value: 'active' },
  { label: '验证', value: 'validated' },
]

const defaultScanOptions = {
  // 前端默认开启多源发现能力，保证演示时能展示较完整的发现链路。
  enable_ct: false,
  enable_passive_dns: true,
  enable_traffic_sniff: true,
  enable_search: true,
  enable_icp: true,
  enable_cloud: true,
  enable_crawl: true,
  enable_js_extract: true,
  enable_certificate_parse: true,
}

const statCards = computed(() => [
  // 将后端仪表盘统计转换为卡片配置，模板只负责渲染。
  {
            label: '资产总数',
            value: stats.value.total_assets ?? '-',
    icon: '资',
    bg: '#eef4ff',
    helper: '当前资产存量',
  },
  {
    label: '已评估资产',
    value: stats.value.assessed_assets ?? '-',
    icon: '评',
    bg: '#ecfdf3',
    helper: '已进入风险引擎',
  },
  {
    label: '高风险资产',
    value: (stats.value.level_counts?.high ?? 0) + (stats.value.level_counts?.critical ?? 0),
    icon: '险',
    bg: '#fff1f2',
    helper: '需要优先处置',
  },
  {
    label: '平均分值',
    value: stats.value.avg_score ?? '-',
    icon: '分',
    bg: '#fffbeb',
    helper: '整体风险基线',
  },
])

const sourceStatsList = computed(() =>
  // 将 source_stats 对象转换为数组，便于 v-for 渲染来源标签。
  Object.entries(lastScan.value.discovery_summary?.source_stats || {}).map(([source, count]) => ({ source, count })),
)
const scanTargets = computed(() => lastScan.value.target_details || [])
const passiveTargets = computed(() => lastScan.value.passive_target_details || [])
const activeTargets = computed(() => lastScan.value.active_target_details || [])
const validationResults = computed(() => lastScan.value.validated_results || [])
const displayTargets = computed(() => {
  // 根据用户选择的分层视图切换表格数据来源。
  if (selectedLayer.value === 'passive') return passiveTargets.value
  if (selectedLayer.value === 'active') return activeTargets.value
  return scanTargets.value
})

const detailRows = computed(() => {
  // 把目标的标题、Server、URL、JS 端点等信息整理为抽屉中的表格行。
  if (!activeTarget.value) return []
  const rows = []
  if (activeTarget.value.title) rows.push({ kind: '标题', value: activeTarget.value.title })
  if (activeTarget.value.server) rows.push({ kind: 'Server', value: activeTarget.value.server })
  if (activeTarget.value.error) rows.push({ kind: '错误', value: activeTarget.value.error })
  for (const url of activeTarget.value.urls || []) rows.push({ kind: 'URL', value: url })
  for (const endpoint of activeTarget.value.js_endpoints || []) rows.push({ kind: 'JS', value: endpoint })
  if (!rows.length) rows.push({ kind: '说明', value: '当前未采集到 URL、JS、标题或错误信息。' })
  return rows
})

async function loadStats() {
  try {
    // 加载仪表盘统计后等待 DOM 更新，再初始化 ECharts 图表。
    const data = await getDashboardStats()
    stats.value = data
    await nextTick()
    renderRiskPie(data.level_counts || {})
    renderTypeBar(data.type_counts || {})
  } catch {
    ElMessage.error('仪表盘统计加载失败')
  }
}

function renderRiskPie(levelCounts) {
  if (!riskPieRef.value) return
  // 风险等级饼图用于展示不同风险等级资产数量。
  const chart = echarts.init(riskPieRef.value)
  const colorMap = { low: '#22c55e', medium: '#f59e0b', high: '#ef4444', critical: '#7f1d1d' }
  const labelMap = { low: '低风险', medium: '中风险', high: '高风险', critical: '严重风险' }
  const data = Object.entries(levelCounts).map(([key, value]) => ({
    name: labelMap[key] || key,
    value,
    itemStyle: { color: colorMap[key] || '#cbd5e1' },
  }))
  chart.setOption({
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { bottom: 0, textStyle: { color: '#64748b' } },
    series: [{ type: 'pie', radius: ['46%', '72%'], data, label: { show: true, formatter: '{b}\n{c}' } }],
  })
}

function renderTypeBar(typeCounts) {
  if (!typeBarRef.value) return
  // 资产类型柱状图用于展示网站、后台、API、数据库等类型分布。
  const chart = echarts.init(typeBarRef.value)
  const labelMap = {
    web_site: '网站系统',
    admin_panel: '管理后台',
    api_service: 'API 服务',
    dev_test_system: '开发测试系统',
    database_service: '数据库服务',
    middleware_service: '中间件服务',
    unknown: '未知类型',
  }
  const keys = Object.keys(typeCounts)
  const values = Object.values(typeCounts)
  chart.setOption({
    tooltip: { trigger: 'axis' },
    xAxis: {
      type: 'category',
      data: keys.map(key => labelMap[key] || key),
      axisLabel: { rotate: 18, color: '#64748b' },
      axisLine: { lineStyle: { color: '#d7e0ea' } },
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: '#64748b' },
      splitLine: { lineStyle: { color: '#e7edf5' } },
    },
    series: [{
      type: 'bar',
      data: values,
      barMaxWidth: 36,
      itemStyle: {
        color: '#2563eb',
        borderRadius: [4, 4, 0, 0],
      },
    }],
  })
}

async function doScan() {
  if (!scanDomainInput.value.trim()) {
    ElMessage.warning('请输入目标域名')
    return
  }
  scanning.value = true
  opResult.value = ''
  try {
    // 将用户输入域名、扫描模式和默认多源开关一起提交给后端扫描接口。
    const res = await apiScan({ domain: scanDomainInput.value.trim(), mode: scanMode.value, ...defaultScanOptions })
    lastScan.value = res
    selectedLayer.value = 'merged'
    opResult.value =
      `Run ${res.run_id || '-'} 扫描完成：合并目标 ${res.subdomains_found}，验证结果 ${res.probes_total}，资产入库 ${res.saved}，` +
      `发现记录 ${res.discovery_records_saved || 0}，验证记录 ${res.validation_records_saved || 0}`
    loadStats()
  } finally {
    scanning.value = false
  }
}

async function doAnalyzeAll() {
  analyzing.value = true
  opResult.value = ''
  try {
    // 批量分析会对当前资产表中的所有有效资产执行规则识别和标签生成。
    const res = await analyzeAll()
    opResult.value = `批量分析完成：成功 ${res.success}，失败 ${res.failed}`
    loadStats()
  } finally {
    analyzing.value = false
  }
}

async function doAssessAll() {
  assessing.value = true
  opResult.value = ''
  try {
    // 批量评估会调用后端风险引擎，为全部资产生成风险分和整改建议。
    const res = await assessAll()
    opResult.value = `批量风险评估完成：成功 ${res.success}，失败 ${res.failed}`
    loadStats()
  } finally {
    assessing.value = false
  }
}

function sourceLabel(source) {
  // 后端来源字段是英文枚举，前端统一转换为中文标签。
  const labels = {
    active_dns: '主动 DNS',
    ct_log: 'CT 日志',
    passive_dns: '被动 DNS',
    traffic_sniff: '流量嗅探',
    search_engine: '搜索引擎',
    icp_record: 'ICP备案',
    cloud_api: '云资产',
    web_crawl: '网络爬虫',
    js_extract: 'JS 提取',
    certificate: '证书解析',
  }
  return labels[source] || source
}

function sourceTagType(source) {
  // 不同来源使用不同颜色，方便用户快速区分主动、被动和富化来源。
  if (['ct_log', 'passive_dns', 'search_engine', 'traffic_sniff'].includes(source)) return 'warning'
  if (['web_crawl', 'js_extract', 'certificate'].includes(source)) return 'success'
  if (['cloud_api', 'icp_record'].includes(source)) return 'danger'
  return 'info'
}

function validationLabel(status) {
  // 验证状态转为中文，用于目标表格和详情抽屉。
  const labels = {
    discovered: '已发现',
    resolved: '已解析',
    probed: '已探测',
    alive: '存活',
    failed: '失败',
  }
  return labels[status] || status || '-'
}

function validationTagType(status) {
  if (status === 'alive') return 'success'
  if (status === 'resolved' || status === 'probed') return 'warning'
  if (status === 'failed') return 'danger'
  return 'info'
}

function layerLabel(layer) {
  const labels = {
    merged: '合并结果',
    passive: '被动发现',
    active: '主动发现',
    validated: '验证结果',
  }
  return labels[layer] || layer || '-'
}

function modeLabel(mode) {
  const labels = {
    hybrid: '混合',
    passive: '被动',
    active: '主动',
  }
  return labels[mode] || mode || '-'
}

function openTargetDetail(row, layer = selectedLayer.value) {
  // 打开详情抽屉前对不同表格行结构做统一整理。
  activeTarget.value = {
    ...row,
    layer,
    ips: row.ips || (row.ip ? [row.ip] : []),
    evidence: row.evidence || [],
    urls: row.urls || [],
    js_endpoints: row.js_endpoints || [],
    validation_status: row.validation_status || (row.success ? 'alive' : 'probed'),
  }
  detailVisible.value = true
}

onMounted(loadStats)
</script>

<style scoped>
.dashboard-page {
  display: grid;
  gap: 16px;
}

.hero-panel {
  padding: 18px 20px;
  display: flex;
  justify-content: space-between;
  gap: 20px;
  background: #ffffff !important;
  align-items: center;
}

.eyebrow {
  margin-bottom: 8px;
  color: #667085;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0;
}

.hero-copy {
  max-width: 720px;
}

.hero-metrics {
  display: flex;
  align-items: stretch;
  gap: 10px;
  flex-wrap: wrap;
}

.hero-pill {
  min-width: 118px;
  padding: 12px 14px;
  border-radius: 8px;
  background: #f8fafc;
  border: 1px solid #dfe5ee;
}

.hero-pill span {
  display: block;
  color: #64748b;
  font-size: 12px;
}

.hero-pill strong {
  display: block;
  margin-top: 6px;
  font-size: 24px;
  line-height: 1;
}

.hero-pill.accent {
  background: #eff6ff;
  color: #1d4ed8;
  border-color: #bfdbfe;
}

.hero-pill.accent span {
  color: #475569;
}

.metric-card {
  min-height: 126px;
}

.metric-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.metric-icon {
  width: 42px;
  height: 42px;
  border-radius: 8px;
  display: grid;
  place-items: center;
  font-size: 18px;
  font-weight: 700;
  color: #17324d;
}

.metric-trend {
  font-size: 12px;
  color: #7b8ca2;
}

.metric-label {
  margin-top: 14px;
  color: #64748b;
  font-size: 13px;
}

.metric-value {
  margin-top: 8px;
  font-size: 30px;
  font-weight: 700;
}

.chart-card,
.scan-console {
  overflow: hidden;
}

.card-head {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  align-items: center;
  flex-wrap: wrap;
}

.card-meta {
  color: #7b8ca2;
  font-size: 12px;
}

.section-title {
  font-weight: 700;
}

.chart-box {
  height: 286px;
}

.console-grid {
  display: grid;
  grid-template-columns: 1.65fr 0.75fr;
  gap: 18px;
}

.console-left {
  display: grid;
  gap: 16px;
}

.console-right {
  display: grid;
  gap: 12px;
}

.mode-row,
.layer-switch-row {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  align-items: center;
  padding: 12px 14px;
  border-radius: 8px;
  background: #f8fafc;
  border: 1px solid #dfe5ee;
  flex-wrap: wrap;
}

.switch-title {
  font-weight: 700;
}

.switch-desc {
  margin-top: 4px;
  color: #6b7b90;
  font-size: 12px;
}

.action-row {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
}

.mini-panel {
  padding: 14px;
  border-radius: 8px;
  background: #f8fafc;
  border: 1px solid #dfe5ee;
}

.mini-label {
  color: #64748b;
  font-size: 12px;
}

.mini-value {
  margin-top: 8px;
  font-size: 28px;
  font-weight: 700;
}

.mini-value-sm {
  font-size: 22px;
  line-height: 1.2;
  word-break: break-word;
}

.result-alert {
  border-radius: 8px;
}

.scan-results {
  margin-top: 20px;
}

.run-meta-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}

.run-meta-card {
  padding: 12px 14px;
  border-radius: 8px;
  background: #f8fafc;
  border: 1px solid #dfe5ee;
}

.run-meta-label {
  color: #64748b;
  font-size: 12px;
}

.run-meta-value {
  margin-top: 8px;
  font-size: 24px;
  font-weight: 700;
}

.source-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: 16px;
}

.layer-switch-row {
  margin-bottom: 16px;
}

.result-table :deep(.el-table__cell) {
  padding-top: 14px;
  padding-bottom: 14px;
}

.target-url {
  font-weight: 600;
  color: #1f2937;
}

.target-meta {
  margin-top: 6px;
  color: #64748b;
  font-size: 12px;
}

.drawer-body {
  padding-right: 6px;
}

.drawer-head {
  display: flex;
  justify-content: space-between;
  gap: 14px;
  align-items: center;
  margin-bottom: 18px;
}

.drawer-title {
  font-size: 20px;
  font-weight: 700;
}

.drawer-subtitle {
  margin-top: 6px;
  color: #64748b;
}

.drawer-block {
  margin-top: 14px;
}

@media (max-width: 1200px) {
  .console-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 900px) {
  .hero-panel {
    flex-direction: column;
  }

  .run-meta-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 640px) {
  .run-meta-grid {
    grid-template-columns: 1fr;
  }

  .metric-value,
  .mini-value {
    font-size: 28px;
  }
}
</style>
