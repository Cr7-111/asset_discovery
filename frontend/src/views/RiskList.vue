<template>
  <div class="risk-page">
    <div class="page-header">
      <div>
        <div class="page-title">风险列表</div>
        <div class="page-subtitle">按风险等级、分数和资产详情快速定位最需要优先处置的暴露目标。</div>
      </div>
      <el-button type="danger" size="large" :loading="assessing" @click="doAssessAll">全量重新评估</el-button>
    </div>

    <el-card class="glass-card" shadow="never">
      <div class="filter-bar">
        <el-select v-model="filters.risk_level" placeholder="风险等级" clearable @change="loadData">
          <el-option label="低风险" value="low" />
          <el-option label="中风险" value="medium" />
          <el-option label="高风险" value="high" />
          <el-option label="严重风险" value="critical" />
        </el-select>
        <el-input-number v-model="filters.min_score" placeholder="最低分" :min="0" :max="100" @change="loadData" />
        <el-button @click="loadData">筛选</el-button>
      </div>

      <el-table :data="risks" v-loading="loading" stripe class="risk-table">
        <el-table-column prop="asset_id" label="资产 ID" width="90" />
        <el-table-column prop="domain" label="域名" min-width="220" show-overflow-tooltip />
        <el-table-column prop="ip" label="IP" width="150" />
        <el-table-column prop="port" label="端口" width="90" />
        <el-table-column label="风险评分" width="150">
          <template #default="{ row }">
            <el-progress
              :percentage="row.risk_score"
              :stroke-width="14"
              :color="scoreColor(row.risk_score)"
              :format="() => row.risk_score"
            />
          </template>
        </el-table-column>
        <el-table-column label="风险等级" width="120">
          <template #default="{ row }">
            <el-tag :type="levelTagType(row.risk_level)" effect="dark">
              {{ levelLabel(row.risk_level) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="assessed_at" label="评估时间" width="190" />
        <el-table-column label="操作" width="110" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="$router.push(`/assets/${row.asset_id}`)">查看详情</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="pager-wrap">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :total="total"
          :page-sizes="[10, 20, 50]"
          layout="total, sizes, prev, pager, next"
          @change="loadData"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { assessAll, getRisks } from '../api/index.js'

const risks = ref([])
const loading = ref(false)
const assessing = ref(false)
const total = ref(0)
const page = ref(1)
const pageSize = ref(20)
const filters = reactive({ risk_level: '', min_score: null })

async function loadData() {
  loading.value = true
  try {
    const params = { page: page.value, per_page: pageSize.value }
    if (filters.risk_level) params.risk_level = filters.risk_level
    if (filters.min_score != null) params.min_score = filters.min_score
    const res = await getRisks(params)
    risks.value = res.items || []
    total.value = res.total || 0
  } finally {
    loading.value = false
  }
}

async function doAssessAll() {
  assessing.value = true
  try {
    const res = await assessAll()
    ElMessage.success(`评估完成：成功 ${res.success}，失败 ${res.failed}`)
    loadData()
  } finally {
    assessing.value = false
  }
}

function scoreColor(score) {
  if (score >= 80) return '#7f1d1d'
  if (score >= 60) return '#ef4444'
  if (score >= 30) return '#f59e0b'
  return '#22c55e'
}

function levelLabel(level) {
  return { low: '低风险', medium: '中风险', high: '高风险', critical: '严重风险' }[level] || level
}

function levelTagType(level) {
  return { low: 'success', medium: 'warning', high: 'danger', critical: 'danger' }[level] || 'info'
}

onMounted(loadData)
</script>

<style scoped>
.risk-page {
  display: grid;
  gap: 18px;
}

.page-header {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: center;
}

.filter-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 16px;
}

.risk-table :deep(.el-table__cell) {
  padding-top: 14px;
  padding-bottom: 14px;
}

.pager-wrap {
  margin-top: 18px;
  display: flex;
  justify-content: flex-end;
}

@media (max-width: 900px) {
  .page-header {
    flex-direction: column;
    align-items: flex-start;
  }
}
</style>
