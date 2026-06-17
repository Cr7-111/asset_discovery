<template>
  <div class="asset-page">
    <div class="page-header">
      <div>
        <div class="page-title">资产列表</div>
        <div class="page-subtitle">查看当前已发现资产，并对单个目标执行分析与风险评估。</div>
      </div>
      <el-button type="primary" size="large" @click="loadData">刷新数据</el-button>
    </div>

    <el-card class="glass-card" shadow="never">
      <div class="filter-bar">
        <el-input v-model="filters.domain" placeholder="按域名搜索" clearable @change="loadData">
          <template #prefix><el-icon><Search /></el-icon></template>
        </el-input>
        <el-select v-model="filters.status_code" placeholder="状态码" clearable @change="loadData">
          <el-option label="200 OK" :value="200" />
          <el-option label="301 Redirect" :value="301" />
          <el-option label="403 Forbidden" :value="403" />
          <el-option label="404 Not Found" :value="404" />
          <el-option label="500 Error" :value="500" />
        </el-select>
        <el-input v-model="filters.ip" placeholder="按 IP 过滤" clearable @change="loadData" />
      </div>

      <el-table :data="assets" v-loading="loading" class="asset-table" stripe @row-click="goDetail">
        <el-table-column prop="asset_id" label="ID" width="76" />
        <el-table-column prop="domain" label="域名" min-width="220" show-overflow-tooltip />
        <el-table-column prop="ip" label="IP" width="150" />
        <el-table-column prop="port" label="端口" width="90" />
        <el-table-column label="状态码" width="110">
          <template #default="{ row }">
            <el-tag :type="statusType(row.status_code)" effect="plain">{{ row.status_code || '-' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="title" label="页面标题" min-width="220" show-overflow-tooltip />
        <el-table-column prop="server" label="Server" width="170" show-overflow-tooltip />
        <el-table-column prop="last_seen" label="最近发现" width="190" />
        <el-table-column label="操作" width="180" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click.stop="goDetail(row)">详情</el-button>
            <el-button link type="warning" :loading="row._analyzing" @click.stop="doAnalyze(row)">分析</el-button>
            <el-button link type="danger" :loading="row._assessing" @click.stop="doAssess(row)">评估</el-button>
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
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Search } from '@element-plus/icons-vue'
import { analyzeAsset, assessAsset, getAssets } from '../api/index.js'

const router = useRouter()
const assets = ref([])
const loading = ref(false)
const total = ref(0)
const page = ref(1)
const pageSize = ref(20)
const filters = reactive({ domain: '', status_code: null, ip: '' })

async function loadData() {
  loading.value = true
  try {
    const params = { page: page.value, per_page: pageSize.value }
    if (filters.domain) params.domain = filters.domain
    if (filters.status_code) params.status_code = filters.status_code
    if (filters.ip) params.ip = filters.ip
    const res = await getAssets(params)
    assets.value = (res.assets || []).map(a => ({ ...a, _analyzing: false, _assessing: false }))
    total.value = res.total || 0
  } finally {
    loading.value = false
  }
}

function statusType(code) {
  if (!code) return 'info'
  if (code < 300) return 'success'
  if (code < 400) return 'warning'
  return 'danger'
}

function goDetail(row) {
  router.push(`/assets/${row.asset_id}`)
}

async function doAnalyze(row) {
  row._analyzing = true
  try {
    await analyzeAsset(row.asset_id)
    ElMessage.success('分析完成')
  } finally {
    row._analyzing = false
  }
}

async function doAssess(row) {
  row._assessing = true
  try {
    await assessAsset(row.asset_id)
    ElMessage.success('风险评估完成')
  } finally {
    row._assessing = false
  }
}

onMounted(loadData)
</script>

<style scoped>
.asset-page {
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
  display: grid;
  grid-template-columns: 1.2fr 220px 220px;
  gap: 12px;
  margin-bottom: 16px;
}

.asset-table :deep(.el-table__cell) {
  padding-top: 14px;
  padding-bottom: 14px;
}

.pager-wrap {
  margin-top: 18px;
  display: flex;
  justify-content: flex-end;
}

@media (max-width: 1000px) {
  .page-header {
    flex-direction: column;
    align-items: flex-start;
  }

  .filter-bar {
    grid-template-columns: 1fr;
  }
}
</style>
