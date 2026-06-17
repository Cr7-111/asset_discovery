<template>
  <div class="shell">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark">ASM</div>
        <div>
          <div class="brand-title">资产暴露面管理</div>
          <div class="brand-subtitle">Asset Surface Management</div>
        </div>
      </div>

      <el-menu
        :default-active="$route.path"
        router
        class="nav-menu"
        background-color="transparent"
        text-color="#9fb1c8"
        active-text-color="#f3f7fb"
      >
        <el-menu-item index="/dashboard">
          <el-icon><DataLine /></el-icon>
          <span>总览面板</span>
        </el-menu-item>
        <el-menu-item index="/assets">
          <el-icon><List /></el-icon>
          <span>资产列表</span>
        </el-menu-item>
        <el-menu-item index="/risks">
          <el-icon><Warning /></el-icon>
          <span>风险列表</span>
        </el-menu-item>
        <el-menu-item v-if="currentUser?.role === 'admin'" index="/users">
          <el-icon><UserFilled /></el-icon>
          <span>用户管理</span>
        </el-menu-item>
      </el-menu>

      <div class="sidebar-foot">
        <div class="foot-label">系统状态</div>
        <div class="foot-value">运行中</div>
      </div>
    </aside>

    <main class="workspace">
      <header class="topbar">
        <div>
          <div class="topbar-title">互联网资产自动发现与风险评估系统</div>
          <div class="topbar-subtitle">资产发现、风险评估与处置建议工作台</div>
        </div>
        <div class="topbar-actions">
          <div class="account-card">
            <el-avatar
              class="account-avatar"
              :size="38"
              :src="currentUser?.avatar_url || ''"
              @click="openAvatarDialog"
            >
              {{ avatarInitial }}
            </el-avatar>
            <div>
              <div class="account-name">{{ currentUser?.display_name || '系统管理员' }}</div>
              <div class="account-role">{{ currentUser?.username || 'admin' }}</div>
            </div>
            <el-button text type="primary" @click="openAvatarDialog">头像</el-button>
            <el-button text type="primary" @click="handleLogout">退出登录</el-button>
          </div>
        </div>
      </header>

      <section class="content-wrap">
        <router-view />
      </section>
    </main>

    <el-dialog v-model="avatarVisible" title="账号头像" width="420px">
      <div class="avatar-editor">
        <el-avatar :size="88" :src="avatarPreview || ''">{{ avatarInitial }}</el-avatar>
        <div class="avatar-actions">
          <input
            ref="avatarInputRef"
            class="avatar-input"
            type="file"
            accept="image/png,image/jpeg,image/webp"
            @change="handleAvatarFile"
          />
          <el-button type="primary" @click="avatarInputRef?.click()">选择图片</el-button>
          <el-button @click="clearAvatar">清除头像</el-button>
        </div>
      </div>
      <template #footer>
        <el-button @click="avatarVisible = false">取消</el-button>
        <el-button type="primary" :loading="avatarSaving" @click="saveAvatar">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { DataLine, List, UserFilled, Warning } from '@element-plus/icons-vue'

import { authUser } from '../auth.js'
import { logout, updateCurrentUserAvatar } from '../api/index.js'

const router = useRouter()
const currentUser = computed(() => authUser.value)
const avatarVisible = ref(false)
const avatarSaving = ref(false)
const avatarPreview = ref('')
const avatarInputRef = ref()
const avatarInitial = computed(() => {
  const name = currentUser.value?.display_name || currentUser.value?.username || 'U'
  return String(name).trim().slice(0, 1).toUpperCase()
})

function openAvatarDialog() {
  avatarPreview.value = currentUser.value?.avatar_url || ''
  avatarVisible.value = true
}

async function handleAvatarFile(event) {
  const file = event.target.files?.[0]
  event.target.value = ''
  if (!file) return
  if (!file.type.startsWith('image/')) {
    ElMessage.warning('请选择图片文件')
    return
  }
  if (file.size > 4 * 1024 * 1024) {
    ElMessage.warning('图片不能超过 4MB')
    return
  }
  avatarPreview.value = await resizeAvatar(file)
}

function clearAvatar() {
  avatarPreview.value = ''
}

async function saveAvatar() {
  avatarSaving.value = true
  try {
    await updateCurrentUserAvatar(avatarPreview.value)
    ElMessage.success('头像已更新')
    avatarVisible.value = false
  } finally {
    avatarSaving.value = false
  }
}

function resizeAvatar(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => {
      const image = new Image()
      image.onload = () => {
        const size = 160
        const canvas = document.createElement('canvas')
        canvas.width = size
        canvas.height = size
        const ctx = canvas.getContext('2d')
        const side = Math.min(image.width, image.height)
        const sx = (image.width - side) / 2
        const sy = (image.height - side) / 2
        ctx.drawImage(image, sx, sy, side, side, 0, 0, size, size)
        resolve(canvas.toDataURL('image/jpeg', 0.82))
      }
      image.onerror = reject
      image.src = reader.result
    }
    reader.onerror = reject
    reader.readAsDataURL(file)
  })
}

async function handleLogout() {
  try {
    await ElMessageBox.confirm('确认退出当前登录状态吗？', '退出登录', {
      type: 'warning',
      confirmButtonText: '退出',
      cancelButtonText: '取消',
    })
  } catch {
    return
  }

  await logout()
  router.push('/login')
}
</script>

<style>
:root {
  --bg-page: #f4f6f9;
  --bg-panel: #ffffff;
  --bg-panel-strong: #ffffff;
  --border-soft: #dfe5ee;
  --text-main: #1f2937;
  --text-sub: #667085;
  --nav-bg: #172033;
  --accent: #2563eb;
  --accent-2: #16a34a;
  --shadow-card: 0 8px 22px rgba(15, 23, 42, 0.06);
  --shadow-soft: 0 4px 14px rgba(15, 23, 42, 0.05);
}

* {
  box-sizing: border-box;
}

html,
body,
#app {
  margin: 0;
  min-height: 100%;
}

body {
  font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
  color: var(--text-main);
  background: var(--bg-page);
}

.shell {
  min-height: 100vh;
  display: grid;
  grid-template-columns: 248px 1fr;
}

.sidebar {
  position: sticky;
  top: 0;
  height: 100vh;
  padding: 22px 16px 16px;
  background: var(--nav-bg);
  color: #fff;
  display: flex;
  flex-direction: column;
  border-right: 1px solid rgba(255, 255, 255, 0.08);
  box-shadow: none;
}

.brand {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-bottom: 20px;
  padding: 8px 8px 16px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}

.brand-mark {
  width: 42px;
  height: 42px;
  border-radius: 8px;
  display: grid;
  place-items: center;
  font-weight: 800;
  letter-spacing: 0;
  background: #2563eb;
  color: #ffffff;
  box-shadow: none;
}

.brand-title {
  font-size: 16px;
  font-weight: 700;
}

.brand-subtitle {
  margin-top: 3px;
  font-size: 12px;
  color: rgba(255, 255, 255, 0.62);
}

.nav-menu {
  flex: 1;
  border-right: none !important;
}

.nav-menu .el-menu-item {
  height: 44px;
  margin-bottom: 8px;
  border-radius: 8px;
  font-weight: 600;
}

.nav-menu .el-menu-item.is-active {
  background: rgba(37, 99, 235, 0.22) !important;
  box-shadow: inset 3px 0 0 #60a5fa;
}

.sidebar-foot {
  margin-top: 18px;
  padding: 14px 12px;
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.06);
  border: 1px solid rgba(255, 255, 255, 0.06);
}

.foot-label {
  font-size: 12px;
  color: rgba(255, 255, 255, 0.58);
}

.foot-value {
  margin-top: 6px;
  font-size: 15px;
  font-weight: 700;
}

.workspace {
  min-width: 0;
  padding: 16px 18px 24px;
}

.topbar {
  display: flex;
  justify-content: space-between;
  gap: 18px;
  align-items: center;
  padding: 16px 20px;
  border-radius: 8px;
  background: #ffffff;
  border: 1px solid var(--border-soft);
  box-shadow: var(--shadow-card);
}

.topbar-title {
  font-size: 20px;
  font-weight: 700;
  letter-spacing: 0;
}

.topbar-subtitle {
  margin-top: 6px;
  font-size: 13px;
  color: var(--text-sub);
}

.topbar-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}

.account-card {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 8px 10px 8px 12px;
  border-radius: 8px;
  background: #f8fafc;
  border: 1px solid var(--border-soft);
}

.account-avatar {
  flex: none;
  cursor: pointer;
  background: #2563eb;
  color: #ffffff;
  font-weight: 700;
}

.account-name {
  font-size: 14px;
  font-weight: 700;
}

.account-role {
  margin-top: 4px;
  font-size: 12px;
  color: var(--text-sub);
}

.avatar-editor {
  display: grid;
  justify-items: center;
  gap: 18px;
  padding: 8px 0 4px;
}

.avatar-actions {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 10px;
}

.avatar-input {
  display: none;
}

.content-wrap {
  margin-top: 16px;
}

.glass-card {
  border-radius: 8px !important;
  border: 1px solid var(--border-soft) !important;
  background: #ffffff !important;
  backdrop-filter: none;
  box-shadow: var(--shadow-soft) !important;
}

.glass-card .el-card__header {
  border-bottom: 1px solid rgba(15, 23, 42, 0.06);
}

.page-title {
  font-size: 22px;
  font-weight: 700;
}

.page-subtitle {
  margin-top: 6px;
  color: var(--text-sub);
  font-size: 13px;
}

.section-title {
  font-size: 16px;
  font-weight: 700;
}

.el-table,
.el-descriptions,
.el-input__wrapper,
.el-select__wrapper,
.el-textarea__inner,
.el-drawer,
.el-dialog {
  border-radius: 8px;
}

@media (max-width: 1100px) {
  .shell {
    grid-template-columns: 1fr;
  }

  .sidebar {
    position: relative;
    height: auto;
  }

  .topbar {
    flex-direction: column;
    align-items: flex-start;
  }

  .topbar-actions {
    width: 100%;
    flex-direction: column;
    align-items: stretch;
  }

  .account-card {
    justify-content: space-between;
  }
}
</style>
