<template>
  <div class="user-page">
    <div class="page-header">
      <div>
        <div class="page-title">用户管理</div>
        <div class="page-subtitle">管理员可以查看用户账号、创建用户、调整角色并启用或禁用账号。</div>
      </div>
      <div class="header-actions">
        <el-button :icon="Refresh" @click="loadData">刷新</el-button>
        <el-button type="primary" :icon="Plus" @click="openCreateDialog">新增用户</el-button>
      </div>
    </div>

    <el-card class="glass-card" shadow="never">
      <el-table :data="users" v-loading="loading" stripe>
        <el-table-column prop="id" label="ID" width="76" />
        <el-table-column label="头像" width="86">
          <template #default="{ row }">
            <el-avatar :size="34" :src="row.avatar_url || ''">{{ getUserInitial(row) }}</el-avatar>
          </template>
        </el-table-column>
        <el-table-column prop="username" label="用户名" min-width="160" show-overflow-tooltip />
        <el-table-column prop="display_name" label="显示名称" min-width="160" show-overflow-tooltip />
        <el-table-column label="角色" width="160">
          <template #default="{ row }">
            <el-select
              v-model="row.role"
              size="small"
              :disabled="isCurrentUser(row)"
              @change="(role) => handleRoleChange(row, role)"
            >
              <el-option label="普通用户" value="user" />
              <el-option label="管理员" value="admin" />
            </el-select>
          </template>
        </el-table-column>
        <el-table-column label="账号状态" width="140">
          <template #default="{ row }">
            <el-switch
              v-model="row.is_active"
              :active-value="1"
              :inactive-value="0"
              active-text="启用"
              inactive-text="禁用"
              :disabled="isCurrentUser(row)"
              @change="(value) => handleStatusChange(row, Boolean(value))"
            />
          </template>
        </el-table-column>
        <el-table-column prop="last_login_at" label="最近登录" min-width="180" show-overflow-tooltip />
        <el-table-column prop="created_at" label="创建时间" min-width="180" show-overflow-tooltip />
        <el-table-column label="操作" width="120" fixed="right">
          <template #default="{ row }">
            <el-popconfirm
              title="确认删除该用户吗？"
              confirm-button-text="删除"
              cancel-button-text="取消"
              @confirm="handleDelete(row)"
            >
              <template #reference>
                <el-button link type="danger" :icon="Delete" :disabled="isCurrentUser(row)">删除</el-button>
              </template>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="createVisible" title="新增用户" width="460px">
      <el-form ref="createFormRef" :model="createForm" :rules="createRules" label-width="86px">
        <el-form-item label="用户名" prop="username">
          <el-input v-model="createForm.username" clearable />
        </el-form-item>
        <el-form-item label="显示名称" prop="display_name">
          <el-input v-model="createForm.display_name" clearable />
        </el-form-item>
        <el-form-item label="头像">
          <div class="avatar-picker">
            <el-avatar :size="56" :src="createForm.avatar_url || ''">{{ createAvatarInitial }}</el-avatar>
            <input
              ref="createAvatarInputRef"
              class="avatar-input"
              type="file"
              accept="image/png,image/jpeg,image/webp"
              @change="handleCreateAvatarFile"
            />
            <el-button @click="createAvatarInputRef?.click()">选择图片</el-button>
            <el-button @click="createForm.avatar_url = ''">清除</el-button>
          </div>
        </el-form-item>
        <el-form-item label="密码" prop="password">
          <el-input v-model="createForm.password" type="password" show-password />
        </el-form-item>
        <el-form-item label="角色" prop="role">
          <el-radio-group v-model="createForm.role">
            <el-radio-button label="user">普通用户</el-radio-button>
            <el-radio-button label="admin">管理员</el-radio-button>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createVisible = false">取消</el-button>
        <el-button type="primary" :loading="creating" @click="handleCreate">创建</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Delete, Plus, Refresh } from '@element-plus/icons-vue'

import { authUser } from '../auth.js'
import { createUser, deleteUser, getUsers, updateUserRole, updateUserStatus } from '../api/index.js'

const users = ref([])
const loading = ref(false)
const creating = ref(false)
const createVisible = ref(false)
const createFormRef = ref()
const createAvatarInputRef = ref()
const createForm = reactive({
  username: '',
  display_name: '',
  avatar_url: '',
  password: '',
  role: 'user',
})
const createAvatarInitial = computed(() => {
  const name = createForm.display_name || createForm.username || 'U'
  return String(name).trim().slice(0, 1).toUpperCase()
})

const createRules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    { min: 6, message: '密码长度不能少于 6 位', trigger: 'blur' },
  ],
  role: [{ required: true, message: '请选择角色', trigger: 'change' }],
}

function isCurrentUser(row) {
  return Number(row.id) === Number(authUser.value?.id)
}

function normalizeUser(row) {
  return {
    ...row,
    avatar_url: row.avatar_url || '',
    is_active: row.is_active ? 1 : 0,
  }
}

function getUserInitial(row) {
  const name = row.display_name || row.username || 'U'
  return String(name).trim().slice(0, 1).toUpperCase()
}

async function loadData() {
  loading.value = true
  try {
    const res = await getUsers()
    users.value = (res.users || []).map(normalizeUser)
  } finally {
    loading.value = false
  }
}

function openCreateDialog() {
  createForm.username = ''
  createForm.display_name = ''
  createForm.avatar_url = ''
  createForm.password = ''
  createForm.role = 'user'
  createVisible.value = true
}

async function handleCreateAvatarFile(event) {
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
  createForm.avatar_url = await resizeAvatar(file)
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

async function handleCreate() {
  const valid = await createFormRef.value?.validate().catch(() => false)
  if (!valid) return

  creating.value = true
  try {
    await createUser({
      username: createForm.username,
      display_name: createForm.display_name || createForm.username,
      avatar_url: createForm.avatar_url,
      password: createForm.password,
      role: createForm.role,
    })
    ElMessage.success('用户创建成功')
    createVisible.value = false
    await loadData()
  } finally {
    creating.value = false
  }
}

async function handleRoleChange(row, role) {
  try {
    await updateUserRole(row.id, role)
    ElMessage.success('角色已更新')
  } finally {
    await loadData()
  }
}

async function handleStatusChange(row, isActive) {
  try {
    await updateUserStatus(row.id, isActive)
    ElMessage.success(isActive ? '账号已启用' : '账号已禁用')
  } finally {
    await loadData()
  }
}

async function handleDelete(row) {
  try {
    await deleteUser(row.id)
    ElMessage.success('用户已删除')
    await loadData()
  } catch {
    await loadData()
  }
}

onMounted(loadData)
</script>

<style scoped>
.user-page {
  display: grid;
  gap: 18px;
}

.page-header {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: center;
}

.header-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.avatar-picker {
  display: flex;
  align-items: center;
  gap: 10px;
}

.avatar-input {
  display: none;
}

@media (max-width: 900px) {
  .page-header {
    flex-direction: column;
    align-items: flex-start;
  }
}
</style>
