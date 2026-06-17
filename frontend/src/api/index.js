// 文件作用：统一封装前端与后端 API 的请求逻辑、登录态处理和各业务接口方法。
import axios from 'axios'
import { ElMessage } from 'element-plus'

import { clearAuthenticatedUser, setAuthenticatedUser } from '../auth.js'

const http = axios.create({
  // 前端通过 Vite 代理访问后端 /api，避免在业务代码中硬编码后端地址。
  baseURL: '/api',
  // 扫描任务可能耗时较长，因此请求超时时间设置得相对宽松。
  timeout: 120000,
  // 携带 Cookie，保证 Flask session 登录态能够在前后端之间保持。
  withCredentials: true,
})

http.interceptors.response.use(
  // 后端统一返回 JSON，正常响应直接取 data，减少页面层重复解包。
  (response) => response.data,
  (error) => {
    const status = error.response?.status
    const message = error.response?.data?.error || error.message || '请求失败'
    const requestUrl = error.config?.url || ''
    const isAuthEndpoint = requestUrl.startsWith('/auth/')
    const suppressedStatuses = error.config?.suppressErrorStatuses || []
    const shouldSuppressMessage = Array.isArray(suppressedStatuses) && suppressedStatuses.includes(status)

    if (status === 401) {
      // 登录态失效时清理前端缓存的用户信息。
      clearAuthenticatedUser(true)

      if (!isAuthEndpoint && !window.location.pathname.startsWith('/login')) {
        // 非登录接口触发 401 时跳转登录页，并记录原路径用于登录后回跳。
        const redirect = `${window.location.pathname}${window.location.search}`
        window.location.replace(`/login?redirect=${encodeURIComponent(redirect)}`)
      }

      if (!isAuthEndpoint) {
        ElMessage.warning('登录状态已失效，请重新登录')
      }

      if (requestUrl === '/auth/login') {
        ElMessage.error(message)
      }

      return Promise.reject(error)
    }

    if (!shouldSuppressMessage) {
      ElMessage.error(message)
    }
    return Promise.reject(error)
  },
)

export const login = async (payload) => {
  // 登录成功后同步保存当前用户信息，供路由守卫和顶部用户信息使用。
  const result = await http.post('/auth/login', payload)
  if (result.user) {
    setAuthenticatedUser(result.user)
  }
  return result
}

export const register = async (payload) => {
  // 注册成功后后端会直接建立会话，前端同步写入登录用户信息。
  const result = await http.post('/auth/register', payload)
  if (result.user) {
    setAuthenticatedUser(result.user)
  }
  return result
}

export const logout = async () => {
  try {
    return await http.post('/auth/logout')
  } finally {
    // 无论后端退出请求是否成功，都清理前端登录缓存，避免界面状态残留。
    clearAuthenticatedUser(true)
  }
}

export const getCurrentUser = async () => {
  // 页面刷新后通过该接口恢复当前登录用户信息。
  const result = await http.get('/auth/me')
  if (result.user) {
    setAuthenticatedUser(result.user)
  }
  return result.user
}

export const updateCurrentUserAvatar = async (avatar_url) => {
  // 头像更新成功后刷新本地用户缓存。
  const result = await http.patch('/auth/me/avatar', { avatar_url })
  if (result.user) {
    setAuthenticatedUser(result.user)
  }
  return result.user
}

export const getDashboardStats = () => http.get('/dashboard/stats')

// 管理员用户管理接口。
export const getUsers = () => http.get('/admin/users')
export const createUser = (data) => http.post('/admin/users', data)
export const updateUser = (id, data) => http.put(`/admin/users/${id}`, data)
export const updateUserRole = (id, role) => http.patch(`/admin/users/${id}/role`, { role })
export const updateUserStatus = (id, is_active) => http.patch(`/admin/users/${id}/status`, { is_active })
export const deleteUser = (id) => http.delete(`/admin/users/${id}`)

// 资产发现与资产管理接口。
export const getAssets = (params) => http.get('/assets', { params })
export const getAsset = (id) => http.get(`/assets/${id}`)
export const scanDomain = (data) => http.post('/scan', data)

// 资产规则分析与标签接口。
export const analyzeAsset = (id) => http.post(`/analyze/${id}`)
export const analyzeAll = () => http.post('/analyze/all')
export const getAnalysis = (id) =>
  http.get(`/assets/${id}/analysis`, {
    suppressErrorStatuses: [404],
  })
export const getTags = (id) => http.get(`/assets/${id}/tags`)

// 风险评估接口。
export const assessAsset = (id) => http.post(`/risk/assess/${id}`)
export const assessAll = () => http.post('/risk/assess/all')
export const getRisk = (id) =>
  http.get(`/risk/${id}`, {
    suppressErrorStatuses: [404],
  })
export const getRisks = (params) => http.get('/risks', { params })

// AI 综合风险研判接口。
export const generateAiAnalysis = (id) => http.post(`/ai/analyze/${id}`)
export const getAiAnalysis = (id) =>
  http.get(`/ai/analyze/${id}`, {
    suppressErrorStatuses: [404],
  })

// 机器学习漏洞情报分析接口。
export const generateMlAnalysis = (id) => http.post(`/ml/analyze/${id}`)
export const getMlAnalysis = (id) =>
  http.get(`/ml/analyze/${id}`, {
    suppressErrorStatuses: [404],
  })
