<template>
  <div class="login-page">
    <div class="bg-orbit orbit-1"></div>
    <div class="bg-orbit orbit-2"></div>
    <div class="bg-dot dot-1"></div>
    <div class="bg-dot dot-2"></div>
    <div class="bg-dot dot-3"></div>

    <header class="page-header">
      <div class="brand-mini">
        <div class="logo-box">
          <el-icon><Lock /></el-icon>
        </div>
        <span>互联网资产自动发现与风险评估系统</span>
      </div>
    </header>

    <main class="page-main">
      <section class="hero-section">
        <div class="hero-title">
          <h1>
            互联网资产发现<br />
            与<span>风险评估</span>系统
          </h1>
          <p>多源发现 · 风险识别 · 分级处置 · 持续管理</p>
        </div>

        <div class="visual-area">
          <div class="shield-stage">
            <div class="ring ring-a"></div>
            <div class="ring ring-b"></div>
            <div class="platform platform-back"></div>
            <div class="platform platform-front"></div>
            <div class="shield-card">
              <el-icon><Check /></el-icon>
            </div>
          </div>

          <div class="feature-list">
            <div v-for="item in features" :key="item.title" class="feature-item">
              <div class="feature-icon">
                <el-icon><component :is="item.icon" /></el-icon>
              </div>
              <div>
                <h3>{{ item.title }}</h3>
                <p>{{ item.desc }}</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section class="form-panel">
        <el-tabs v-model="activeTab" stretch class="auth-tabs">
          <el-tab-pane label="登录" name="login">
            <div class="form-title">
              <h2>欢迎登录</h2>
              <p>请输入您的账号和密码登录系统</p>
            </div>

            <el-form ref="loginFormRef" :model="loginForm" :rules="loginRules" size="large">
              <el-form-item prop="username">
                <el-input v-model="loginForm.username" placeholder="请输入用户名" clearable>
                  <template #prefix>
                    <el-icon><User /></el-icon>
                  </template>
                </el-input>
              </el-form-item>

              <el-form-item prop="password">
                <el-input v-model="loginForm.password" placeholder="请输入密码" type="password" show-password>
                  <template #prefix>
                    <el-icon><Lock /></el-icon>
                  </template>
                </el-input>
              </el-form-item>

              <div class="form-options">
                <el-checkbox v-model="rememberMe">记住我</el-checkbox>
                <el-button link type="primary">忘记密码?</el-button>
              </div>

              <el-button class="submit-btn" type="primary" @click="handleLogin">登录</el-button>
            </el-form>
          </el-tab-pane>

          <el-tab-pane label="注册" name="register">
            <div class="form-title">
              <h2>创建账号</h2>
              <p>填写基础信息完成系统账号注册</p>
            </div>

            <el-form ref="registerFormRef" :model="registerForm" :rules="registerRules" size="large">
              <el-form-item prop="username">
                <el-input v-model="registerForm.username" placeholder="请输入用户名" clearable>
                  <template #prefix>
                    <el-icon><User /></el-icon>
                  </template>
                </el-input>
              </el-form-item>

              <el-form-item prop="email">
                <el-input v-model="registerForm.email" placeholder="请输入邮箱" clearable>
                  <template #prefix>
                    <el-icon><Message /></el-icon>
                  </template>
                </el-input>
              </el-form-item>

              <el-form-item prop="password">
                <el-input v-model="registerForm.password" placeholder="请输入密码" type="password" show-password>
                  <template #prefix>
                    <el-icon><Lock /></el-icon>
                  </template>
                </el-input>
              </el-form-item>

              <el-form-item prop="confirmPassword">
                <el-input v-model="registerForm.confirmPassword" placeholder="请再次输入密码" type="password" show-password>
                  <template #prefix>
                    <el-icon><Lock /></el-icon>
                  </template>
                </el-input>
              </el-form-item>

              <el-button class="submit-btn" type="primary" @click="handleRegister">注册</el-button>
            </el-form>
          </el-tab-pane>
        </el-tabs>

        <div class="security-tip">
          <el-icon><Lock /></el-icon>
          <span>当前连接已加密，保障您的数据安全</span>
        </div>
      </section>
    </main>

    <footer class="page-footer">© 2026 互联网资产自动发现与风险评估系统　版权所有</footer>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import {
  Check,
  DataAnalysis,
  Lock,
  Message,
  Monitor,
  User,
} from '@element-plus/icons-vue'

import { login, register } from '../api/index.js'

const router = useRouter()
const route = useRoute()
const activeTab = ref('login')
const rememberMe = ref(true)
const loginFormRef = ref()
const registerFormRef = ref()

const features = [
  { title: '资产发现', desc: '收集目标相关互联网资产', icon: Monitor },
  { title: '风险评估', desc: '按规则和模型计算风险等级', icon: Lock },
  { title: '结果管理', desc: '沉淀扫描记录与处置建议', icon: DataAnalysis },
]

const loginForm = reactive({
  username: '',
  password: '',
})

const registerForm = reactive({
  username: '',
  email: '',
  password: '',
  confirmPassword: '',
})

const loginRules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
}

const validateConfirmPassword = (_rule, value, callback) => {
  if (!value) callback(new Error('请再次输入密码'))
  else if (value !== registerForm.password) callback(new Error('两次输入的密码不一致'))
  else callback()
}

const registerRules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  email: [
    { required: true, message: '请输入邮箱', trigger: 'blur' },
    { type: 'email', message: '邮箱格式不正确', trigger: 'blur' },
  ],
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    { min: 6, message: '密码长度不能少于 6 位', trigger: 'blur' },
  ],
  confirmPassword: [{ validator: validateConfirmPassword, trigger: 'blur' }],
}

const handleLogin = async () => {
  // 提交登录请求前，先执行前端表单校验。
  const valid = await loginFormRef.value?.validate().catch(() => false)
  if (!valid) return

  try {
    // 校验通过后，将用户名和密码提交给后端认证接口。
    await login({
      username: loginForm.username,
      password: loginForm.password,
    })
    ElMessage.success('登录成功')
    // 登录成功后跳转到原访问页面，没有重定向地址时进入系统首页。
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/dashboard'
    router.replace(redirect)
  } catch (error) {
    ElMessage.error(error.message || '登录失败')
  }
}

const handleRegister = async () => {
  // 提交注册请求前，先校验用户名、邮箱、密码和确认密码。
  const valid = await registerFormRef.value?.validate().catch(() => false)
  if (!valid) return

  try {
    // 注册时只提交必要账号信息，密码安全处理由后端完成。
    await register({
      username: registerForm.username,
      display_name: registerForm.username,
      password: registerForm.password,
    })
    ElMessage.success('注册成功')
    // 注册成功后切换到登录页，并清空注册表单。
    activeTab.value = 'login'
    loginForm.username = registerForm.username
    registerForm.username = ''
    registerForm.email = ''
    registerForm.password = ''
    registerForm.confirmPassword = ''
  } catch (error) {
    ElMessage.error(error.message || '注册失败')
  }
}
</script>

<style scoped>
* {
  box-sizing: border-box;
}

.login-page {
  position: relative;
  min-height: 100vh;
  overflow: auto;
  color: #1f2937;
  background: #f4f6f9;
  font-family: Inter, 'PingFang SC', 'Microsoft YaHei', Arial, sans-serif;
}

.bg-orbit,
.bg-dot {
  display: none;
}

.page-header,
.page-main,
.page-footer {
  position: relative;
  z-index: 1;
}

.page-header {
  height: 78px;
  display: flex;
  align-items: center;
  padding: 0 6vw;
  border-bottom: 1px solid #dfe5ee;
  background: #ffffff;
}

.brand-mini {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 18px;
  font-weight: 700;
  letter-spacing: 0;
}

.logo-box {
  width: 38px;
  height: 38px;
  display: grid;
  place-items: center;
  border-radius: 8px;
  color: #fff;
  font-size: 22px;
  background: #2563eb;
  box-shadow: none;
}

.page-main {
  min-height: calc(100vh - 126px);
  display: grid;
  grid-template-columns: minmax(420px, 1fr) 460px;
  align-items: center;
  gap: 6vw;
  padding: 48px 6vw;
}

.hero-section {
  max-width: 760px;
}

.hero-title h1 {
  margin: 0;
  font-size: clamp(34px, 3.6vw, 54px);
  line-height: 1.24;
  font-weight: 700;
  letter-spacing: 0;
}

.hero-title h1 span {
  color: #2563eb;
  text-shadow: none;
}

.hero-title p {
  margin: 20px 0 36px;
  color: #667085;
  font-size: 18px;
  letter-spacing: 0;
}

.visual-area {
  display: flex;
  align-items: center;
  gap: 0;
}

.shield-stage {
  display: none;
}

.feature-list {
  display: grid;
  gap: 12px;
  width: min(560px, 100%);
}

.feature-item {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 14px 16px;
  border: 1px solid #dfe5ee;
  border-radius: 8px;
  background: #ffffff;
}

.feature-icon {
  width: 40px;
  height: 40px;
  flex: none;
  display: grid;
  place-items: center;
  border-radius: 8px;
  font-size: 22px;
  color: #2563eb;
  background: #eff6ff;
  border: 1px solid #bfdbfe;
}

.feature-item h3 {
  margin: 0 0 6px;
  font-size: 16px;
  color: #1f2937;
}

.feature-item p {
  margin: 0;
  font-size: 14px;
  color: #667085;
}

.form-panel {
  width: 100%;
  min-height: 560px;
  padding: 40px 42px 32px;
  border-radius: 8px;
  color: #1f2937;
  background: #ffffff;
  border: 1px solid #dfe5ee;
  box-shadow: 0 8px 22px rgba(15, 23, 42, 0.06);
}

.auth-tabs :deep(.el-tabs__header) {
  margin-bottom: 32px;
}

.auth-tabs :deep(.el-tabs__nav-wrap::after) {
  height: 1px;
  background: #e7ebf2;
}

.auth-tabs :deep(.el-tabs__active-bar) {
  height: 3px;
  background: #2563eb;
}

.auth-tabs :deep(.el-tabs__item) {
  height: 46px;
  font-size: 18px;
  font-weight: 500;
  color: #7c89a3;
}

.auth-tabs :deep(.el-tabs__item.is-active) {
  color: #2563eb;
  font-weight: 700;
}

.form-title {
  margin-bottom: 28px;
}

.form-title h2 {
  margin: 0 0 10px;
  font-size: 26px;
  font-weight: 700;
  color: #1f2937;
}

.form-title p {
  margin: 0;
  font-size: 15px;
  color: #6d7890;
}

.form-panel :deep(.el-input__wrapper) {
  height: 46px;
  border-radius: 8px;
  box-shadow: 0 0 0 1px #dde4ef inset;
  background: #fff;
}

.form-panel :deep(.el-input__wrapper.is-focus) {
  box-shadow: 0 0 0 1px #2563eb inset, 0 0 0 3px rgba(37, 99, 235, 0.1);
}

.form-panel :deep(.el-form-item) {
  margin-bottom: 22px;
}

.form-options {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin: 2px 0 28px;
}

.submit-btn {
  width: 100%;
  height: 46px;
  border: 0;
  border-radius: 8px;
  font-size: 16px;
  font-weight: 700;
  background: #2563eb;
  box-shadow: none;
}

.submit-btn:hover {
  background: #1d4ed8;
  transform: none;
  box-shadow: none;
}

.security-tip {
  margin-top: 32px;
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 8px;
  color: #71809b;
  font-size: 14px;
}

.security-tip .el-icon {
  color: #627390;
}

.page-footer {
  position: relative;
  left: auto;
  bottom: auto;
  padding: 0 6vw 24px;
  color: #98a2b3;
  font-size: 13px;
}

@media (max-width: 1200px) {
  .page-main {
    grid-template-columns: 1fr;
    gap: 28px;
  }

  .form-panel {
    max-width: 560px;
  }

  .page-footer {
    padding: 0 6vw 24px;
  }
}

@media (max-width: 768px) {
  .page-header {
    height: 86px;
    padding: 0 24px;
  }

  .brand-mini span {
    font-size: 16px;
  }

  .page-main {
    padding: 20px 24px 40px;
  }

  .hero-title h1 {
    font-size: 34px;
  }

  .hero-title p {
    font-size: 16px;
    margin-bottom: 34px;
  }

  .visual-area {
    flex-direction: column;
    align-items: flex-start;
  }

  .form-panel {
    min-height: auto;
    padding: 32px 24px 28px;
  }
}
</style>
