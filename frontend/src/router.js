import { createRouter, createWebHistory } from 'vue-router'

import { ensureAuthenticatedUser } from './auth.js'
import { getCurrentUser } from './api/index.js'
import AppLayout from './components/AppShell.vue'
import AssetDetail from './views/AssetDetail.vue'
import AssetList from './views/AssetList.vue'
import Dashboard from './views/Dashboard.vue'
import Login from './views/Login.vue'
import RiskList from './views/RiskList.vue'
import UserManagement from './views/UserManagement.vue'

const routes = [
  {
    path: '/login',
    component: Login,
    meta: { public: true },
  },
  {
    path: '/',
    component: AppLayout,
    meta: { requiresAuth: true },
    children: [
      { path: '', redirect: '/dashboard' },
      { path: 'dashboard', component: Dashboard },
      { path: 'assets', component: AssetList },
      { path: 'assets/:id', component: AssetDetail },
      { path: 'risks', component: RiskList },
      { path: 'users', component: UserManagement, meta: { requiresAdmin: true } },
    ],
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach(async (to) => {
  if (to.meta.public) {
    try {
      await ensureAuthenticatedUser(getCurrentUser)
      const redirect = typeof to.query.redirect === 'string' ? to.query.redirect : '/dashboard'
      return redirect
    } catch {
      return true
    }
  }

  if (!to.meta.requiresAuth) {
    return true
  }

  try {
    const user = await ensureAuthenticatedUser(getCurrentUser)
    if (to.meta.requiresAdmin && user?.role !== 'admin') {
      return '/dashboard'
    }
    return true
  } catch {
    return {
      path: '/login',
      query: { redirect: to.fullPath },
    }
  }
})

export default router
