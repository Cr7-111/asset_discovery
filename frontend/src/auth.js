import { shallowRef } from 'vue'

const STORAGE_KEY = 'asset-discovery-user'

function loadStoredUser() {
  if (typeof window === 'undefined') {
    return null
  }

  const raw = window.localStorage.getItem(STORAGE_KEY)
  if (!raw) {
    return null
  }

  try {
    return JSON.parse(raw)
  } catch {
    window.localStorage.removeItem(STORAGE_KEY)
    return null
  }
}

export const authUser = shallowRef(loadStoredUser())

let sessionChecked = false
let authPromise = null

export function getAuthenticatedUser() {
  return authUser.value
}

export function setAuthenticatedUser(user) {
  authUser.value = user
  sessionChecked = true

  if (typeof window !== 'undefined') {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(user))
  }
}

export function clearAuthenticatedUser(markChecked = true) {
  authUser.value = null
  sessionChecked = markChecked

  if (typeof window !== 'undefined') {
    window.localStorage.removeItem(STORAGE_KEY)
  }
}

export function hasValidatedSession() {
  return sessionChecked
}

export async function ensureAuthenticatedUser(loader) {
  if (sessionChecked) {
    if (authUser.value) {
      return authUser.value
    }
    throw new Error('AUTH_REQUIRED')
  }

  if (!authPromise) {
    authPromise = loader()
      .then((user) => {
        setAuthenticatedUser(user)
        return user
      })
      .catch((error) => {
        clearAuthenticatedUser(true)
        throw error
      })
      .finally(() => {
        authPromise = null
      })
  }

  return authPromise
}
