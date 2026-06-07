import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
})

// ─── Request interceptor: attach access token ──────────────────────────────
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// ─── Response interceptor: auto-refresh on 401 ────────────────────────────
let isRefreshing = false
let failedQueue = []

const processQueue = (error, token = null) => {
  failedQueue.forEach((prom) => {
    if (error) prom.reject(error)
    else prom.resolve(token)
  })
  failedQueue = []
}

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config

    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject })
        })
          .then((token) => {
            originalRequest.headers.Authorization = `Bearer ${token}`
            return api(originalRequest)
          })
          .catch((err) => Promise.reject(err))
      }

      originalRequest._retry = true
      isRefreshing = true

      const refreshToken = localStorage.getItem('refresh_token')
      if (!refreshToken) {
        isRefreshing = false
        window.location.href = '/login'
        return Promise.reject(error)
      }

      try {
        const { data } = await axios.post('/api/v1/auth/refresh', {
          refresh_token: refreshToken,
        })
        localStorage.setItem('access_token', data.access_token)
        localStorage.setItem('refresh_token', data.refresh_token)
        api.defaults.headers.Authorization = `Bearer ${data.access_token}`
        processQueue(null, data.access_token)
        originalRequest.headers.Authorization = `Bearer ${data.access_token}`
        return api(originalRequest)
      } catch (refreshError) {
        processQueue(refreshError, null)
        localStorage.clear()
        window.location.href = '/login'
        return Promise.reject(refreshError)
      } finally {
        isRefreshing = false
      }
    }

    return Promise.reject(error)
  }
)

export default api

// ─── Auth API ──────────────────────────────────────────────────────────────
export const authApi = {
  register: (data) => api.post('/auth/register', data),
  login: (data) => api.post('/auth/login', data),
  logout: (refreshToken) => api.post('/auth/logout', { refresh_token: refreshToken }),
  me: () => api.get('/auth/me'),
  verifyEmail: (token) => api.post('/auth/verify-email', { token }),
  forgotPassword: (email) => api.post('/auth/forgot-password', { email }),
  resetPassword: (token, newPassword) =>
    api.post('/auth/reset-password', { token, new_password: newPassword }),
  changePassword: (currentPassword, newPassword) =>
    api.post('/auth/change-password', {
      current_password: currentPassword,
      new_password: newPassword,
    }),
}

// ─── Sessions API ──────────────────────────────────────────────────────────
export const sessionsApi = {
  list: () => api.get('/users/sessions'),
  revoke: (sessionId) => api.delete(`/users/sessions/${sessionId}`),
  revokeAll: () => api.delete('/users/sessions'),
  revokeAllForce: () => api.delete('/users/sessions/all/force'),
}

// ─── Admin API ─────────────────────────────────────────────────────────────
export const adminApi = {
  listUsers: (params) => api.get('/admin/users', { params }),
  getUser: (id) => api.get(`/admin/users/${id}`),
  updateRole: (id, role) => api.put(`/admin/users/${id}/role`, { role }),
  toggleActive: (id, active) =>
    api.put(`/admin/users/${id}/active`, null, { params: { active } }),
  deleteUser: (id) => api.delete(`/admin/users/${id}`),
  listPermissions: () => api.get('/admin/permissions'),
  grantPermission: (userId, permission) =>
    api.post(`/admin/users/${userId}/permissions`, { permission }),
  revokePermission: (userId, permission) =>
    api.delete(`/admin/users/${userId}/permissions/${permission}`),
}

// ─── Audit Logs API ────────────────────────────────────────────────────────
export const auditApi = {
  list: (params) => api.get('/admin/audit-logs', { params }),
}
