import { useEffect, useState } from 'react'
import { sessionsApi, authApi } from '../api/client'
import { useAuth } from '../context/AuthContext'

function formatDate(iso) {
  return new Date(iso).toLocaleString()
}

function SessionCard({ session, isCurrent, onRevoke }) {
  const [revoking, setRevoking] = useState(false)

  const handleRevoke = async () => {
    setRevoking(true)
    try {
      await onRevoke(session.id)
    } finally {
      setRevoking(false)
    }
  }

  return (
    <div className={`bg-gray-800 rounded-xl p-4 border ${isCurrent ? 'border-indigo-500' : 'border-gray-700'}`}>
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-lg">💻</span>
            <span className="text-sm font-medium text-gray-200 truncate">
              {session.device_info || 'Unknown device'}
            </span>
            {isCurrent && (
              <span className="px-2 py-0.5 bg-indigo-600 text-indigo-100 text-xs rounded-full font-medium shrink-0">
                Current
              </span>
            )}
          </div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 mt-2">
            <p className="text-xs text-gray-400">
              <span className="text-gray-500">IP: </span>{session.ip_address || 'Unknown'}
            </p>
            <p className="text-xs text-gray-400">
              <span className="text-gray-500">Created: </span>{formatDate(session.created_at)}
            </p>
            <p className="text-xs text-gray-400 col-span-2">
              <span className="text-gray-500">Last active: </span>{formatDate(session.last_active)}
            </p>
          </div>
        </div>
        {!isCurrent && (
          <button
            onClick={handleRevoke}
            disabled={revoking}
            className="shrink-0 px-3 py-1.5 bg-red-600/20 hover:bg-red-600/40 border border-red-600/40 text-red-400 hover:text-red-300 rounded-lg text-xs font-medium transition-colors disabled:opacity-50"
          >
            {revoking ? 'Revoking...' : 'Revoke'}
          </button>
        )}
      </div>
    </div>
  )
}

function ChangePasswordModal({ onClose }) {
  const [form, setForm] = useState({ current_password: '', new_password: '', confirm: '' })
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (form.new_password !== form.confirm) {
      setError('Passwords do not match')
      return
    }
    setError('')
    setLoading(true)
    try {
      await authApi.changePassword(form.current_password, form.new_password)
      setSuccess(true)
      setTimeout(onClose, 1500)
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to change password')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 rounded-2xl p-6 w-full max-w-md border border-gray-700">
        <h3 className="text-lg font-bold text-white mb-4">Change Password</h3>
        {success ? (
          <div className="text-center py-4">
            <div className="text-4xl mb-2">✅</div>
            <p className="text-green-400 font-medium">Password changed successfully!</p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="bg-red-900/50 border border-red-700 text-red-200 rounded-lg px-4 py-3 text-sm">
                {error}
              </div>
            )}
            {['current_password', 'new_password', 'confirm'].map((field) => (
              <div key={field}>
                <label className="block text-sm text-gray-300 mb-1 capitalize">
                  {field.replace('_', ' ')}
                </label>
                <input
                  type="password"
                  value={form[field]}
                  onChange={(e) => setForm({ ...form, [field]: e.target.value })}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  required
                  minLength={field !== 'current_password' ? 8 : undefined}
                />
              </div>
            ))}
            <div className="flex gap-3 pt-2">
              <button
                type="button"
                onClick={onClose}
                className="flex-1 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading}
                className="flex-1 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-800 text-white rounded-lg text-sm font-medium transition-colors"
              >
                {loading ? 'Saving...' : 'Change Password'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}

export default function Dashboard() {
  const { user } = useAuth()
  const [sessions, setSessions] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [revokeAllLoading, setRevokeAllLoading] = useState(false)
  const [showPasswordModal, setShowPasswordModal] = useState(false)
  const [currentSessionId, setCurrentSessionId] = useState(null)

  const loadSessions = async () => {
    try {
      const res = await sessionsApi.list()
      setSessions(res.data)
    } catch (err) {
      setError('Failed to load sessions')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadSessions()
    // Identify current session from token
    const token = localStorage.getItem('access_token')
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1]))
        setCurrentSessionId(payload.session_id)
      } catch (_) {}
    }
  }, [])

  const handleRevokeSession = async (sessionId) => {
    try {
      await sessionsApi.revoke(sessionId)
      setSessions((prev) => prev.filter((s) => s.id !== sessionId))
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to revoke session')
    }
  }

  const handleRevokeAll = async () => {
    setRevokeAllLoading(true)
    try {
      await sessionsApi.revokeAll()
      await loadSessions()
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to revoke sessions')
    } finally {
      setRevokeAllLoading(false)
    }
  }

  const otherSessions = sessions.filter((s) => s.id !== currentSessionId)

  return (
    <div className="space-y-6">
      {showPasswordModal && <ChangePasswordModal onClose={() => setShowPasswordModal(false)} />}

      {/* Account Info */}
      <div className="bg-gray-900 rounded-2xl p-6 border border-gray-800">
        <h2 className="text-lg font-bold text-white mb-4">Account</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Email', value: user?.email },
            { label: 'Username', value: user?.username },
            {
              label: 'Role',
              value: (
                <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${
                  user?.role === 'admin' ? 'bg-red-600/30 text-red-300' :
                  user?.role === 'manager' ? 'bg-yellow-600/30 text-yellow-300' :
                  'bg-gray-600/30 text-gray-300'
                }`}>
                  {user?.role}
                </span>
              ),
            },
            {
              label: 'Email Verified',
              value: user?.is_verified
                ? <span className="text-green-400">✓ Verified</span>
                : <span className="text-yellow-400">⚠ Unverified</span>,
            },
          ].map(({ label, value }) => (
            <div key={label} className="bg-gray-800 rounded-lg p-3">
              <p className="text-xs text-gray-400 mb-1">{label}</p>
              <p className="text-sm font-medium text-white">{value}</p>
            </div>
          ))}
        </div>
        <button
          onClick={() => setShowPasswordModal(true)}
          className="mt-4 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm transition-colors"
        >
          Change Password
        </button>
      </div>

      {/* Sessions */}
      <div className="bg-gray-900 rounded-2xl p-6 border border-gray-800">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-lg font-bold text-white">Active Sessions</h2>
            <p className="text-sm text-gray-400 mt-0.5">{sessions.length} session{sessions.length !== 1 ? 's' : ''} active</p>
          </div>
          {otherSessions.length > 0 && (
            <button
              onClick={handleRevokeAll}
              disabled={revokeAllLoading}
              className="px-4 py-2 bg-red-600/20 hover:bg-red-600/30 border border-red-600/40 text-red-400 hover:text-red-300 rounded-lg text-sm transition-colors disabled:opacity-50"
            >
              {revokeAllLoading ? 'Revoking...' : `Revoke ${otherSessions.length} other session${otherSessions.length !== 1 ? 's' : ''}`}
            </button>
          )}
        </div>

        {error && (
          <div className="bg-red-900/50 border border-red-700 text-red-200 rounded-lg px-4 py-3 text-sm mb-4">
            {error}
          </div>
        )}

        {loading ? (
          <div className="text-center py-8 text-gray-400">Loading sessions...</div>
        ) : sessions.length === 0 ? (
          <div className="text-center py-8 text-gray-400">No active sessions</div>
        ) : (
          <div className="space-y-3">
            {/* Current session first */}
            {sessions
              .sort((a, b) => (a.id === currentSessionId ? -1 : b.id === currentSessionId ? 1 : 0))
              .map((session) => (
                <SessionCard
                  key={session.id}
                  session={session}
                  isCurrent={session.id === currentSessionId}
                  onRevoke={handleRevokeSession}
                />
              ))}
          </div>
        )}
      </div>

      {/* Token Info Box */}
      <div className="bg-gray-900 rounded-2xl p-6 border border-gray-800">
        <h2 className="text-lg font-bold text-white mb-3">Token Configuration</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: 'Access Token TTL', value: '15 minutes' },
            { label: 'Refresh Token TTL', value: '7 days' },
            { label: 'Rate Limit', value: '5 attempts' },
            { label: 'Block Duration', value: '15 minutes' },
          ].map(({ label, value }) => (
            <div key={label} className="bg-indigo-900/20 border border-indigo-800/40 rounded-lg p-3">
              <p className="text-xs text-indigo-300 mb-1">{label}</p>
              <p className="text-sm font-bold text-indigo-100">{value}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
