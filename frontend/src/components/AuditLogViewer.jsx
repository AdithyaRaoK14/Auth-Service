import { useEffect, useState } from 'react'
import { auditApi } from '../api/client'

const ACTION_COLORS = {
  USER_REGISTERED:               'text-green-400  bg-green-900/20  border-green-800/40',
  USER_LOGIN:                    'text-blue-400   bg-blue-900/20   border-blue-800/40',
  USER_LOGOUT:                   'text-gray-400   bg-gray-800/40   border-gray-700/40',
  USER_LOGIN_FAILED:             'text-yellow-400 bg-yellow-900/20 border-yellow-800/40',
  USER_EMAIL_VERIFIED:           'text-teal-400   bg-teal-900/20   border-teal-800/40',
  USER_PASSWORD_RESET:           'text-purple-400 bg-purple-900/20 border-purple-800/40',
  USER_PASSWORD_CHANGED:         'text-purple-400 bg-purple-900/20 border-purple-800/40',
  USER_PASSWORD_RESET_REQUESTED: 'text-purple-300 bg-purple-900/10 border-purple-800/30',
  ACCOUNT_LOCKED:                'text-red-400    bg-red-900/30    border-red-700/50',
  ACCOUNT_UNLOCKED:              'text-green-400  bg-green-900/20  border-green-800/40',
  SESSION_REVOKED:               'text-orange-400 bg-orange-900/20 border-orange-800/40',
  SESSION_ALL_REVOKED:           'text-orange-500 bg-orange-900/30 border-orange-700/50',
  REFRESH_TOKEN_REUSE_DETECTED:  'text-red-500    bg-red-900/40    border-red-600/60',
  ADMIN_ROLE_CHANGED:            'text-indigo-400 bg-indigo-900/20 border-indigo-800/40',
  ADMIN_USER_DELETED:            'text-red-400    bg-red-900/20    border-red-800/40',
  ADMIN_USER_DISABLED:           'text-yellow-400 bg-yellow-900/20 border-yellow-800/40',
  ADMIN_USER_ENABLED:            'text-green-400  bg-green-900/20  border-green-800/40',
  ADMIN_PERMISSION_GRANTED:      'text-cyan-400   bg-cyan-900/20   border-cyan-800/40',
  ADMIN_PERMISSION_REVOKED:      'text-cyan-300   bg-cyan-900/10   border-cyan-800/30',
}

const ACTION_ICONS = {
  USER_REGISTERED:               '👤',
  USER_LOGIN:                    '🔑',
  USER_LOGOUT:                   '🚪',
  USER_LOGIN_FAILED:             '⚠️',
  USER_EMAIL_VERIFIED:           '✉️',
  USER_PASSWORD_RESET:           '🔒',
  USER_PASSWORD_CHANGED:         '🔐',
  USER_PASSWORD_RESET_REQUESTED: '📧',
  ACCOUNT_LOCKED:                '🔒',
  ACCOUNT_UNLOCKED:              '🔓',
  SESSION_REVOKED:               '📵',
  SESSION_ALL_REVOKED:           '🚫',
  REFRESH_TOKEN_REUSE_DETECTED:  '🚨',
  ADMIN_ROLE_CHANGED:            '👑',
  ADMIN_USER_DELETED:            '🗑️',
  ADMIN_USER_DISABLED:           '⛔',
  ADMIN_USER_ENABLED:            '✅',
  ADMIN_PERMISSION_GRANTED:      '✨',
  ADMIN_PERMISSION_REVOKED:      '❌',
}

function shortUUID(id) {
  if (!id) return '—'
  return id.slice(0, 8) + '…'
}

function MetadataView({ meta }) {
  if (!meta || Object.keys(meta).length === 0) return <span className="text-gray-600">—</span>
  return (
    <div className="flex flex-wrap gap-1">
      {Object.entries(meta).map(([k, v]) => (
        <span key={k} className="inline-block px-1.5 py-0.5 bg-gray-800 rounded text-xs text-gray-400 font-mono">
          <span className="text-gray-500">{k}:</span> {String(v).slice(0, 40)}
        </span>
      ))}
    </div>
  )
}

const ALL_ACTIONS = Object.keys(ACTION_COLORS)

export default function AuditLogViewer() {
  const [logs, setLogs] = useState([])
  const [total, setTotal] = useState(0)
  const [pages, setPages] = useState(1)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [actionFilter, setActionFilter] = useState('')
  const [autoRefresh, setAutoRefresh] = useState(false)

  const loadLogs = async (p = page) => {
    setLoading(true)
    try {
      const params = { page: p, limit: 25 }
      if (actionFilter) params.action = actionFilter
      const res = await auditApi.list(params)
      setLogs(res.data.items)
      setTotal(res.data.total)
      setPages(res.data.pages)
    } catch (err) {
      setError('Failed to load audit logs')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadLogs(1); setPage(1) }, [actionFilter])
  useEffect(() => { loadLogs(page) }, [page])

  useEffect(() => {
    if (!autoRefresh) return
    const id = setInterval(() => loadLogs(page), 5000)
    return () => clearInterval(id)
  }, [autoRefresh, page, actionFilter])

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="flex items-center gap-3 flex-wrap">
        <select
          value={actionFilter}
          onChange={(e) => setActionFilter(e.target.value)}
          className="bg-gray-800 border border-gray-700 text-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          <option value="">All actions</option>
          {ALL_ACTIONS.map((a) => (
            <option key={a} value={a}>{a}</option>
          ))}
        </select>

        <button
          onClick={() => loadLogs(page)}
          className="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm transition-colors"
        >
          Refresh
        </button>

        <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer">
          <div
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`w-9 h-5 rounded-full transition-colors relative cursor-pointer ${autoRefresh ? 'bg-indigo-600' : 'bg-gray-700'}`}
          >
            <div className={`absolute top-0.5 w-4 h-4 bg-white rounded-full transition-transform ${autoRefresh ? 'translate-x-4' : 'translate-x-0.5'}`} />
          </div>
          Live ({autoRefresh ? 'on' : 'off'})
        </label>

        <span className="ml-auto text-sm text-gray-400">{total.toLocaleString()} total events</span>
      </div>

      {error && (
        <div className="bg-red-900/50 border border-red-700 text-red-200 rounded-lg px-4 py-3 text-sm">
          {error}
        </div>
      )}

      {/* Log Table */}
      <div className="bg-gray-900 rounded-2xl border border-gray-800 overflow-hidden">
        {loading && logs.length === 0 ? (
          <div className="text-center py-12 text-gray-400">Loading audit logs…</div>
        ) : logs.length === 0 ? (
          <div className="text-center py-12 text-gray-400">No audit events found</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-gray-800 bg-gray-800/50">
                  {['Time', 'Action', 'Actor', 'Target', 'IP', 'Metadata'].map((h) => (
                    <th key={h} className="px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wide">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => {
                  const colorClass = ACTION_COLORS[log.action] || 'text-gray-400 bg-gray-800/20 border-gray-700/40'
                  const icon = ACTION_ICONS[log.action] || '•'
                  return (
                    <tr key={log.id} className="border-b border-gray-800/60 hover:bg-gray-800/30 transition-colors">
                      <td className="px-4 py-2.5">
                        <span className="text-xs text-gray-400 font-mono whitespace-nowrap">
                          {new Date(log.created_at).toLocaleString()}
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-medium whitespace-nowrap ${colorClass}`}>
                          {icon} {log.action}
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="text-xs text-gray-400 font-mono" title={log.actor_user_id}>
                          {log.actor_user_id ? shortUUID(log.actor_user_id) : <span className="text-gray-600">system</span>}
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="text-xs text-gray-400 font-mono" title={log.target_user_id}>
                          {log.target_user_id ? shortUUID(log.target_user_id) : <span className="text-gray-600">—</span>}
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="text-xs text-gray-500 font-mono">{log.ip_address || '—'}</span>
                      </td>
                      <td className="px-4 py-2.5 max-w-xs">
                        <MetadataView meta={log.metadata_} />
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pagination */}
      {pages > 1 && (
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-400">
            Page {page} of {pages}
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => setPage(Math.max(1, page - 1))}
              disabled={page === 1}
              className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 disabled:opacity-40 text-white rounded text-sm transition-colors"
            >
              ← Prev
            </button>
            {Array.from({ length: Math.min(pages, 7) }, (_, i) => {
              const p = page <= 4 ? i + 1 : page - 3 + i
              if (p < 1 || p > pages) return null
              return (
                <button
                  key={p}
                  onClick={() => setPage(p)}
                  className={`px-3 py-1.5 rounded text-sm transition-colors ${
                    p === page
                      ? 'bg-indigo-600 text-white'
                      : 'bg-gray-800 hover:bg-gray-700 text-gray-300'
                  }`}
                >
                  {p}
                </button>
              )
            })}
            <button
              onClick={() => setPage(Math.min(pages, page + 1))}
              disabled={page === pages}
              className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 disabled:opacity-40 text-white rounded text-sm transition-colors"
            >
              Next →
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
