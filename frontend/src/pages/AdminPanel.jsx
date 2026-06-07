import { useEffect, useState } from 'react'
import { adminApi } from '../api/client'
import { useAuth } from '../context/AuthContext'
import AuditLogViewer from '../components/AuditLogViewer'

const ROLES = ['user', 'manager', 'admin']
const ROLE_COLORS = {
  admin:   'bg-red-600/30    text-red-300    border-red-600/40',
  manager: 'bg-yellow-600/30 text-yellow-300 border-yellow-600/40',
  user:    'bg-gray-600/30   text-gray-300   border-gray-600/40',
}

const TABS = ['Users', 'Permissions', 'Audit Logs']

function PermissionBadge({ name, onRevoke, userId }) {
  const [removing, setRemoving] = useState(false)
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-blue-900/40 border border-blue-700/40 text-blue-300 rounded text-xs">
      {name}
      <button
        onClick={async () => { setRemoving(true); try { await onRevoke(userId, name) } finally { setRemoving(false) } }}
        disabled={removing}
        className="hover:text-red-400 transition-colors"
      >
        {removing ? '…' : '×'}
      </button>
    </span>
  )
}

function UserRow({ user, currentUserId, allPermissions, onRoleChange, onToggleActive, onDelete, onGrantPerm, onRevokePerm }) {
  const [roleLoading, setRoleLoading] = useState(false)
  const [selectedPerm, setSelectedPerm] = useState('')
  const [grantLoading, setGrantLoading] = useState(false)
  const isSelf = user.id === currentUserId
  const unownedPerms = allPermissions.filter((p) => !user.permissions.includes(p.name))

  return (
    <tr className="border-b border-gray-800 hover:bg-gray-800/40 transition-colors">
      <td className="px-4 py-3">
        <p className="text-sm font-medium text-white">{user.username}</p>
        <p className="text-xs text-gray-400">{user.email}</p>
        {user.account_locked_until && new Date(user.account_locked_until) > new Date() && (
          <span className="inline-block mt-0.5 px-1.5 py-0.5 bg-red-900/40 text-red-400 text-xs rounded">🔒 locked</span>
        )}
      </td>
      <td className="px-4 py-3">
        {isSelf ? (
          <span className={`inline-block px-2 py-0.5 rounded border text-xs font-bold uppercase ${ROLE_COLORS[user.role]}`}>
            {user.role}
          </span>
        ) : (
          <select
            value={user.role}
            onChange={async (e) => { setRoleLoading(true); try { await onRoleChange(user.id, e.target.value) } finally { setRoleLoading(false) } }}
            disabled={roleLoading}
            className="bg-gray-800 border border-gray-700 text-gray-200 rounded px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-indigo-500"
          >
            {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        )}
      </td>
      <td className="px-4 py-3">
        <div className="flex flex-wrap gap-1 max-w-xs">
          {user.permissions.map((p) => (
            <PermissionBadge key={p} name={p} userId={user.id} onRevoke={onRevokePerm} />
          ))}
          {unownedPerms.length > 0 && (
            <div className="flex items-center gap-1">
              <select
                value={selectedPerm}
                onChange={(e) => setSelectedPerm(e.target.value)}
                className="bg-gray-800 border border-gray-700 text-gray-400 rounded px-1 py-0.5 text-xs"
              >
                <option value="">+ Add</option>
                {unownedPerms.map((p) => <option key={p.id} value={p.name}>{p.name}</option>)}
              </select>
              {selectedPerm && (
                <button
                  onClick={async () => { setGrantLoading(true); try { await onGrantPerm(user.id, selectedPerm); setSelectedPerm('') } finally { setGrantLoading(false) } }}
                  disabled={grantLoading}
                  className="px-1.5 py-0.5 bg-blue-600/30 hover:bg-blue-600/50 text-blue-300 rounded text-xs"
                >
                  Grant
                </button>
              )}
            </div>
          )}
        </div>
      </td>
      <td className="px-4 py-3">
        <span className={`px-2 py-0.5 rounded text-xs font-medium ${user.is_active ? 'bg-green-900/40 text-green-400' : 'bg-red-900/40 text-red-400'}`}>
          {user.is_active ? 'Active' : 'Disabled'}
        </span>
      </td>
      <td className="px-4 py-3">
        <span className={`text-xs ${user.is_verified ? 'text-green-400' : 'text-yellow-400'}`}>
          {user.is_verified ? '✓' : '⚠'}
        </span>
      </td>
      <td className="px-4 py-3">
        {!isSelf && (
          <div className="flex gap-2">
            <button
              onClick={() => onToggleActive(user.id, !user.is_active)}
              className={`px-2 py-1 rounded text-xs transition-colors ${user.is_active ? 'bg-yellow-600/20 hover:bg-yellow-600/40 text-yellow-400' : 'bg-green-600/20 hover:bg-green-600/40 text-green-400'}`}
            >
              {user.is_active ? 'Disable' : 'Enable'}
            </button>
            <button
              onClick={() => onDelete(user.id)}
              className="px-2 py-1 bg-red-600/20 hover:bg-red-600/40 text-red-400 rounded text-xs"
            >
              Delete
            </button>
          </div>
        )}
      </td>
    </tr>
  )
}

function UsersTab({ currentUser }) {
  const [users, setUsers] = useState([])
  const [allPermissions, setAllPermissions] = useState([])
  const [total, setTotal] = useState(0)
  const [pages, setPages] = useState(1)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [roleFilter, setRoleFilter] = useState('')
  const [newPermName, setNewPermName] = useState('')

  const loadData = async (p = page) => {
    setLoading(true)
    try {
      const params = { page: p, limit: 15 }
      if (search) params.search = search
      if (roleFilter) params.role = roleFilter
      const [usersRes, permsRes] = await Promise.all([
        adminApi.listUsers(params),
        adminApi.listPermissions(),
      ])
      setUsers(usersRes.data.items)
      setTotal(usersRes.data.total)
      setPages(usersRes.data.pages)
      setAllPermissions(permsRes.data)
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load data')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadData(1); setPage(1) }, [search, roleFilter])
  useEffect(() => { loadData(page) }, [page])

  const setErr = (e) => setError(e?.response?.data?.detail || String(e))

  const handleRoleChange = async (id, role) => {
    try { await adminApi.updateRole(id, role); setUsers((p) => p.map((u) => u.id === id ? { ...u, role } : u)) }
    catch (e) { setErr(e) }
  }
  const handleToggleActive = async (id, active) => {
    try { await adminApi.toggleActive(id, active); setUsers((p) => p.map((u) => u.id === id ? { ...u, is_active: active } : u)) }
    catch (e) { setErr(e) }
  }
  const handleDelete = async (id) => {
    if (!window.confirm('Delete this user permanently?')) return
    try { await adminApi.deleteUser(id); setUsers((p) => p.filter((u) => u.id !== id)); setTotal((t) => t - 1) }
    catch (e) { setErr(e) }
  }
  const handleGrantPerm = async (id, permission) => {
    try { await adminApi.grantPermission(id, permission); setUsers((p) => p.map((u) => u.id === id ? { ...u, permissions: [...u.permissions, permission] } : u)) }
    catch (e) { setErr(e) }
  }
  const handleRevokePerm = async (id, permission) => {
    try { await adminApi.revokePermission(id, permission); setUsers((p) => p.map((u) => u.id === id ? { ...u, permissions: u.permissions.filter((pp) => pp !== permission) } : u)) }
    catch (e) { setErr(e) }
  }

  return (
    <div className="space-y-4">
      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Total Users', value: total, color: 'indigo' },
          { label: 'Admins', value: users.filter((u) => u.role === 'admin').length, color: 'red' },
          { label: 'Managers', value: users.filter((u) => u.role === 'manager').length, color: 'yellow' },
          { label: 'Active', value: users.filter((u) => u.is_active).length, color: 'green' },
        ].map(({ label, value, color }) => (
          <div key={label} className={`bg-${color}-900/20 border border-${color}-800/40 rounded-xl p-4`}>
            <p className={`text-xs text-${color}-400 mb-1`}>{label}</p>
            <p className={`text-2xl font-bold text-${color}-200`}>{value}</p>
          </div>
        ))}
      </div>

      {error && (
        <div className="bg-red-900/50 border border-red-700 text-red-200 rounded-lg px-4 py-3 text-sm flex justify-between">
          {error}
          <button onClick={() => setError('')} className="text-red-400">×</button>
        </div>
      )}

      {/* User Table */}
      <div className="bg-gray-900 rounded-2xl border border-gray-800 overflow-hidden">
        <div className="p-4 border-b border-gray-800 flex items-center gap-3 flex-wrap">
          <input
            type="text" value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by email or username…"
            className="flex-1 min-w-[200px] bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
          <select
            value={roleFilter} onChange={(e) => setRoleFilter(e.target.value)}
            className="bg-gray-800 border border-gray-700 text-gray-300 rounded-lg px-3 py-2 text-sm"
          >
            <option value="">All roles</option>
            {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
          <span className="text-sm text-gray-400">{total} user{total !== 1 ? 's' : ''}</span>
        </div>

        {loading ? (
          <div className="text-center py-10 text-gray-400">Loading…</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-gray-800 bg-gray-800/50">
                  {['User', 'Role', 'Permissions', 'Status', 'Verified', 'Actions'].map((h) => (
                    <th key={h} className="px-4 py-3 text-xs font-semibold text-gray-400 uppercase">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {users.length === 0 ? (
                  <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-400">No users found</td></tr>
                ) : users.map((u) => (
                  <UserRow key={u.id} user={u} currentUserId={currentUser?.id}
                    allPermissions={allPermissions}
                    onRoleChange={handleRoleChange} onToggleActive={handleToggleActive}
                    onDelete={handleDelete} onGrantPerm={handleGrantPerm} onRevokePerm={handleRevokePerm}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {pages > 1 && (
          <div className="px-4 py-3 border-t border-gray-800 flex items-center justify-between">
            <span className="text-sm text-gray-400">Page {page} of {pages}</span>
            <div className="flex gap-2">
              <button onClick={() => setPage(Math.max(1, page - 1))} disabled={page === 1}
                className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 disabled:opacity-40 text-white rounded text-sm">
                ← Prev
              </button>
              <button onClick={() => setPage(Math.min(pages, page + 1))} disabled={page === pages}
                className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 disabled:opacity-40 text-white rounded text-sm">
                Next →
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function PermissionsTab() {
  const [permissions, setPermissions] = useState([])
  const [newPerm, setNewPerm] = useState('')
  const [loading, setLoading] = useState(true)
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState('')

  const load = async () => {
    try { const res = await adminApi.listPermissions(); setPermissions(res.data) }
    catch (e) { setError('Failed to load permissions') }
    finally { setLoading(false) }
  }
  useEffect(() => { load() }, [])

  const handleCreate = async (e) => {
    e.preventDefault()
    if (!newPerm.trim()) return
    setCreating(true)
    try {
      const resp = await fetch('/api/v1/admin/permissions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${localStorage.getItem('access_token')}` },
        body: JSON.stringify({ permission: newPerm.trim() }),
      })
      if (resp.ok) { setNewPerm(''); load() }
      else { const e = await resp.json(); setError(e.detail || 'Failed') }
    } finally { setCreating(false) }
  }

  return (
    <div className="space-y-4">
      {error && <div className="bg-red-900/50 border border-red-700 text-red-200 rounded-lg px-4 py-3 text-sm">{error}</div>}
      <div className="bg-gray-900 rounded-2xl p-6 border border-gray-800">
        <h3 className="text-base font-bold text-white mb-4">System Permissions</h3>
        {loading ? <p className="text-gray-400">Loading…</p> : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-6">
            {permissions.map((p) => (
              <div key={p.id} className="flex items-start gap-3 bg-gray-800 rounded-lg p-3">
                <span className="text-blue-400 font-mono text-sm font-medium">{p.name}</span>
                {p.description && <span className="text-gray-400 text-xs mt-0.5">{p.description}</span>}
              </div>
            ))}
          </div>
        )}
        <form onSubmit={handleCreate} className="flex gap-2">
          <input type="text" value={newPerm} onChange={(e) => setNewPerm(e.target.value)}
            placeholder="new_permission_name"
            className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
          <button type="submit" disabled={creating || !newPerm.trim()}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-gray-700 text-white rounded-lg text-sm font-medium transition-colors">
            Add Permission
          </button>
        </form>
      </div>
    </div>
  )
}

export default function AdminPanel() {
  const { user: currentUser } = useAuth()
  const [activeTab, setActiveTab] = useState('Users')

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Admin Panel</h1>
          <p className="text-gray-400 text-sm mt-1">Manage users, roles, permissions, and audit logs</p>
        </div>
        <div className="bg-red-900/30 border border-red-700/50 rounded-lg px-3 py-1.5">
          <span className="text-red-300 text-xs font-bold uppercase">Admin Access</span>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-gray-900 rounded-xl p-1 border border-gray-800 w-fit">
        {TABS.map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              activeTab === tab
                ? 'bg-indigo-600 text-white'
                : 'text-gray-400 hover:text-white hover:bg-gray-800'
            }`}
          >
            {tab === 'Audit Logs' && '📋 '}
            {tab}
          </button>
        ))}
      </div>

      {activeTab === 'Users'       && <UsersTab currentUser={currentUser} />}
      {activeTab === 'Permissions' && <PermissionsTab />}
      {activeTab === 'Audit Logs'  && <AuditLogViewer />}
    </div>
  )
}
