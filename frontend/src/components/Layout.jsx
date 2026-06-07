import { Link, Outlet, useLocation } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export default function Layout() {
  const { user, logout } = useAuth()
  const location = useLocation()

  const navLink = (to, label) => (
    <Link
      to={to}
      className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
        location.pathname.startsWith(to)
          ? 'bg-indigo-700 text-white'
          : 'text-indigo-100 hover:bg-indigo-700'
      }`}
    >
      {label}
    </Link>
  )

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <nav className="bg-indigo-900 border-b border-indigo-800 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-xl font-bold text-white">🔐 AuthService</span>
          <div className="ml-6 flex gap-2">
            {navLink('/dashboard', 'Dashboard')}
            {user?.role === 'admin' && navLink('/admin', 'Admin Panel')}
          </div>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-sm text-indigo-200">
            <span className="font-medium text-white">{user?.username}</span>
            <span className={`ml-2 px-2 py-0.5 rounded text-xs font-bold uppercase ${
              user?.role === 'admin' ? 'bg-red-600' :
              user?.role === 'manager' ? 'bg-yellow-600' : 'bg-gray-600'
            }`}>
              {user?.role}
            </span>
          </span>
          <button
            onClick={logout}
            className="px-3 py-1.5 bg-indigo-700 hover:bg-indigo-600 rounded text-sm transition-colors"
          >
            Logout
          </button>
        </div>
      </nav>
      <main className="max-w-6xl mx-auto p-6">
        <Outlet />
      </main>
    </div>
  )
}
