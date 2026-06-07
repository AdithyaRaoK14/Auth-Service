import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { authApi } from '../api/client'

export default function Register() {
  const [form, setForm] = useState({ email: '', username: '', password: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [verificationToken, setVerificationToken] = useState(null)
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await authApi.register(form)
      setVerificationToken(res.data.verification_token)
    } catch (err) {
      const detail = err.response?.data?.detail
      setError(Array.isArray(detail) ? detail[0]?.msg : detail || 'Registration failed')
    } finally {
      setLoading(false)
    }
  }

  const handleVerify = async () => {
    try {
      await authApi.verifyEmail(verificationToken)
      navigate('/login')
    } catch (err) {
      setError(err.response?.data?.detail || 'Verification failed')
    }
  }

  if (verificationToken) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
        <div className="w-full max-w-md bg-gray-900 rounded-2xl p-8 border border-gray-800">
          <div className="text-center mb-6">
            <div className="text-4xl mb-3">📧</div>
            <h2 className="text-2xl font-bold text-white">Verify Your Email</h2>
            <p className="text-gray-400 mt-1 text-sm">
              In a real app, this token would be emailed to you.
              For testing, use it directly below.
            </p>
          </div>

          {error && (
            <div className="bg-red-900/50 border border-red-700 text-red-200 rounded-lg px-4 py-3 text-sm mb-4">
              {error}
            </div>
          )}

          <div className="bg-gray-800 rounded-lg p-4 mb-6">
            <p className="text-xs text-gray-400 mb-1 uppercase tracking-wide font-medium">Verification Token</p>
            <p className="text-green-400 font-mono text-xs break-all">{verificationToken}</p>
          </div>

          <button
            onClick={handleVerify}
            className="w-full bg-green-600 hover:bg-green-500 text-white font-semibold py-2.5 rounded-lg transition-colors mb-3"
          >
            Verify Email & Continue
          </button>
          <button
            onClick={() => navigate('/login')}
            className="w-full bg-gray-700 hover:bg-gray-600 text-white font-semibold py-2.5 rounded-lg transition-colors"
          >
            Skip for now (login without verification)
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="text-5xl mb-3">🔐</div>
          <h1 className="text-3xl font-bold text-white">Create Account</h1>
          <p className="text-gray-400 mt-1">Get started with Auth Service</p>
        </div>

        <form onSubmit={handleSubmit} className="bg-gray-900 rounded-2xl p-8 border border-gray-800 space-y-5">
          {error && (
            <div className="bg-red-900/50 border border-red-700 text-red-200 rounded-lg px-4 py-3 text-sm">
              {error}
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">Email</label>
            <input
              type="email"
              value={form.email}
              onChange={(e) => setForm({ ...form, email: e.target.value })}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              placeholder="you@example.com"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">Username</label>
            <input
              type="text"
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              placeholder="johndoe"
              minLength={3}
              maxLength={50}
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">Password</label>
            <input
              type="password"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              placeholder="Min 8 characters"
              minLength={8}
              required
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-800 disabled:cursor-not-allowed text-white font-semibold py-2.5 rounded-lg transition-colors"
          >
            {loading ? 'Creating account...' : 'Create Account'}
          </button>

          <p className="text-center text-sm text-gray-400">
            Already have an account?{' '}
            <Link to="/login" className="text-indigo-400 hover:text-indigo-300 font-medium">
              Sign in
            </Link>
          </p>
        </form>
      </div>
    </div>
  )
}
