import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { authAPI } from '../api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser]       = useState(null)
  const [activeKey, setKey]   = useState(null)
  const [loading, setLoading] = useState(true)

  // On mount, restore session from sessionStorage
  useEffect(() => {
    const token    = sessionStorage.getItem('sv_token')
    const cached   = sessionStorage.getItem('sv_user')
    if (token && cached) {
      try {
        const parsed = JSON.parse(cached)
        setUser(parsed.user)
        setKey(parsed.active_key)
      } catch (_) {}
    }
    setLoading(false)
  }, [])

  const login = useCallback(async (username, password) => {
    const { data } = await authAPI.login(username, password)
    sessionStorage.setItem('sv_token', data.token)
    sessionStorage.setItem('sv_user', JSON.stringify({ user: data.user, active_key: data.active_key }))
    setUser(data.user)
    setKey(data.active_key)
    return data
  }, [])

  const logout = useCallback(() => {
    sessionStorage.removeItem('sv_token')
    sessionStorage.removeItem('sv_user')
    setUser(null)
    setKey(null)
  }, [])

  const refreshMe = useCallback(async () => {
    const { data } = await authAPI.me()
    setUser(data.user)
    setKey(data.active_key)
    sessionStorage.setItem('sv_user', JSON.stringify({ user: data.user, active_key: data.active_key }))
  }, [])

  const isAdmin = user?.system_role === 'admin'
  const token   = sessionStorage.getItem('sv_token')

  return (
    <AuthContext.Provider value={{ user, activeKey, loading, login, logout, refreshMe, isAdmin, token }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}
