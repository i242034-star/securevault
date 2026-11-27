import { Navigate, Outlet } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'

export default function AdminRoute() {
  const { isAdmin } = useAuth()
  // Backend is the real authority — this is a UX guard only
  return isAdmin ? <Outlet /> : <Navigate to="/dashboard" replace />
}
