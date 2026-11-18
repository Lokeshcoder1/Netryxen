// src/components/layout/AppLayout.tsx
import { Outlet } from 'react-router-dom'
import { Sidebar } from './Sidebar'

export function AppLayout() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex">
      <Sidebar />
      <div className="flex-1 ml-56 flex flex-col min-h-screen overflow-auto">
        <Outlet />
      </div>
    </div>
  )
}
