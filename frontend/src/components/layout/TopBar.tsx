// src/components/layout/TopBar.tsx
import { useQuery } from '@tanstack/react-query'
import { getHealthLive } from '../../lib/api'
import { Wifi, WifiOff } from 'lucide-react'

export function TopBar({ title }: { title: string }) {
  const { data, isError } = useQuery({
    queryKey: ['health'],
    queryFn: getHealthLive,
    refetchInterval: 10_000,
    retry: false,
  })

  const online = !!data && !isError

  return (
    <header className="sticky top-0 z-20 flex items-center justify-between h-14 px-6 border-b border-slate-700/50 bg-slate-900/80 backdrop-blur">
      <h1 className="text-base font-semibold text-slate-100">{title}</h1>
      <div className={`flex items-center gap-1.5 text-xs font-medium ${online ? 'text-emerald-400' : 'text-red-400'}`}>
        {online ? <Wifi className="w-4 h-4" /> : <WifiOff className="w-4 h-4" />}
        {online ? 'Backend Online' : 'Backend Offline'}
      </div>
    </header>
  )
}
