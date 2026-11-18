// src/components/ui/StatTile.tsx
import { cn } from '../../lib/utils'

export function StatTile({
  label,
  value,
  sub,
  icon: Icon,
  accent = 'sky',
  className,
}: {
  label: string
  value: string | number
  sub?: string
  icon?: React.ElementType
  accent?: 'sky' | 'emerald' | 'amber' | 'red' | 'violet'
  className?: string
}) {
  const accents = {
    sky:     'text-sky-400 bg-sky-900/30',
    emerald: 'text-emerald-400 bg-emerald-900/30',
    amber:   'text-amber-400 bg-amber-900/30',
    red:     'text-red-400 bg-red-900/30',
    violet:  'text-violet-400 bg-violet-900/30',
  }
  return (
    <div className={cn('rounded-xl border border-slate-700/50 bg-slate-800/60 p-5 flex items-start gap-4', className)}>
      {Icon && (
        <div className={cn('rounded-lg p-2.5 shrink-0', accents[accent])}>
          <Icon className="w-5 h-5" />
        </div>
      )}
      <div className="min-w-0">
        <p className="text-xs text-slate-400 uppercase tracking-wider truncate">{label}</p>
        <p className="text-2xl font-bold text-slate-100 mt-0.5 leading-none">{value}</p>
        {sub && <p className="text-xs text-slate-500 mt-1 truncate">{sub}</p>}
      </div>
    </div>
  )
}
