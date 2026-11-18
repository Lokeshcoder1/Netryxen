// src/components/ui/Badge.tsx
import { cn } from '../../lib/utils'

type Variant = 'default' | 'success' | 'warning' | 'danger' | 'info' | 'muted'

const variants: Record<Variant, string> = {
  default:  'bg-slate-700 text-slate-200',
  success:  'bg-emerald-900/60 text-emerald-300 border border-emerald-700/40',
  warning:  'bg-amber-900/60 text-amber-300 border border-amber-700/40',
  danger:   'bg-red-900/60 text-red-300 border border-red-700/40',
  info:     'bg-sky-900/60 text-sky-300 border border-sky-700/40',
  muted:    'bg-slate-800 text-slate-400',
}

export function Badge({
  children,
  variant = 'default',
  className,
}: {
  children: React.ReactNode
  variant?: Variant
  className?: string
}) {
  return (
    <span className={cn('inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium', variants[variant], className)}>
      {children}
    </span>
  )
}
