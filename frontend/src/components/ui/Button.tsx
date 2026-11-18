// src/components/ui/Button.tsx
import { cn } from '../../lib/utils'

type Variant = 'primary' | 'danger' | 'ghost' | 'success'
type Size = 'sm' | 'md'

const variantCls: Record<Variant, string> = {
  primary: 'bg-sky-600 hover:bg-sky-500 text-white',
  danger:  'bg-red-700 hover:bg-red-600 text-white',
  ghost:   'bg-slate-700 hover:bg-slate-600 text-slate-200',
  success: 'bg-emerald-700 hover:bg-emerald-600 text-white',
}

const sizeCls: Record<Size, string> = {
  sm: 'px-3 py-1.5 text-xs',
  md: 'px-4 py-2 text-sm',
}

export function Button({
  children,
  variant = 'primary',
  size = 'md',
  className,
  disabled,
  onClick,
}: {
  children: React.ReactNode
  variant?: Variant
  size?: Size
  className?: string
  disabled?: boolean
  onClick?: () => void
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={cn(
        'inline-flex items-center gap-2 rounded-lg font-medium transition-colors disabled:opacity-40 disabled:pointer-events-none',
        variantCls[variant],
        sizeCls[size],
        className,
      )}
    >
      {children}
    </button>
  )
}
