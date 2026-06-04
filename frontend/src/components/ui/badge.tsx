import { cn } from '@/lib/utils'

interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: 'default' | 'success' | 'warning' | 'destructive' | 'outline' | 'secondary'
}

export function Badge({ className, variant = 'default', ...props }: BadgeProps) {
  const variants = {
    default: 'bg-primary/20 text-primary border-primary/30',
    success: 'bg-green-900/30 text-green-400 border-green-700/40',
    warning: 'bg-yellow-900/30 text-yellow-400 border-yellow-700/40',
    destructive: 'bg-red-900/30 text-red-400 border-red-700/40',
    outline: 'border-border text-foreground',
    secondary: 'bg-secondary text-secondary-foreground border-border',
  }
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium',
        variants[variant], className
      )}
      {...props}
    />
  )
}
