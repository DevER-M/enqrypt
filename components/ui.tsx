import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from 'react';

export function cn(
  ...parts: Array<string | false | null | undefined>
): string {
  return parts.filter(Boolean).join(' ');
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
};

export function Button({
  variant = 'primary',
  type = 'button',
  className,
  ...props
}: ButtonProps) {
  const variants = {
    primary: 'btn-primary',
    secondary: 'btn-secondary',
    ghost: 'btn-ghost',
    danger: 'btn-danger',
  } as const;
  return <button type={type} className={cn(variants[variant], className)} {...props} />;
}

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn('input', className)} {...props} />;
}

export function Alert({
  tone = 'error',
  children,
}: {
  tone?: 'error' | 'warn' | 'info' | 'success';
  children: ReactNode;
}) {
  const tones = {
    error: 'border-rose-500/30 bg-rose-500/10 text-rose-200',
    warn: 'border-amber-500/30 bg-amber-500/10 text-amber-100',
    info: 'border-sky-500/30 bg-sky-500/10 text-sky-100',
    success: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-100',
  } as const;
  return (
    <div className={cn('rounded-xl border px-3 py-2 text-sm', tones[tone])} role="status">
      {children}
    </div>
  );
}

export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div className="flex items-center gap-3">
      <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-violet-500 to-sky-500 text-white shadow-lg shadow-violet-900/30">
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="h-5 w-5"
          aria-hidden="true"
        >
          <path d="M12 3 5 6v5c0 4.5 2.9 8.2 7 10 4.1-1.8 7-5.5 7-10V6l-7-3Z" />
          <path d="M9 12h6" />
          <path d="M12 9v6" />
        </svg>
      </div>
      {compact ? null : (
        <div className="leading-tight">
          <div className="text-sm font-semibold tracking-wide text-slate-100">enqrypt</div>
          <div className="text-[11px] uppercase tracking-[0.18em] text-slate-500">
            post-quantum e2ee
          </div>
        </div>
      )}
    </div>
  );
}
