import { cn, getSeverityColor } from "@/lib/utils";

interface SeverityBadgeProps {
  severity: string;
  className?: string;
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const colorClasses = getSeverityColor(severity);
  
  return (
    <span className={cn("px-2 py-0.5 rounded text-xs font-mono font-semibold uppercase border tracking-wider", colorClasses, className)}>
      {severity}
    </span>
  );
}
