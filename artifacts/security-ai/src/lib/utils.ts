import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDate(dateString: string | undefined | null) {
  if (!dateString) return "N/A"
  const date = new Date(dateString)
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  }).format(date)
}

export function getSeverityColor(severity: string) {
  switch (severity.toLowerCase()) {
    case 'critical': return 'text-red-500 bg-red-500/10 border-red-500/20';
    case 'high': return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
    case 'medium': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
    case 'low': return 'text-blue-500 bg-blue-500/10 border-blue-500/20';
    case 'info': return 'text-gray-400 bg-gray-500/10 border-gray-500/20';
    default: return 'text-gray-400 bg-gray-500/10 border-gray-500/20';
  }
}

export function getScoreColor(score: number | null | undefined) {
  if (score === null || score === undefined) return 'text-gray-500';
  if (score >= 80) return 'text-emerald-500';
  if (score >= 60) return 'text-yellow-500';
  if (score >= 40) return 'text-orange-500';
  return 'text-red-500';
}
