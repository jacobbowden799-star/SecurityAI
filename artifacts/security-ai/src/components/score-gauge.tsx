import { cn, getScoreColor } from "@/lib/utils";
import { ShieldAlert, ShieldCheck, Shield } from "lucide-react";

interface ScoreGaugeProps {
  score: number | null | undefined;
  size?: "sm" | "md" | "lg" | "xl";
  className?: string;
}

export function ScoreGauge({ score, size = "md", className }: ScoreGaugeProps) {
  const isNull = score === null || score === undefined;
  const colorClass = getScoreColor(score);
  
  const sizeClasses = {
    sm: "w-12 h-12 text-sm",
    md: "w-20 h-20 text-2xl",
    lg: "w-32 h-32 text-4xl",
    xl: "w-48 h-48 text-6xl"
  };

  const ringRadius = 45;
  const circumference = 2 * Math.PI * ringRadius;
  const dashoffset = isNull ? 0 : circumference - ((score || 0) / 100) * circumference;
  
  // Choose stroke color based on score
  let strokeColor = "stroke-gray-500/30";
  if (!isNull) {
    if (score >= 80) strokeColor = "stroke-emerald-500";
    else if (score >= 60) strokeColor = "stroke-yellow-500";
    else if (score >= 40) strokeColor = "stroke-orange-500";
    else strokeColor = "stroke-red-500";
  }

  return (
    <div className={cn("relative flex items-center justify-center", sizeClasses[size], className)}>
      {/* Background ring */}
      <svg className="absolute inset-0 w-full h-full -rotate-90 transform" viewBox="0 0 100 100">
        <circle
          className="stroke-muted fill-transparent"
          strokeWidth="6"
          cx="50"
          cy="50"
          r={ringRadius}
        />
        {/* Progress ring */}
        <circle
          className={cn("fill-transparent transition-all duration-1000 ease-out", strokeColor)}
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashoffset}
          cx="50"
          cy="50"
          r={ringRadius}
        />
      </svg>
      
      {/* Center content */}
      <div className="relative flex flex-col items-center justify-center font-mono font-bold">
        {isNull ? (
          <Shield className="w-1/3 h-1/3 text-muted-foreground mb-1" />
        ) : (
          <span className={cn(colorClass)}>{score}</span>
        )}
      </div>
    </div>
  );
}
