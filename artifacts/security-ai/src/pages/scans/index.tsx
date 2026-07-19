import { useListScans } from "@workspace/api-client-react";
import { Link, useLocation } from "wouter";
import { Globe, Zap, ShieldCheck, Plus, Search, TrendingUp, TrendingDown, Minus } from "lucide-react";
import { ScoreGauge } from "@/components/score-gauge";
import { formatDate, cn } from "@/lib/utils";

const ScanTypeIcon = ({ type, className }: { type: string; className?: string }) => {
  switch (type) {
    case "quick": return <Zap className={className} />;
    case "full":  return <ShieldCheck className={className} />;
    default:      return <Globe className={className} />;
  }
};

const StatusBadge = ({ status }: { status: string }) => {
  const styles =
    ({
      completed: "text-emerald-400 bg-emerald-400/10 border-emerald-400/20",
      running:   "text-blue-400 bg-blue-400/10 border-blue-400/20 animate-pulse",
      failed:    "text-red-400 bg-red-400/10 border-red-400/20",
      pending:   "text-gray-400 bg-gray-400/10 border-gray-400/20",
    } as Record<string, string>)[status.toLowerCase()] ?? "text-gray-400 bg-gray-400/10 border-gray-400/20";

  return (
    <span className={cn("px-2 py-0.5 rounded text-[10px] font-mono uppercase border tracking-wider", styles)}>
      {status}
    </span>
  );
};

function DeltaCell({ delta }: { delta?: number | null }) {
  if (delta === null || delta === undefined) return <span className="text-muted-foreground font-mono text-xs">—</span>;
  const up = delta > 0;
  const flat = delta === 0;
  return (
    <span className={cn(
      "flex items-center gap-1 font-mono text-xs font-bold",
      up ? "text-emerald-400" : flat ? "text-gray-400" : "text-red-400"
    )}>
      {up ? <TrendingUp className="w-3 h-3" /> : flat ? <Minus className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
      {up ? `+${delta}` : delta}
    </span>
  );
}

export default function Scans() {
  const { data: scans, isLoading } = useListScans();
  const [, setLocation] = useLocation();

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight mb-1">Audit History</h1>
          <p className="text-muted-foreground font-mono text-sm">
            All external security audits and their results
          </p>
        </div>
        <Link href="/scans/new">
          <div className="bg-primary text-primary-foreground hover:bg-primary/90 px-4 py-2 rounded-md font-bold font-mono tracking-tight flex items-center gap-2 cursor-pointer shadow-[0_0_15px_rgba(20,184,100,0.2)]">
            <Plus className="w-4 h-4" />
            NEW AUDIT
          </div>
        </Link>
      </div>

      <div className="bg-card border border-border rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left whitespace-nowrap">
            <thead className="text-xs text-muted-foreground uppercase bg-secondary/50 font-mono">
              <tr>
                <th className="px-6 py-4 font-semibold">Target</th>
                <th className="px-6 py-4 font-semibold">URL</th>
                <th className="px-6 py-4 font-semibold">Depth</th>
                <th className="px-6 py-4 font-semibold">Status</th>
                <th className="px-6 py-4 font-semibold text-center">Score</th>
                <th className="px-6 py-4 font-semibold text-center">Change</th>
                <th className="px-6 py-4 font-semibold text-center">Findings</th>
                <th className="px-6 py-4 font-semibold">Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {isLoading ? (
                <tr>
                  <td colSpan={8} className="px-6 py-12 text-center">
                    <div className="flex justify-center">
                      <div className="w-6 h-6 border-t-2 border-primary border-solid rounded-full animate-spin" />
                    </div>
                  </td>
                </tr>
              ) : scans?.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-6 py-12 text-center text-muted-foreground">
                    <div className="flex flex-col items-center gap-3">
                      <Search className="w-8 h-8 opacity-20" />
                      <p>No audits yet. Enter a website URL to run your first external security audit.</p>
                    </div>
                  </td>
                </tr>
              ) : (
                scans?.map((scan) => (
                  <tr
                    key={scan.id}
                    onClick={() => setLocation(`/scans/${scan.id}`)}
                    className="hover:bg-muted/30 cursor-pointer transition-colors group"
                  >
                    <td className="px-6 py-4 font-medium text-foreground group-hover:text-primary transition-colors">
                      {scan.name}
                    </td>
                    <td className="px-6 py-4 text-xs text-muted-foreground font-mono max-w-[180px] truncate">
                      {scan.targetUrl ?? "—"}
                    </td>
                    <td className="px-6 py-4">
                      <span className="flex items-center gap-1.5 text-xs font-mono bg-secondary text-secondary-foreground px-2 py-1 rounded w-fit capitalize">
                        <ScanTypeIcon type={scan.scanType} className="w-3 h-3" />
                        {scan.scanType}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <StatusBadge status={scan.status} />
                    </td>
                    <td className="px-6 py-2 flex justify-center">
                      <ScoreGauge score={scan.securityScore} size="sm" />
                    </td>
                    <td className="px-6 py-4 text-center">
                      <DeltaCell delta={scan.scoreDelta} />
                    </td>
                    <td className="px-6 py-4 text-center">
                      <div className="flex items-center justify-center gap-1.5">
                        <span className="w-6 text-center text-red-500 font-mono font-bold bg-red-500/10 rounded" title="Critical">{scan.criticalCount}</span>
                        <span className="w-6 text-center text-orange-500 font-mono font-bold bg-orange-500/10 rounded" title="High">{scan.highCount}</span>
                        <span className="w-6 text-center text-yellow-500 font-mono font-bold bg-yellow-500/10 rounded" title="Medium">{scan.mediumCount}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 font-mono text-xs text-muted-foreground">
                      {formatDate(scan.createdAt)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
