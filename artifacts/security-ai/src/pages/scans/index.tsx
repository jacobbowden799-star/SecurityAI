import { useListScans } from "@workspace/api-client-react";
import { Link, useLocation } from "wouter";
import { Globe, Zap, ShieldCheck, Plus, Search } from "lucide-react";
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
    {
      completed: "text-emerald-400 bg-emerald-400/10 border-emerald-400/20",
      running:   "text-blue-400 bg-blue-400/10 border-blue-400/20 animate-pulse",
      failed:    "text-red-400 bg-red-400/10 border-red-400/20",
      pending:   "text-gray-400 bg-gray-400/10 border-gray-400/20",
    }[status.toLowerCase()] ?? "text-gray-400 bg-gray-400/10 border-gray-400/20";

  return (
    <span className={cn("px-2 py-0.5 rounded text-[10px] font-mono uppercase border tracking-wider", styles)}>
      {status}
    </span>
  );
};

export default function Scans() {
  const { data: scans, isLoading } = useListScans();
  const [, setLocation] = useLocation();

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight mb-1">Scan History</h1>
          <p className="text-muted-foreground font-mono text-sm">
            All website security scans and their results
          </p>
        </div>
        <Link href="/scans/new">
          <div
            data-testid="button-new-scan"
            className="bg-primary text-primary-foreground hover:bg-primary/90 px-4 py-2 rounded-md font-bold font-mono tracking-tight flex items-center gap-2 cursor-pointer shadow-[0_0_15px_rgba(20,184,100,0.2)]"
          >
            <Plus className="w-4 h-4" />
            NEW SCAN
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
                <th className="px-6 py-4 font-semibold text-center">Findings</th>
                <th className="px-6 py-4 font-semibold">Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="px-6 py-12 text-center">
                    <div className="flex justify-center">
                      <div className="w-6 h-6 border-t-2 border-primary border-solid rounded-full animate-spin" />
                    </div>
                  </td>
                </tr>
              ) : scans?.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-6 py-12 text-center text-muted-foreground">
                    <div className="flex flex-col items-center gap-3">
                      <Search className="w-8 h-8 opacity-20" />
                      <p>No scans yet. Enter a website URL to run your first scan.</p>
                    </div>
                  </td>
                </tr>
              ) : (
                scans?.map((scan) => (
                  <tr
                    key={scan.id}
                    data-testid={`scan-row-${scan.id}`}
                    onClick={() => setLocation(`/scans/${scan.id}`)}
                    className="hover:bg-muted/30 cursor-pointer transition-colors group"
                  >
                    <td className="px-6 py-4 font-medium text-foreground group-hover:text-primary transition-colors">
                      {scan.name}
                    </td>
                    <td className="px-6 py-4 text-xs text-muted-foreground font-mono max-w-[200px] truncate">
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
