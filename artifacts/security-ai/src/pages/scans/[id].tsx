import {
  useGetScan, useGetScanFindings, useDeleteScan,
  getGetScanQueryKey, getGetScanFindingsQueryKey, getListScansQueryKey,
} from "@workspace/api-client-react";
import { useRoute, Link, useLocation } from "wouter";
import {
  ArrowLeft, Globe, AlertTriangle, Loader2, CheckCircle2, Trash2,
  Zap, ShieldCheck, TrendingUp, TrendingDown, Minus, RefreshCw,
  Lock, Eye, Server, FileSearch, Bug,
} from "lucide-react";
import { ScoreGauge } from "@/components/score-gauge";
import { FindingCard } from "@/components/finding-card";
import { formatDate, cn } from "@/lib/utils";
import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";

// Map category slugs to friendly labels
const CATEGORY_LABELS: Record<string, { label: string; icon: React.ComponentType<{ className?: string }> }> = {
  "tls-certificate":        { label: "TLS / HTTPS",           icon: Lock },
  "missing-security-header":{ label: "Security Headers",      icon: ShieldCheck },
  "technology-disclosure":  { label: "Tech Disclosure",       icon: Server },
  "cookie-security":        { label: "Cookie Security",       icon: Eye },
  "exposed-file":           { label: "Exposed Files",         icon: FileSearch },
  "admin-exposure":         { label: "Admin Panels",          icon: AlertTriangle },
  "information-disclosure": { label: "Info Disclosure",       icon: Bug },
  "weak-config":            { label: "Weak Config",           icon: AlertTriangle },
};

function ScoreDeltaBadge({ delta }: { delta: number | null | undefined }) {
  if (delta === null || delta === undefined) return null;
  const improved = delta > 0;
  const unchanged = delta === 0;
  return (
    <div className={cn(
      "flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-sm font-mono font-bold",
      improved  ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400" :
      unchanged ? "bg-gray-500/10 border-gray-500/30 text-gray-400" :
                  "bg-red-500/10 border-red-500/30 text-red-400"
    )}>
      {improved  ? <TrendingUp className="w-4 h-4" /> :
       unchanged ? <Minus className="w-4 h-4" /> :
                   <TrendingDown className="w-4 h-4" />}
      {improved ? `+${delta}` : delta} vs last audit
    </div>
  );
}

export default function ScanDetail() {
  const [, params] = useRoute("/scans/:id");
  const [, setLocation] = useLocation();
  const id = params?.id ? parseInt(params.id) : 0;
  const queryClient = useQueryClient();

  const { data: scanData, isLoading: scanLoading } = useGetScan(id, {
    query: { enabled: !!id, queryKey: getGetScanQueryKey(id) },
  });
  const { data: findings, isLoading: findingsLoading } = useGetScanFindings(id, {
    query: { enabled: !!id, queryKey: getGetScanFindingsQueryKey(id) },
  });

  const deleteScan = useDeleteScan();
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null);

  const handleDelete = () => {
    if (confirm("Delete this audit and all its findings?")) {
      deleteScan.mutate({ id }, {
        onSuccess: () => {
          queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
          setLocation("/scans");
        },
      });
    }
  };

  if (scanLoading || findingsLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="flex flex-col items-center gap-4 text-primary">
          <Loader2 className="w-12 h-12 animate-spin" />
          <p className="font-mono tracking-widest text-sm">LOADING AUDIT…</p>
        </div>
      </div>
    );
  }

  if (!scanData) {
    return <div className="p-8 text-center text-muted-foreground font-mono">Audit not found.</div>;
  }

  const { scan } = scanData;

  // Category breakdown from findings
  const categoryMap: Record<string, number> = {};
  for (const f of findings ?? []) {
    if (f.severity !== "info") categoryMap[f.category] = (categoryMap[f.category] ?? 0) + 1;
  }

  // Filter findings
  const filteredFindings = (findings ?? []).filter((f) => {
    if (severityFilter && f.severity !== severityFilter) return false;
    if (categoryFilter && f.category !== categoryFilter) return false;
    return true;
  });

  const ScanTypeIcon = scan.scanType === "quick" ? Zap : ShieldCheck;

  // Re-audit URL
  const reAuditUrl = `/scans/new?url=${encodeURIComponent(scan.targetUrl ?? "")}&name=${encodeURIComponent(scan.name)}`;

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">

      {/* Top bar */}
      <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
        <Link href="/scans">
          <div className="text-primary hover:underline text-sm font-mono flex items-center gap-2 cursor-pointer w-fit">
            <ArrowLeft className="w-4 h-4" /> BACK TO HISTORY
          </div>
        </Link>
        <div className="flex items-center gap-2">
          {scan.targetUrl && scan.status === "completed" && (
            <Link href={reAuditUrl}>
              <div className="flex items-center gap-2 text-sm font-mono bg-primary/10 hover:bg-primary/20 border border-primary/30 text-primary px-3 py-1.5 rounded transition-colors cursor-pointer">
                <RefreshCw className="w-4 h-4" />
                RE-AUDIT
              </div>
            </Link>
          )}
          <button
            onClick={handleDelete}
            disabled={deleteScan.isPending}
            className="flex items-center gap-2 text-sm font-mono bg-destructive/10 hover:bg-destructive/20 text-destructive border border-destructive/20 px-3 py-1.5 rounded transition-colors disabled:opacity-50"
          >
            {deleteScan.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
            DELETE
          </button>
        </div>
      </div>

      {/* Summary banner */}
      <div className="flex flex-col md:flex-row gap-6 md:items-start justify-between bg-card border border-border p-6 rounded-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-64 h-64 bg-primary/5 rounded-full blur-3xl -translate-y-1/2 translate-x-1/4 pointer-events-none" />

        <div className="space-y-3 relative z-10 flex-1 min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <div className="p-1.5 rounded bg-primary/10 border border-primary/20">
              <ShieldCheck className="w-4 h-4 text-primary" />
            </div>
            <span className="text-xs font-mono text-primary uppercase tracking-widest">External Security Audit</span>
            <span className={`px-2.5 py-1 text-xs font-mono uppercase rounded border ${
              scan.status === "completed" ? "text-emerald-400 border-emerald-400/30 bg-emerald-400/10" :
              scan.status === "running"   ? "text-blue-400 border-blue-400/30 bg-blue-400/10 animate-pulse" :
                                           "text-gray-400 border-gray-400/30 bg-gray-400/10"
            }`}>{scan.status}</span>
          </div>

          <h1 className="text-2xl font-bold tracking-tight">{scan.name}</h1>

          <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-sm text-muted-foreground font-mono">
            {scan.targetUrl && (
              <a href={scan.targetUrl} target="_blank" rel="noopener noreferrer"
                className="flex items-center gap-1.5 text-primary hover:underline truncate max-w-sm"
                onClick={(e) => e.stopPropagation()}>
                <Globe className="w-3.5 h-3.5 flex-shrink-0" />
                {scan.targetUrl}
              </a>
            )}
            <span className="flex items-center gap-1.5">
              <ScanTypeIcon className="w-3.5 h-3.5" />
              {scan.scanType === "quick" ? "Quick audit" : "Full audit"}
            </span>
            <span>{formatDate(scan.createdAt)}</span>
          </div>

          {/* Score delta */}
          {scan.scoreDelta !== null && scan.scoreDelta !== undefined && (
            <div className="flex items-center gap-3 pt-1">
              <ScoreDeltaBadge delta={scan.scoreDelta} />
              {scan.baselineScanId && (
                <Link href={`/scans/${scan.baselineScanId}`}>
                  <span className="text-xs text-muted-foreground hover:text-foreground font-mono cursor-pointer hover:underline">
                    View previous audit →
                  </span>
                </Link>
              )}
            </div>
          )}
        </div>

        {/* Score + severity counts */}
        <div className="flex items-center gap-4 relative z-10 bg-background/50 p-4 rounded-xl border border-border backdrop-blur-sm flex-shrink-0">
          <div className="flex gap-2 text-center">
            {[
              { key: "critical", label: "Crit",   count: scan.criticalCount, color: "red" },
              { key: "high",     label: "High",   count: scan.highCount,     color: "orange" },
              { key: "medium",   label: "Med",    count: scan.mediumCount,   color: "yellow" },
              { key: "low",      label: "Low",    count: scan.lowCount,      color: "blue" },
            ].map(({ key, label, count, color }) => (
              <div
                key={key}
                onClick={() => setSeverityFilter(severityFilter === key ? null : key)}
                className={cn(
                  "flex flex-col items-center px-3 py-2 rounded-lg border cursor-pointer transition-all select-none",
                  severityFilter === key
                    ? `bg-${color}-500/20 border-${color}-500/50`
                    : `bg-${color}-500/5 border-${color}-500/20 hover:bg-${color}-500/10`
                )}
                title={`Filter by ${key}`}
              >
                <span className={`text-xl font-bold text-${color}-500 font-mono`}>{count}</span>
                <span className="text-[10px] text-muted-foreground uppercase tracking-widest mt-0.5">{label}</span>
              </div>
            ))}
          </div>
          <div className="h-14 w-px bg-border hidden sm:block" />
          <ScoreGauge score={scan.securityScore} />
        </div>
      </div>

      {/* Category breakdown + filter pills */}
      {Object.keys(categoryMap).length > 0 && (
        <div className="bg-card border border-border rounded-xl p-5">
          <h3 className="text-xs font-mono text-muted-foreground uppercase tracking-widest mb-4">Filter by Category</h3>
          <div className="flex flex-wrap gap-2">
            {Object.entries(categoryMap)
              .sort((a, b) => b[1] - a[1])
              .map(([cat, count]) => {
                const meta = CATEGORY_LABELS[cat];
                const Icon = meta?.icon ?? Bug;
                const active = categoryFilter === cat;
                return (
                  <button
                    key={cat}
                    onClick={() => setCategoryFilter(active ? null : cat)}
                    className={cn(
                      "flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-xs font-mono transition-all",
                      active
                        ? "bg-primary/20 border-primary/50 text-primary"
                        : "bg-secondary/50 border-border text-muted-foreground hover:text-foreground hover:border-primary/30"
                    )}
                  >
                    <Icon className="w-3 h-3" />
                    {meta?.label ?? cat}
                    <span className="ml-1 opacity-70">{count}</span>
                  </button>
                );
              })}
            {(severityFilter || categoryFilter) && (
              <button
                onClick={() => { setSeverityFilter(null); setCategoryFilter(null); }}
                className="px-3 py-1.5 rounded-full border border-muted-foreground/20 text-xs font-mono text-muted-foreground hover:text-foreground transition-all"
              >
                Clear filters ✕
              </button>
            )}
          </div>
        </div>
      )}

      {/* Findings */}
      <div className="space-y-4">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <h2 className="text-xl font-bold tracking-tight flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-primary" />
            Audit Findings
            <span className="text-sm font-mono text-muted-foreground ml-2 font-normal bg-secondary px-2 py-0.5 rounded">
              {filteredFindings.length} {(severityFilter || categoryFilter) ? "shown" : "total"}
            </span>
          </h2>
        </div>

        {filteredFindings.length > 0 ? (
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            {filteredFindings.map((finding) => (
              <FindingCard key={finding.id} finding={finding} />
            ))}
          </div>
        ) : (
          <div className="bg-card border border-border rounded-xl p-12 text-center flex flex-col items-center">
            {scan.status === "completed" ? (
              <>
                <CheckCircle2 className="w-12 h-12 text-emerald-500 mb-4" />
                <h3 className="text-lg font-bold">
                  {severityFilter || categoryFilter ? "No matching findings" : "No Issues Detected"}
                </h3>
                <p className="text-muted-foreground mt-1 max-w-sm text-sm">
                  {severityFilter || categoryFilter
                    ? "Try clearing the filters to see all findings."
                    : "All checked security configurations passed for this audit depth."}
                </p>
              </>
            ) : scan.status === "running" ? (
              <>
                <Loader2 className="w-12 h-12 text-primary animate-spin mb-4" />
                <h3 className="text-lg font-bold">Audit in Progress</h3>
              </>
            ) : (
              <>
                <AlertTriangle className="w-12 h-12 text-muted-foreground mb-4 opacity-50" />
                <h3 className="text-lg font-bold">Audit Did Not Complete</h3>
                <p className="text-muted-foreground mt-1 max-w-sm text-sm">
                  The URL may be unreachable. Check the address and try again.
                </p>
              </>
            )}
          </div>
        )}
      </div>

      {/* Verification prompt after completion */}
      {scan.status === "completed" && (findings?.length ?? 0) > 0 && (
        <div className="bg-primary/5 border border-primary/20 rounded-xl p-5 flex items-center justify-between gap-4 flex-wrap">
          <div>
            <h3 className="font-bold text-foreground mb-1">Applied some fixes?</h3>
            <p className="text-sm text-muted-foreground">Run another audit to verify your improvements and update the security score.</p>
          </div>
          {scan.targetUrl && (
            <Link href={reAuditUrl}>
              <div className="flex items-center gap-2 text-sm font-mono bg-primary text-primary-foreground hover:bg-primary/90 px-4 py-2 rounded-md font-bold cursor-pointer shadow-[0_0_15px_rgba(20,184,100,0.2)] transition-all whitespace-nowrap">
                <RefreshCw className="w-4 h-4" />
                VERIFY FIXES
              </div>
            </Link>
          )}
        </div>
      )}
    </div>
  );
}
