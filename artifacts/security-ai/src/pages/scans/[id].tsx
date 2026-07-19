import { useGetScan, useGetScanFindings, useDeleteScan, getGetScanQueryKey, getGetScanFindingsQueryKey, getListScansQueryKey } from "@workspace/api-client-react";
import { useRoute, Link, useLocation } from "wouter";
import { ArrowLeft, Shield, AlertTriangle, FileText, Loader2, CheckCircle2, Trash2 } from "lucide-react";
import { ScoreGauge } from "@/components/score-gauge";
import { FindingCard } from "@/components/finding-card";
import { formatDate } from "@/lib/utils";
import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";

export default function ScanDetail() {
  const [, params] = useRoute("/scans/:id");
  const [, setLocation] = useLocation();
  const id = params?.id ? parseInt(params.id) : 0;
  const queryClient = useQueryClient();
  
  const { data: scanData, isLoading: scanLoading } = useGetScan(id, {
    query: { enabled: !!id, queryKey: getGetScanQueryKey(id) }
  });
  
  const { data: findings, isLoading: findingsLoading } = useGetScanFindings(id, {
    query: { enabled: !!id, queryKey: getGetScanFindingsQueryKey(id) }
  });

  const deleteScan = useDeleteScan();

  const [severityFilter, setSeverityFilter] = useState<string | null>(null);

  const handleDelete = () => {
    if (confirm("Are you sure you want to permanently delete this scan and all its findings?")) {
      deleteScan.mutate({ id }, {
        onSuccess: () => {
          queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
          setLocation("/scans");
        }
      });
    }
  };

  if (scanLoading || findingsLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="flex flex-col items-center gap-4 text-primary">
          <Loader2 className="w-12 h-12 animate-spin" />
          <p className="font-mono tracking-widest text-sm">LOADING TELEMETRY...</p>
        </div>
      </div>
    );
  }

  if (!scanData) {
    return (
      <div className="p-8 text-center text-muted-foreground font-mono">Scan data not found.</div>
    );
  }

  const { scan } = scanData;
  
  const filteredFindings = severityFilter 
    ? findings?.filter(f => f.severity === severityFilter)
    : findings;

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <div className="flex items-center justify-between mb-4">
        <Link href="/scans">
          <div className="text-primary hover:underline text-sm font-mono flex items-center gap-2 cursor-pointer w-fit">
            <ArrowLeft className="w-4 h-4" /> BACK TO ARCHIVE
          </div>
        </Link>
        <button 
          onClick={handleDelete}
          disabled={deleteScan.isPending}
          className="flex items-center gap-2 text-sm font-mono bg-destructive/10 hover:bg-destructive/20 text-destructive px-3 py-1.5 rounded transition-colors disabled:opacity-50"
        >
          {deleteScan.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
          DELETE SCAN
        </button>
      </div>

      <div className="flex flex-col md:flex-row gap-6 md:items-center justify-between bg-card border border-border p-6 rounded-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-64 h-64 bg-primary/5 rounded-full blur-3xl -translate-y-1/2 translate-x-1/4 pointer-events-none" />
        
        <div className="space-y-4 relative z-10">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <h1 className="text-3xl font-bold tracking-tight">{scan.name}</h1>
              <span className={`px-2.5 py-1 text-xs font-mono uppercase rounded border ${
                scan.status === 'completed' ? 'text-emerald-400 border-emerald-400/30 bg-emerald-400/10' :
                scan.status === 'running' ? 'text-blue-400 border-blue-400/30 bg-blue-400/10 animate-pulse' :
                'text-gray-400 border-gray-400/30 bg-gray-400/10'
              }`}>
                {scan.status}
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm text-muted-foreground font-mono">
              <span className="flex items-center gap-1.5"><Shield className="w-4 h-4" /> Vector: {scan.scanType}</span>
              {scan.language && <span className="flex items-center gap-1.5"><FileText className="w-4 h-4" /> Env: {scan.language}</span>}
              <span className="flex items-center gap-1.5">Started: {formatDate(scan.createdAt)}</span>
              {scan.completedAt && <span className="flex items-center gap-1.5 border-l border-border pl-6">Completed: {formatDate(scan.completedAt)}</span>}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-8 relative z-10 bg-background/50 p-4 rounded-xl border border-border backdrop-blur-sm">
          <div className="flex gap-4 text-center">
            <div 
              className={`flex flex-col items-center p-3 rounded-lg border cursor-pointer transition-all ${severityFilter === 'critical' ? 'bg-red-500/20 border-red-500/50' : 'bg-red-500/5 border-red-500/20 hover:bg-red-500/10'}`}
              onClick={() => setSeverityFilter(severityFilter === 'critical' ? null : 'critical')}
            >
              <span className="text-2xl font-bold text-red-500 font-mono">{scan.criticalCount}</span>
              <span className="text-[10px] text-muted-foreground uppercase tracking-widest mt-1">Critical</span>
            </div>
            <div 
              className={`flex flex-col items-center p-3 rounded-lg border cursor-pointer transition-all ${severityFilter === 'high' ? 'bg-orange-500/20 border-orange-500/50' : 'bg-orange-500/5 border-orange-500/20 hover:bg-orange-500/10'}`}
              onClick={() => setSeverityFilter(severityFilter === 'high' ? null : 'high')}
            >
              <span className="text-2xl font-bold text-orange-500 font-mono">{scan.highCount}</span>
              <span className="text-[10px] text-muted-foreground uppercase tracking-widest mt-1">High</span>
            </div>
            <div 
              className={`flex flex-col items-center p-3 rounded-lg border cursor-pointer transition-all ${severityFilter === 'medium' ? 'bg-yellow-500/20 border-yellow-500/50' : 'bg-yellow-500/5 border-yellow-500/20 hover:bg-yellow-500/10'}`}
              onClick={() => setSeverityFilter(severityFilter === 'medium' ? null : 'medium')}
            >
              <span className="text-2xl font-bold text-yellow-500 font-mono">{scan.mediumCount}</span>
              <span className="text-[10px] text-muted-foreground uppercase tracking-widest mt-1">Medium</span>
            </div>
          </div>
          <div className="h-16 w-px bg-border hidden sm:block" />
          <ScoreGauge score={scan.securityScore} />
        </div>
      </div>

      <div className="space-y-4">
        <div className="flex items-center justify-between border-b border-border pb-2">
          <h2 className="text-xl font-bold tracking-tight flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-primary" />
            Detected Vulnerabilities
            <span className="text-sm font-mono text-muted-foreground ml-2 font-normal bg-secondary px-2 py-0.5 rounded">
              {filteredFindings?.length || 0} {severityFilter ? `showing (${severityFilter})` : 'total'}
            </span>
          </h2>
          {severityFilter && (
            <button 
              onClick={() => setSeverityFilter(null)}
              className="text-xs font-mono text-muted-foreground hover:text-foreground transition-colors"
            >
              Clear Filter ✕
            </button>
          )}
        </div>

        {filteredFindings && filteredFindings.length > 0 ? (
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            {filteredFindings.map((finding) => (
              <FindingCard key={finding.id} finding={finding} />
            ))}
          </div>
        ) : (
          <div className="bg-card border border-border rounded-xl p-12 text-center flex flex-col items-center">
            {scan.status === 'completed' ? (
              <>
                <CheckCircle2 className="w-12 h-12 text-emerald-500 mb-4" />
                <h3 className="text-lg font-bold">No Vulnerabilities Detected</h3>
                <p className="text-muted-foreground mt-1 max-w-sm">
                  {severityFilter 
                    ? `No findings match the severity level: ${severityFilter}.` 
                    : "The codebase appears to be secure against our current signature sets."}
                </p>
              </>
            ) : scan.status === 'running' ? (
              <>
                 <Loader2 className="w-12 h-12 text-primary animate-spin mb-4" />
                 <h3 className="text-lg font-bold">Analysis in Progress</h3>
                 <p className="text-muted-foreground mt-1 max-w-sm text-sm font-mono">Scanning target payload against security signatures...</p>
              </>
            ) : (
              <>
                 <AlertTriangle className="w-12 h-12 text-muted-foreground mb-4 opacity-50" />
                 <h3 className="text-lg font-bold">No Data Available</h3>
                 <p className="text-muted-foreground mt-1 max-w-sm">The scan has not completed successfully.</p>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
