import { useGetReport, useDeleteReport, getGetReportQueryKey, getListReportsQueryKey } from "@workspace/api-client-react";
import { useRoute, Link, useLocation } from "wouter";
import { ArrowLeft, Loader2, FileText, Printer, Download, ShieldCheck, AlertTriangle, Trash2 } from "lucide-react";
import { ScoreGauge } from "@/components/score-gauge";
import { formatDate } from "@/lib/utils";
import { useQueryClient } from "@tanstack/react-query";

export default function ReportDetail() {
  const [, params] = useRoute("/reports/:id");
  const [, setLocation] = useLocation();
  const id = params?.id ? parseInt(params.id) : 0;
  const queryClient = useQueryClient();
  
  const { data: report, isLoading } = useGetReport(id, {
    query: { enabled: !!id, queryKey: getGetReportQueryKey(id) }
  });

  const deleteReport = useDeleteReport();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="w-12 h-12 text-primary animate-spin" />
      </div>
    );
  }

  if (!report) {
    return <div className="p-8 text-center text-muted-foreground font-mono">Report not found.</div>;
  }

  const handlePrint = () => window.print();

  const handleDelete = () => {
    if (confirm("Are you sure you want to delete this report?")) {
      deleteReport.mutate({ id }, {
        onSuccess: () => {
          queryClient.invalidateQueries({ queryKey: getListReportsQueryKey() });
          setLocation("/reports");
        }
      });
    }
  };

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-6 pb-20">
      <div className="flex items-center justify-between mb-4 print:hidden">
        <Link href="/reports">
          <div className="text-primary hover:underline text-sm font-mono flex items-center gap-2 cursor-pointer w-fit">
            <ArrowLeft className="w-4 h-4" /> BACK TO REPORTS
          </div>
        </Link>
        <div className="flex gap-3">
          <button 
            onClick={handleDelete}
            className="flex items-center gap-2 text-sm font-mono bg-destructive/10 hover:bg-destructive/20 text-destructive px-3 py-1.5 rounded transition-colors"
          >
            <Trash2 className="w-4 h-4" /> DELETE
          </button>
          <button 
            onClick={handlePrint}
            className="flex items-center gap-2 text-sm font-mono bg-secondary hover:bg-secondary/80 text-secondary-foreground px-3 py-1.5 rounded transition-colors"
          >
            <Printer className="w-4 h-4" /> PRINT
          </button>
          <button className="flex items-center gap-2 text-sm font-mono bg-secondary hover:bg-secondary/80 text-secondary-foreground px-3 py-1.5 rounded transition-colors">
            <Download className="w-4 h-4" /> EXPORT PDF
          </button>
        </div>
      </div>

      <div className="bg-card border border-border rounded-xl shadow-lg print:shadow-none print:border-none print:bg-transparent overflow-hidden">
        {/* Header Header */}
        <div className="p-8 md:p-12 border-b border-border bg-gradient-to-b from-primary/5 to-transparent relative">
          <div className="absolute top-6 right-8 opacity-20">
             <ShieldCheck className="w-24 h-24 text-primary" />
          </div>
          
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-secondary text-muted-foreground text-xs font-mono uppercase tracking-widest mb-6">
            <FileText className="w-3.5 h-3.5" /> SECURITY ASSESSMENT REPORT
          </div>
          
          <h1 className="text-4xl md:text-5xl font-bold tracking-tight mb-4 relative z-10 text-foreground">{report.title}</h1>
          
          <div className="flex flex-col sm:flex-row gap-4 sm:items-center text-muted-foreground font-mono text-sm">
            <span>Target: <span className="text-foreground">{report.scanName}</span></span>
            <span className="hidden sm:inline text-border">•</span>
            <span>Generated: <span className="text-foreground">{formatDate(report.createdAt)}</span></span>
            <span className="hidden sm:inline text-border">•</span>
            <span>ID: <span className="text-foreground">RPT-{report.id.toString().padStart(4, '0')}</span></span>
          </div>
        </div>

        {/* Content */}
        <div className="p-8 md:p-12 space-y-12">
          
          {/* Section 1: Executive Summary */}
          <section>
            <h2 className="text-xl font-bold border-b border-border pb-2 mb-4 text-primary tracking-tight">1. EXECUTIVE SUMMARY</h2>
            <div className="flex flex-col md:flex-row gap-8 items-start">
              <div className="flex-1 text-foreground/90 leading-relaxed space-y-4">
                <p>{report.summary}</p>
                <div className="bg-secondary/30 p-4 rounded border border-border mt-4 text-sm font-mono">
                  This report contains a summary of findings from automated security analysis. 
                  The target system was evaluated against known vulnerability signatures, configuration anti-patterns, 
                  and dependency risks.
                </div>
              </div>
              <div className="bg-background border border-border p-6 rounded-lg flex flex-col items-center min-w-[200px] shrink-0">
                <span className="text-xs text-muted-foreground font-mono uppercase tracking-widest mb-4">Final Score</span>
                <ScoreGauge score={report.securityScore} size="lg" />
              </div>
            </div>
          </section>

          {/* Section 2: Findings Breakdown */}
          <section>
             <h2 className="text-xl font-bold border-b border-border pb-2 mb-6 text-primary tracking-tight">2. VULNERABILITY BREAKDOWN</h2>
             <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="border border-red-500/20 bg-red-500/5 p-4 rounded-lg">
                  <div className="text-red-500 font-mono text-xs uppercase tracking-widest mb-2 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" /> Critical
                  </div>
                  <div className="text-4xl font-bold text-red-500">{report.criticalCount}</div>
                </div>
                <div className="border border-orange-500/20 bg-orange-500/5 p-4 rounded-lg">
                  <div className="text-orange-500 font-mono text-xs uppercase tracking-widest mb-2">High</div>
                  <div className="text-4xl font-bold text-orange-500">{report.highCount}</div>
                </div>
                <div className="border border-yellow-500/20 bg-yellow-500/5 p-4 rounded-lg">
                  <div className="text-yellow-500 font-mono text-xs uppercase tracking-widest mb-2">Medium</div>
                  <div className="text-4xl font-bold text-yellow-500">{report.mediumCount}</div>
                </div>
                <div className="border border-blue-500/20 bg-blue-500/5 p-4 rounded-lg">
                  <div className="text-blue-500 font-mono text-xs uppercase tracking-widest mb-2">Low</div>
                  <div className="text-4xl font-bold text-blue-500">{report.lowCount}</div>
                </div>
             </div>
             <p className="mt-4 text-sm text-muted-foreground">Total distinct findings identified across all vectors: <strong className="text-foreground">{report.totalFindings}</strong></p>
          </section>

          {/* Section 3: Recommendations */}
          <section>
             <h2 className="text-xl font-bold border-b border-border pb-2 mb-4 text-primary tracking-tight">3. STRATEGIC RECOMMENDATIONS</h2>
             <div className="bg-primary/5 border border-primary/20 rounded-lg p-6 text-foreground/90 whitespace-pre-wrap leading-relaxed font-mono text-sm">
               {report.recommendations}
             </div>
          </section>

        </div>
        
        {/* Footer */}
        <div className="bg-secondary p-6 text-center text-xs font-mono text-muted-foreground border-t border-border">
          SecurityAI Platform • Internal Defensive Tool • CONFIDENTIAL
        </div>
      </div>
    </div>
  );
}
