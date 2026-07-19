import { useListReports, useCreateReport, getListReportsQueryKey } from "@workspace/api-client-react";
import { Link, useLocation } from "wouter";
import { FileText, Plus, Search, ShieldAlert, ArrowRight, Loader2 } from "lucide-react";
import { ScoreGauge } from "@/components/score-gauge";
import { formatDate } from "@/lib/utils";
import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";

export default function Reports() {
  const { data: reports, isLoading } = useListReports();
  const [, setLocation] = useLocation();
  const [isGenerating, setIsGenerating] = useState(false);
  const createReport = useCreateReport();
  const queryClient = useQueryClient();

  const handleGenerateReport = () => {
    // For this example we just create a dummy report, normally would open a modal to select scan
    const name = prompt("Enter a title for the new executive report:");
    const scanId = prompt("Enter the Scan ID to report on (e.g. 1):");
    
    if (name && scanId) {
      setIsGenerating(true);
      createReport.mutate({ data: { title: name, scanId: parseInt(scanId) } }, {
        onSuccess: (report) => {
          queryClient.invalidateQueries({ queryKey: getListReportsQueryKey() });
          setLocation(`/reports/${report.id}`);
        },
        onSettled: () => setIsGenerating(false)
      });
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight mb-1">Executive Reports</h1>
          <p className="text-muted-foreground font-mono text-sm">Formal security assessments and posture summaries</p>
        </div>
        <button 
          onClick={handleGenerateReport}
          disabled={isGenerating}
          className="bg-primary text-primary-foreground hover:bg-primary/90 px-4 py-2 rounded-md font-bold font-mono tracking-tight flex items-center gap-2 cursor-pointer shadow-[0_0_15px_rgba(20,184,100,0.2)] disabled:opacity-50"
        >
          {isGenerating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
          GENERATE REPORT
        </button>
      </div>

      {isLoading ? (
         <div className="flex items-center justify-center py-20">
           <Loader2 className="w-8 h-8 text-primary animate-spin" />
         </div>
      ) : reports?.length === 0 ? (
        <div className="bg-card border border-border rounded-xl p-16 flex flex-col items-center justify-center text-center">
          <FileText className="w-16 h-16 text-muted-foreground opacity-20 mb-4" />
          <h2 className="text-xl font-bold mb-2">No Reports Generated</h2>
          <p className="text-muted-foreground max-w-md">
            Generate your first executive report based on a completed scan to share findings with stakeholders.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {reports?.map((report) => (
            <div 
              key={report.id}
              onClick={() => setLocation(`/reports/${report.id}`)}
              className="bg-card border border-border rounded-xl p-6 hover:border-primary/50 cursor-pointer transition-all group flex flex-col h-full shadow-sm hover:shadow-[0_4px_20px_rgba(0,0,0,0.2)] relative overflow-hidden"
            >
              <div className="absolute top-0 right-0 w-32 h-32 bg-primary/5 rounded-full blur-2xl -translate-y-1/2 translate-x-1/4" />
              
              <div className="flex justify-between items-start mb-4 relative z-10">
                <div className="bg-secondary p-2 rounded-lg text-primary">
                  <FileText className="w-5 h-5" />
                </div>
                <ScoreGauge score={report.securityScore} size="sm" />
              </div>
              
              <h3 className="font-bold text-lg leading-tight mb-1 relative z-10 group-hover:text-primary transition-colors">{report.title}</h3>
              <p className="text-muted-foreground text-sm font-mono flex items-center gap-1.5 mb-4">
                <Search className="w-3.5 h-3.5" /> Source: {report.scanName}
              </p>
              
              <div className="grid grid-cols-4 gap-2 mb-6 mt-auto">
                <div className="flex flex-col border border-border rounded items-center py-1.5 bg-red-500/5">
                  <span className="text-red-500 font-mono font-bold text-sm">{report.criticalCount}</span>
                </div>
                <div className="flex flex-col border border-border rounded items-center py-1.5 bg-orange-500/5">
                  <span className="text-orange-500 font-mono font-bold text-sm">{report.highCount}</span>
                </div>
                <div className="flex flex-col border border-border rounded items-center py-1.5 bg-yellow-500/5">
                  <span className="text-yellow-500 font-mono font-bold text-sm">{report.mediumCount}</span>
                </div>
                <div className="flex flex-col border border-border rounded items-center py-1.5 bg-blue-500/5">
                  <span className="text-blue-500 font-mono font-bold text-sm">{report.lowCount}</span>
                </div>
              </div>
              
              <div className="flex items-center justify-between border-t border-border pt-4 mt-auto">
                <span className="text-xs text-muted-foreground font-mono">{formatDate(report.createdAt)}</span>
                <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-primary group-hover:translate-x-1 transition-all" />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
