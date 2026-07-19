import { Finding } from "@workspace/api-client-react";
import { SeverityBadge } from "./severity-badge";
import { AlertCircle, Tag, Code2, Copy, CheckCircle2 } from "lucide-react";
import { useState } from "react";

export function FindingCard({ finding }: { finding: Finding }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    if (finding.codeSnippet) {
      navigator.clipboard.writeText(finding.codeSnippet);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden flex flex-col shadow-sm">
      <div className="p-4 border-b border-border bg-secondary/30 flex items-start justify-between gap-4">
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <SeverityBadge severity={finding.severity} />
            <h3 className="font-semibold text-lg leading-tight">{finding.title}</h3>
          </div>
          <div className="flex flex-wrap items-center gap-3 text-sm text-muted-foreground font-mono">
            <span className="flex items-center gap-1.5"><Tag className="w-3.5 h-3.5" /> {finding.category}</span>
            {finding.cweId && (
              <span className="flex items-center gap-1.5 text-orange-500/80 bg-orange-500/10 px-1.5 py-0.5 rounded border border-orange-500/20">
                <AlertCircle className="w-3.5 h-3.5" /> {finding.cweId}
              </span>
            )}
            {finding.lineNumber && (
              <span className="flex items-center gap-1.5 bg-muted px-1.5 py-0.5 rounded">
                Line {finding.lineNumber}
              </span>
            )}
          </div>
        </div>
      </div>
      
      <div className="p-4 space-y-4 text-sm flex-1">
        <div className="text-foreground/90 leading-relaxed">
          {finding.description}
        </div>
        
        {finding.codeSnippet && (
          <div className="relative group">
            <div className="absolute top-0 right-0 p-2 flex items-center justify-end z-10 opacity-0 group-hover:opacity-100 transition-opacity">
              <button 
                onClick={handleCopy}
                className="bg-card hover:bg-muted border border-border text-muted-foreground hover:text-foreground p-1.5 rounded transition-colors"
                title="Copy snippet"
              >
                {copied ? <CheckCircle2 className="w-4 h-4 text-primary" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
            <div className="bg-background border border-border rounded overflow-hidden font-mono text-[13px]">
              <div className="flex items-center bg-muted/50 border-b border-border px-3 py-1.5 text-muted-foreground gap-2">
                <Code2 className="w-3.5 h-3.5" />
                <span>Affected Code</span>
              </div>
              <pre className="p-3 overflow-x-auto text-muted-foreground">
                <code>{finding.codeSnippet}</code>
              </pre>
            </div>
          </div>
        )}

        <div className="bg-primary/5 border border-primary/20 rounded-md p-3 text-primary-foreground/90 mt-auto">
          <div className="flex items-center gap-2 mb-1.5 text-primary font-semibold">
            <CheckCircle2 className="w-4 h-4" />
            <span>Remediation</span>
          </div>
          <p className="leading-relaxed">{finding.recommendation}</p>
        </div>
      </div>
    </div>
  );
}
