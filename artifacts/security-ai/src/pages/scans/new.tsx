import { useState } from "react";
import { useCreateScan, ScanInputScanType } from "@workspace/api-client-react";
import { useLocation } from "wouter";
import { ArrowLeft, Shield, Package, Settings, TerminalSquare } from "lucide-react";
import { Link } from "wouter";

export default function NewScan() {
  const [, setLocation] = useLocation();
  const createScan = useCreateScan();

  const [name, setName] = useState("");
  const [scanType, setScanType] = useState<ScanInputScanType>(ScanInputScanType.code);
  const [language, setLanguage] = useState("javascript");
  const [code, setCode] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createScan.mutate(
      { data: { name, scanType, language, code } },
      {
        onSuccess: (result) => {
          setLocation(`/scans/${result.scan.id}`);
        },
      }
    );
  };

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-6">
      <Link href="/scans">
        <div className="text-primary hover:underline text-sm font-mono flex items-center gap-2 mb-6 cursor-pointer w-fit">
          <ArrowLeft className="w-4 h-4" /> BACK TO ARCHIVE
        </div>
      </Link>

      <div>
        <h1 className="text-3xl font-bold tracking-tight mb-1">Initiate Analysis</h1>
        <p className="text-muted-foreground font-mono text-sm">Configure target parameters for security audit</p>
      </div>

      <div className="bg-card border border-border rounded-xl shadow-sm p-6 lg:p-8">
        <form onSubmit={handleSubmit} className="space-y-8">
          
          <div className="space-y-4">
            <label className="block text-sm font-mono text-muted-foreground uppercase tracking-widest">Target Name</label>
            <input
              type="text"
              required
              placeholder="e.g. Auth Controller Service"
              className="w-full bg-background border border-border rounded-md px-4 py-3 font-mono text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-all"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          <div className="space-y-4">
            <label className="block text-sm font-mono text-muted-foreground uppercase tracking-widest">Scan Vector</label>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <label className={`relative flex flex-col p-4 cursor-pointer rounded-lg border-2 transition-all ${scanType === 'code' ? 'border-primary bg-primary/5' : 'border-border bg-background hover:bg-muted/50'}`}>
                <input type="radio" name="scanType" value="code" checked={scanType === 'code'} onChange={() => setScanType(ScanInputScanType.code)} className="sr-only" />
                <Shield className={`w-6 h-6 mb-3 ${scanType === 'code' ? 'text-primary' : 'text-muted-foreground'}`} />
                <span className="font-bold text-foreground">SAST</span>
                <span className="text-xs text-muted-foreground mt-1">Static Code Analysis</span>
              </label>
              
              <label className={`relative flex flex-col p-4 cursor-pointer rounded-lg border-2 transition-all ${scanType === 'dependency' ? 'border-primary bg-primary/5' : 'border-border bg-background hover:bg-muted/50'}`}>
                <input type="radio" name="scanType" value="dependency" checked={scanType === 'dependency'} onChange={() => setScanType(ScanInputScanType.dependency)} className="sr-only" />
                <Package className={`w-6 h-6 mb-3 ${scanType === 'dependency' ? 'text-primary' : 'text-muted-foreground'}`} />
                <span className="font-bold text-foreground">SCA</span>
                <span className="text-xs text-muted-foreground mt-1">Software Composition</span>
              </label>
              
              <label className={`relative flex flex-col p-4 cursor-pointer rounded-lg border-2 transition-all ${scanType === 'config' ? 'border-primary bg-primary/5' : 'border-border bg-background hover:bg-muted/50'}`}>
                <input type="radio" name="scanType" value="config" checked={scanType === 'config'} onChange={() => setScanType(ScanInputScanType.config)} className="sr-only" />
                <Settings className={`w-6 h-6 mb-3 ${scanType === 'config' ? 'text-primary' : 'text-muted-foreground'}`} />
                <span className="font-bold text-foreground">CSPM</span>
                <span className="text-xs text-muted-foreground mt-1">Config Posture</span>
              </label>
            </div>
          </div>

          <div className="space-y-4">
            <label className="block text-sm font-mono text-muted-foreground uppercase tracking-widest">Environment / Language</label>
            <select
              className="w-full bg-background border border-border rounded-md px-4 py-3 font-mono text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-all appearance-none"
              value={language}
              onChange={(e) => setLanguage(e.target.value)}
            >
              <option value="javascript">JavaScript / TypeScript</option>
              <option value="python">Python</option>
              <option value="java">Java</option>
              <option value="go">Go</option>
              <option value="rust">Rust</option>
              <option value="yaml">YAML / JSON (Config)</option>
            </select>
          </div>

          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <label className="block text-sm font-mono text-muted-foreground uppercase tracking-widest">Target Payload</label>
              <div className="flex items-center gap-2 text-xs text-muted-foreground font-mono">
                <TerminalSquare className="w-3.5 h-3.5" />
                Raw Input
              </div>
            </div>
            <textarea
              required
              placeholder="// Paste raw source code, package.json, or configuration file here..."
              className="w-full h-80 bg-[#0a0a0a] border border-border rounded-md px-4 py-4 font-mono text-sm text-green-400/90 focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-all resize-y"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              spellCheck={false}
            />
          </div>

          <div className="pt-4 border-t border-border flex justify-end">
            <button
              type="submit"
              disabled={createScan.isPending || !name || !code}
              className="bg-primary text-primary-foreground hover:bg-primary/90 px-8 py-3 rounded-md font-bold font-mono tracking-widest disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_20px_rgba(20,184,100,0.3)] transition-all flex items-center gap-2"
            >
              {createScan.isPending ? (
                <>
                  <div className="w-4 h-4 border-t-2 border-primary-foreground rounded-full animate-spin" />
                  ANALYZING...
                </>
              ) : (
                "RUN ANALYSIS"
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
