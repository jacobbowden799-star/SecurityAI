import { useState } from "react";
import { useCreateScan } from "@workspace/api-client-react";
import { useLocation, Link } from "wouter";
import { ArrowLeft, Globe, Zap, ShieldCheck } from "lucide-react";

export default function NewScan() {
  const [, setLocation] = useLocation();
  const createScan = useCreateScan();

  const [name, setName] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [scanType, setScanType] = useState<"quick" | "full">("full");
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    createScan.mutate(
      { data: { name, targetUrl, scanType } },
      {
        onSuccess: (result) => {
          setLocation(`/scans/${result.scan.id}`);
        },
        onError: (err: unknown) => {
          const msg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error;
          setError(msg ?? "Could not reach the URL. Make sure it is publicly accessible.");
        },
      }
    );
  };

  return (
    <div className="p-8 max-w-3xl mx-auto space-y-6">
      <Link href="/scans">
        <div className="text-primary hover:underline text-sm font-mono flex items-center gap-2 mb-6 cursor-pointer w-fit">
          <ArrowLeft className="w-4 h-4" /> BACK TO HISTORY
        </div>
      </Link>

      <div>
        <h1 className="text-3xl font-bold tracking-tight mb-1">Scan a Website</h1>
        <p className="text-muted-foreground font-mono text-sm">
          Enter a URL you own or have permission to test. The scanner checks HTTP security headers, HTTPS enforcement, cookies, and more.
        </p>
      </div>

      <div className="bg-card border border-border rounded-xl shadow-sm p-6 lg:p-8">
        <form onSubmit={handleSubmit} className="space-y-8">

          {/* Scan name */}
          <div className="space-y-3">
            <label className="block text-sm font-mono text-muted-foreground uppercase tracking-widest">
              Scan Label
            </label>
            <input
              type="text"
              required
              placeholder="e.g. My Company Homepage"
              data-testid="input-scan-name"
              className="w-full bg-background border border-border rounded-md px-4 py-3 font-mono text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-all"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          {/* Target URL */}
          <div className="space-y-3">
            <label className="block text-sm font-mono text-muted-foreground uppercase tracking-widest">
              Website URL
            </label>
            <div className="relative">
              <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
              <input
                type="text"
                required
                placeholder="https://example.com"
                data-testid="input-target-url"
                className="w-full bg-background border border-border rounded-md pl-10 pr-4 py-3 font-mono text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-all"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
              />
            </div>
            <p className="text-xs text-muted-foreground font-mono">
              Only scan websites you own or have explicit permission to test.
            </p>
          </div>

          {/* Scan type */}
          <div className="space-y-3">
            <label className="block text-sm font-mono text-muted-foreground uppercase tracking-widest">
              Scan Depth
            </label>
            <div className="grid grid-cols-2 gap-4">
              <label
                className={`relative flex flex-col gap-2 p-4 cursor-pointer rounded-lg border-2 transition-all ${
                  scanType === "quick"
                    ? "border-primary bg-primary/5"
                    : "border-border bg-background hover:bg-muted/30"
                }`}
              >
                <input
                  type="radio"
                  name="scanType"
                  value="quick"
                  checked={scanType === "quick"}
                  onChange={() => setScanType("quick")}
                  className="sr-only"
                />
                <Zap className={`w-6 h-6 ${scanType === "quick" ? "text-primary" : "text-muted-foreground"}`} />
                <span className="font-bold text-foreground font-mono">QUICK</span>
                <span className="text-xs text-muted-foreground leading-relaxed">
                  Checks HTTPS enforcement and all key security headers. Fast — results in seconds.
                </span>
              </label>

              <label
                className={`relative flex flex-col gap-2 p-4 cursor-pointer rounded-lg border-2 transition-all ${
                  scanType === "full"
                    ? "border-primary bg-primary/5"
                    : "border-border bg-background hover:bg-muted/30"
                }`}
              >
                <input
                  type="radio"
                  name="scanType"
                  value="full"
                  checked={scanType === "full"}
                  onChange={() => setScanType("full")}
                  className="sr-only"
                />
                <ShieldCheck className={`w-6 h-6 ${scanType === "full" ? "text-primary" : "text-muted-foreground"}`} />
                <span className="font-bold text-foreground font-mono">FULL</span>
                <span className="text-xs text-muted-foreground leading-relaxed">
                  Everything in Quick plus cookie security, CORS policy, cache headers, and redirect analysis.
                </span>
              </label>
            </div>
          </div>

          {/* Error */}
          {error && (
            <div className="bg-destructive/10 border border-destructive/30 rounded-md px-4 py-3 text-sm text-destructive font-mono">
              {error}
            </div>
          )}

          <div className="pt-4 border-t border-border flex justify-end">
            <button
              type="submit"
              disabled={createScan.isPending || !name.trim() || !targetUrl.trim()}
              data-testid="button-run-scan"
              className="bg-primary text-primary-foreground hover:bg-primary/90 px-8 py-3 rounded-md font-bold font-mono tracking-widest disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_20px_rgba(20,184,100,0.3)] transition-all flex items-center gap-2"
            >
              {createScan.isPending ? (
                <>
                  <div className="w-4 h-4 border-t-2 border-primary-foreground rounded-full animate-spin" />
                  SCANNING...
                </>
              ) : (
                <>
                  <Globe className="w-4 h-4" />
                  RUN SCAN
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
