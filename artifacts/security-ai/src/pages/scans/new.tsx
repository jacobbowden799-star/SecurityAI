import { useState, useEffect } from "react";
import { useCreateScan } from "@workspace/api-client-react";
import { useLocation, Link } from "wouter";
import {
  ArrowLeft, Globe, Zap, ShieldCheck, CheckSquare, Square,
  Lock, Eye, Server, FileSearch, ShieldAlert, Bug,
} from "lucide-react";

const CHECK_CATEGORIES = [
  { icon: Lock,        label: "HTTPS / TLS Certificate",        detail: "Validates HTTPS is enforced and the TLS certificate is valid and not expired." },
  { icon: ShieldCheck, label: "Security Headers",               detail: "Checks all 6 key response headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy." },
  { icon: Server,      label: "Technology Fingerprinting",      detail: "Detects which web server, framework, CMS, and CDN are visible from response headers and page source." },
  { icon: Eye,         label: "Cookie Security Flags",          detail: "(Full) Checks all cookies for HttpOnly, Secure, and SameSite attributes." },
  { icon: FileSearch,  label: "Exposed Sensitive Files",        detail: "(Full) Probes for publicly accessible .git, .env, wp-config.php, and backup archives." },
  { icon: ShieldAlert, label: "Admin Panel Exposure",           detail: "(Full) Checks whether admin panels (/wp-admin, /phpmyadmin, etc.) are accessible without authentication." },
  { icon: Globe,       label: "robots.txt & Error Disclosure",  detail: "(Full) Analyses robots.txt for sensitive path disclosure and error pages for stack traces." },
  { icon: Bug,         label: "CORS & Cache Policies",          detail: "(Full) Checks for wildcard CORS and missing Cache-Control on authenticated pages." },
];

export default function NewScan() {
  const [, setLocation] = useLocation();
  const createScan = useCreateScan();

  const [name, setName] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [scanType, setScanType] = useState<"quick" | "full">("full");
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showChecks, setShowChecks] = useState(false);

  // Pre-fill from query params when navigating from "Re-audit" button
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const url  = params.get("url");
    const n    = params.get("name");
    if (url) setTargetUrl(url);
    if (n)   setName(n);
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!confirmed) return;
    setError(null);
    createScan.mutate(
      { data: { name, targetUrl, scanType } },
      {
        onSuccess: (result) => setLocation(`/scans/${result.scan.id}`),
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

      {/* Page header */}
      <div className="flex items-start gap-4">
        <div className="p-3 rounded-xl bg-primary/10 border border-primary/20 mt-1">
          <ShieldCheck className="w-6 h-6 text-primary" />
        </div>
        <div>
          <h1 className="text-3xl font-bold tracking-tight mb-1">External Security Audit</h1>
          <p className="text-muted-foreground font-mono text-sm">
            A passive, read-only analysis of your website from an outside perspective — no credentials, no changes, no intrusion.
          </p>
        </div>
      </div>

      {/* What we check */}
      <div className="bg-secondary/40 border border-border rounded-xl overflow-hidden">
        <button
          type="button"
          className="w-full flex items-center justify-between px-5 py-4 text-sm font-mono text-muted-foreground hover:text-foreground transition-colors"
          onClick={() => setShowChecks((v) => !v)}
        >
          <span className="uppercase tracking-widest text-xs">What gets checked</span>
          <span className="text-xs">{showChecks ? "▲ hide" : "▼ show"}</span>
        </button>
        {showChecks && (
          <div className="px-5 pb-5 grid grid-cols-1 sm:grid-cols-2 gap-3 border-t border-border pt-4">
            {CHECK_CATEGORIES.map(({ icon: Icon, label, detail }) => (
              <div key={label} className="flex items-start gap-3">
                <Icon className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
                <div>
                  <p className="text-sm font-semibold text-foreground">{label}</p>
                  <p className="text-xs text-muted-foreground leading-relaxed">{detail}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="bg-card border border-border rounded-xl shadow-sm p-6 lg:p-8">
        <form onSubmit={handleSubmit} className="space-y-8">

          {/* Scan label */}
          <div className="space-y-3">
            <label className="block text-sm font-mono text-muted-foreground uppercase tracking-widest">
              Audit Label
            </label>
            <input
              type="text"
              required
              placeholder="e.g. My Company Homepage"
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
                placeholder="https://yourwebsite.com"
                className="w-full bg-background border border-border rounded-md pl-10 pr-4 py-3 font-mono text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-all"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
              />
            </div>
          </div>

          {/* Scan depth */}
          <div className="space-y-3">
            <label className="block text-sm font-mono text-muted-foreground uppercase tracking-widest">
              Audit Depth
            </label>
            <div className="grid grid-cols-2 gap-4">
              <label className={`relative flex flex-col gap-2 p-4 cursor-pointer rounded-lg border-2 transition-all ${scanType === "quick" ? "border-primary bg-primary/5" : "border-border bg-background hover:bg-muted/30"}`}>
                <input type="radio" name="scanType" value="quick" checked={scanType === "quick"} onChange={() => setScanType("quick")} className="sr-only" />
                <Zap className={`w-5 h-5 ${scanType === "quick" ? "text-primary" : "text-muted-foreground"}`} />
                <span className="font-bold text-foreground font-mono text-sm">QUICK AUDIT</span>
                <span className="text-xs text-muted-foreground leading-relaxed">
                  HTTPS, TLS cert, all 6 security headers, tech fingerprint. Results in seconds.
                </span>
              </label>

              <label className={`relative flex flex-col gap-2 p-4 cursor-pointer rounded-lg border-2 transition-all ${scanType === "full" ? "border-primary bg-primary/5" : "border-border bg-background hover:bg-muted/30"}`}>
                <input type="radio" name="scanType" value="full" checked={scanType === "full"} onChange={() => setScanType("full")} className="sr-only" />
                <ShieldCheck className={`w-5 h-5 ${scanType === "full" ? "text-primary" : "text-muted-foreground"}`} />
                <span className="font-bold text-foreground font-mono text-sm">FULL AUDIT</span>
                <span className="text-xs text-muted-foreground leading-relaxed">
                  Everything in Quick plus cookies, exposed files, admin panels, robots.txt, and error disclosure.
                </span>
              </label>
            </div>
          </div>

          {/* Authorization confirmation */}
          <div className={`rounded-lg border p-4 transition-all ${confirmed ? "border-primary/40 bg-primary/5" : "border-border bg-secondary/30"}`}>
            <label className="flex items-start gap-3 cursor-pointer" onClick={() => setConfirmed((v) => !v)}>
              <span className="mt-0.5 flex-shrink-0">
                {confirmed
                  ? <CheckSquare className="w-5 h-5 text-primary" />
                  : <Square className="w-5 h-5 text-muted-foreground" />}
              </span>
              <span className="text-sm text-foreground leading-relaxed">
                <span className="font-semibold">I confirm I own this website or have explicit written permission to perform security testing on it.</span>
                {" "}I understand this tool performs a passive read-only audit and does not attempt to gain unauthorized access, bypass authentication, or modify the target site.
              </span>
            </label>
          </div>

          {error && (
            <div className="bg-destructive/10 border border-destructive/30 rounded-md px-4 py-3 text-sm text-destructive font-mono">
              {error}
            </div>
          )}

          <div className="pt-4 border-t border-border flex justify-end">
            <button
              type="submit"
              disabled={createScan.isPending || !name.trim() || !targetUrl.trim() || !confirmed}
              className="bg-primary text-primary-foreground hover:bg-primary/90 px-8 py-3 rounded-md font-bold font-mono tracking-widest disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_20px_rgba(20,184,100,0.3)] transition-all flex items-center gap-2"
            >
              {createScan.isPending ? (
                <>
                  <div className="w-4 h-4 border-t-2 border-primary-foreground rounded-full animate-spin" />
                  AUDITING…
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  RUN AUDIT
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
