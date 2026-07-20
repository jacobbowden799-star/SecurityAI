import { useState, useEffect, useRef, useCallback } from "react";
import {
  Play, ShieldCheck, AlertTriangle, CheckCircle2, Clock, RotateCcw,
  FileCode2, Cpu, Wrench, FlaskConical, TrendingUp, Zap, ChevronRight,
  Terminal, GitCompare, History, BarChart3, X,
} from "lucide-react";
import { cn } from "@/lib/utils";

// ─── Demo Data ────────────────────────────────────────────────────────────────

interface Issue {
  id: number;
  title: string;
  severity: "critical" | "high" | "medium";
  file: string;
  line: number;
  description: string;
  beforeCode: string;
  afterCode: string;
  explanation: string;
  scoreGain: number;
}

const ISSUES: Issue[] = [
  {
    id: 1,
    title: "Hardcoded Database Credentials",
    severity: "critical",
    file: "src/config/database.js",
    line: 7,
    description: "Plaintext credentials embedded directly in source code.",
    beforeCode: `const mysql = require('mysql2');

// Database configuration
const connection = mysql.createConnection({
  host:     'prod-db.internal.company.com',
  user:     'app_admin',
  password: 'Sup3rS3cr3t!2024',
  database: 'customers_prod',
});

module.exports = connection;`,
    afterCode: `const mysql = require('mysql2');
require('dotenv').config();

// Database configuration — credentials from environment
const connection = mysql.createConnection({
  host:     process.env.DB_HOST,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

module.exports = connection;`,
    explanation:
      "Hardcoded credentials in source code are exposed to anyone with repository access (current or historical). The AI replaced all literal values with `process.env.*` references. A `.env.example` template and updated `.gitignore` were also generated. The original credentials must be rotated immediately.",
    scoreGain: 18,
  },
  {
    id: 2,
    title: "SQL Injection via String Concatenation",
    severity: "critical",
    file: "src/api/users.js",
    line: 23,
    description: "User-supplied input concatenated directly into SQL query string.",
    beforeCode: `app.get('/users/search', async (req, res) => {
  const { term } = req.query;

  // ⚠ VULNERABLE: direct string interpolation
  const query = \`SELECT id, name, email
    FROM users
    WHERE name LIKE '%\${term}%'
       OR email = '\${term}'\`;

  const [rows] = await db.execute(query);
  res.json(rows);
});`,
    afterCode: `app.get('/users/search', [
  query('term').isString().trim().isLength({ max: 100 }).escape(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { term } = req.query;

  // ✓ SAFE: parameterised query — no injection possible
  const [rows] = await db.execute(
    'SELECT id, name, email FROM users WHERE name LIKE ? OR email = ?',
    [\`%\${term}%\`, term]
  );
  res.json(rows);
});`,
    explanation:
      "The vulnerable query built a SQL string using template literals with raw user input — a classic SQL injection. A single quote in `term` could break the query and allow arbitrary SQL execution. The fix uses a parameterised query with `?` placeholders; the database driver handles escaping. Input validation with `express-validator` was also added to reject excessively long or malformed input before it reaches the database.",
    scoreGain: 22,
  },
  {
    id: 3,
    title: "Missing Authentication on Admin Route",
    severity: "critical",
    file: "src/routes/admin.js",
    line: 12,
    description: "Sensitive admin endpoint accessible without authentication.",
    beforeCode: `const express = require('express');
const router = express.Router();
const { getAllUsers, deleteUser } = require('../controllers/users');

// Admin dashboard routes
router.get('/admin/users',        getAllUsers);
router.delete('/admin/users/:id', deleteUser);
router.get('/admin/logs',         getSystemLogs);
router.post('/admin/config',      updateConfig);

module.exports = router;`,
    afterCode: `const express = require('express');
const router  = express.Router();
const { verifyToken, requireRole } = require('../middleware/auth');
const { getAllUsers, deleteUser }   = require('../controllers/users');

// All admin routes require authentication + admin role
router.use(verifyToken);
router.use(requireRole('admin'));

router.get('/admin/users',        getAllUsers);
router.delete('/admin/users/:id', deleteUser);
router.get('/admin/logs',         getSystemLogs);
router.post('/admin/config',      updateConfig);

module.exports = router;`,
    explanation:
      "All four admin endpoints were fully unauthenticated — any user (or attacker) could enumerate users, delete accounts, read system logs, and change configuration without any credentials. The fix uses `router.use()` to apply `verifyToken` and `requireRole('admin')` middleware to every route in the file, ensuring the check cannot be accidentally skipped on a new route added later.",
    scoreGain: 20,
  },
  {
    id: 4,
    title: "Stack Trace Exposed in Error Response",
    severity: "high",
    file: "src/middleware/errorHandler.js",
    line: 8,
    description: "Full exception stack trace returned to client in JSON response.",
    beforeCode: `// Global error handling middleware
function errorHandler(err, req, res, next) {
  console.error(err);

  res.status(err.status || 500).json({
    error:   err.message,
    stack:   err.stack,
    details: err,
  });
}

module.exports = errorHandler;`,
    afterCode: `const logger = require('../lib/logger');

// Global error handling middleware
function errorHandler(err, req, res, next) {
  // Log full detail server-side only
  logger.error({ err, url: req.url, method: req.method }, 'Unhandled error');

  // Never expose internals to the client
  const isProduction = process.env.NODE_ENV === 'production';
  res.status(err.status || 500).json({
    error: isProduction ? 'An unexpected error occurred' : err.message,
  });
}

module.exports = errorHandler;`,
    explanation:
      "Returning `err.stack` and `err` in the API response leaks internal file paths, line numbers, framework versions, and logic details. Attackers use this to map your codebase and find exploitable paths. The fix logs full error detail server-side using a structured logger, while returning only a generic message to clients in production. In development the message is still shown for debugging convenience.",
    scoreGain: 12,
  },
  {
    id: 5,
    title: "No Rate Limiting on Login Endpoint",
    severity: "high",
    file: "src/routes/auth.js",
    line: 4,
    description: "Login route allows unlimited requests, enabling brute-force attacks.",
    beforeCode: `const express = require('express');
const router = express.Router();
const { login, logout } = require('../controllers/auth');

// Auth routes — no rate limiting!
router.post('/auth/login',  login);
router.post('/auth/logout', logout);
router.post('/auth/reset',  requestPasswordReset);

module.exports = router;`,
    afterCode: `const express   = require('express');
const router    = express.Router();
const rateLimit = require('express-rate-limit');
const { login, logout } = require('../controllers/auth');

// 10 attempts per 15 minutes per IP — blocks brute force
const loginLimiter = rateLimit({
  windowMs:       15 * 60 * 1000,
  max:            10,
  message:        { error: 'Too many login attempts. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders:  false,
});

router.post('/auth/login',  loginLimiter, login);
router.post('/auth/logout', logout);
router.post('/auth/reset',  loginLimiter, requestPasswordReset);

module.exports = router;`,
    explanation:
      "Without rate limiting, an attacker can automate thousands of password guesses per second. A standard password list attack can crack a weak 8-character password in minutes. The fix adds `express-rate-limit` allowing only 10 attempts per IP per 15-minute window. This is applied to both `/auth/login` and `/auth/reset` (which can also be abused for account enumeration via timing attacks).",
    scoreGain: 10,
  },
];

const SCAN_LINES = [
  "[00:00.1] Initializing Autonomous Code Repair Engine v2.4.1...",
  "[00:00.3] Loading static analysis rules (CVE-2024 database)...",
  "[00:00.5] Parsing project structure — 847 source files detected",
  "[00:00.7] Building abstract syntax tree...",
  "[00:00.9] Scanning src/config/database.js",
  "[00:01.1] Scanning src/api/users.js",
  "[00:01.3] Scanning src/routes/admin.js",
  "[00:01.5] Scanning src/middleware/errorHandler.js",
  "[00:01.7] Scanning src/routes/auth.js",
  "[00:01.9] ⚠  ISSUE [CRITICAL] Hardcoded credentials — src/config/database.js:7",
  "[00:02.1] ⚠  ISSUE [CRITICAL] SQL injection — src/api/users.js:23",
  "[00:02.3] ⚠  ISSUE [CRITICAL] Unauthenticated admin routes — src/routes/admin.js:12",
  "[00:02.5] ⚠  ISSUE [HIGH] Stack trace disclosure — src/middleware/errorHandler.js:8",
  "[00:02.7] ⚠  ISSUE [HIGH] Missing rate limiting — src/routes/auth.js:4",
  "[00:02.9] Cross-referencing OWASP Top 10 (2023)...",
  "[00:03.1] Scan complete. 5 security issues require remediation.",
];

const VERIFY_CHECKS = [
  "Running SAST analysis on patched files...",
  "Executing unit test suite (147 tests)...",
  "Checking no regressions in API contracts...",
  "Validating environment variable references...",
  "Confirming parameterised queries in all DB calls...",
  "Testing rate limiter behaviour under load...",
  "Final OWASP vulnerability sweep...",
  "All checks passed. Repairs verified.",
];

const APPLY_STEPS = [
  "Creating encrypted backup...",
  "Applying AI-generated patch...",
  "Updating project files...",
  "Running affected tests...",
];

type Phase = "idle" | "scanning" | "issue" | "verifying" | "complete";
type IssueStep = "analyzing" | "generating" | "diffing" | "applying" | "done";

interface CompletedRepair {
  issue: Issue;
  timestamp: Date;
  undone: boolean;
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function SeverityPill({ s }: { s: "critical" | "high" | "medium" }) {
  return (
    <span className={cn(
      "px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold border tracking-wider",
      s === "critical" ? "text-red-400 bg-red-400/10 border-red-400/20" :
      s === "high"     ? "text-orange-400 bg-orange-400/10 border-orange-400/20" :
                         "text-yellow-400 bg-yellow-400/10 border-yellow-400/20"
    )}>
      {s}
    </span>
  );
}

function CodeBlock({
  code, label, variant,
}: { code: string; label: string; variant: "before" | "after" }) {
  const lines = code.split("\n");
  return (
    <div className={cn(
      "rounded-lg border overflow-hidden flex-1 min-w-0",
      variant === "before" ? "border-red-500/20" : "border-emerald-500/20"
    )}>
      <div className={cn(
        "flex items-center gap-2 px-4 py-2 text-xs font-mono font-bold border-b",
        variant === "before"
          ? "bg-red-500/10 border-red-500/20 text-red-400"
          : "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
      )}>
        <span>{variant === "before" ? "✗" : "✓"}</span>
        {label}
      </div>
      <pre className="p-4 text-xs font-mono overflow-x-auto bg-black/40 text-slate-300 leading-relaxed">
        {lines.map((line, i) => {
          const isRemoved = variant === "before" && line.includes("⚠");
          return (
            <div
              key={i}
              className={cn(
                "px-1 rounded",
                isRemoved && "bg-red-500/10 text-red-300"
              )}
            >
              {line || "\u00A0"}
            </div>
          );
        })}
      </pre>
    </div>
  );
}

function StepRow({
  icon: Icon, label, status, active,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  status: "pending" | "active" | "done";
  active?: boolean;
}) {
  return (
    <div className={cn(
      "flex items-center gap-3 px-4 py-3 rounded-lg border transition-all duration-300",
      status === "active" ? "bg-primary/10 border-primary/30 text-foreground" :
      status === "done"   ? "bg-secondary/30 border-border text-muted-foreground" :
                            "border-transparent text-muted-foreground/50"
    )}>
      <div className={cn(
        "w-7 h-7 rounded-full flex items-center justify-center border flex-shrink-0",
        status === "active" ? "border-primary/40 bg-primary/20" :
        status === "done"   ? "border-emerald-500/40 bg-emerald-500/10" :
                              "border-border bg-secondary/30"
      )}>
        {status === "done"   ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> :
         status === "active" ? <div className="w-3 h-3 rounded-full bg-primary animate-pulse" /> :
                               <Icon className="w-3.5 h-3.5 text-muted-foreground/40" />}
      </div>
      <span className={cn("text-sm font-medium", status === "active" && "text-primary font-semibold")}>
        {label}
      </span>
      {status === "active" && <ChevronRight className="w-3.5 h-3.5 text-primary ml-auto animate-pulse" />}
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function RepairEngine() {
  const [phase, setPhase]                 = useState<Phase>("idle");
  const [scanLines, setScanLines]         = useState<string[]>([]);
  const [scanProgress, setScanProgress]   = useState(0);
  const [currentIdx, setCurrentIdx]       = useState(0);
  const [issueStep, setIssueStep]         = useState<IssueStep>("analyzing");
  const [applyStep, setApplyStep]         = useState(0);
  const [verifyLines, setVerifyLines]     = useState<string[]>([]);
  const [verifyProgress, setVerifyProgress] = useState(0);
  const [completed, setCompleted]         = useState<CompletedRepair[]>([]);
  const [totalScore, setTotalScore]       = useState(0);
  const [elapsed, setElapsed]             = useState(0);
  const [undoneIdx, setUndoneIdx]         = useState<number | null>(null);
  const [showUndo, setShowUndo]           = useState(false);

  const terminalRef   = useRef<HTMLDivElement>(null);
  const timerRef      = useRef<ReturnType<typeof setInterval> | null>(null);
  const startTimeRef  = useRef<number>(0);

  // ── Scroll terminal to bottom ──────────────────────────────────────────────
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [scanLines, verifyLines]);

  // ── Elapsed timer ──────────────────────────────────────────────────────────
  useEffect(() => {
    if (phase !== "idle" && phase !== "complete") {
      timerRef.current = setInterval(() => {
        setElapsed(Math.floor((Date.now() - startTimeRef.current) / 1000));
      }, 1000);
    } else {
      if (timerRef.current) clearInterval(timerRef.current);
    }
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [phase]);

  // ── Kick off a single issue's repair sequence ──────────────────────────────
  const repairIssue = useCallback((idx: number) => {
    setCurrentIdx(idx);
    setIssueStep("analyzing");
    setApplyStep(0);

    const t = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

    (async () => {
      await t(1800);
      setIssueStep("generating");

      await t(1800);
      setIssueStep("diffing");

      await t(2500);
      setIssueStep("applying");

      // Step through apply sub-steps
      for (let s = 0; s < APPLY_STEPS.length; s++) {
        setApplyStep(s);
        await t(700);
      }
      setApplyStep(APPLY_STEPS.length); // all done

      await t(500);
      setIssueStep("done");

      setCompleted((prev) => [
        ...prev,
        { issue: ISSUES[idx], timestamp: new Date(), undone: false },
      ]);
      setTotalScore((s) => s + ISSUES[idx].scoreGain);

      await t(600);

      // Advance
      if (idx + 1 < ISSUES.length) {
        repairIssue(idx + 1);
      } else {
        // Start verification
        setPhase("verifying");
        setVerifyLines([]);
        setVerifyProgress(0);
        runVerification();
      }
    })();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Verification phase ─────────────────────────────────────────────────────
  const runVerification = useCallback(() => {
    let i = 0;
    const step = () => {
      if (i >= VERIFY_CHECKS.length) {
        setVerifyProgress(100);
        setTimeout(() => setPhase("complete"), 800);
        return;
      }
      setVerifyLines((p) => [...p, VERIFY_CHECKS[i]]);
      setVerifyProgress(Math.round(((i + 1) / VERIFY_CHECKS.length) * 100));
      i++;
      setTimeout(step, 600);
    };
    setTimeout(step, 400);
  }, []);

  // ── Start the full sequence ────────────────────────────────────────────────
  const startRepair = useCallback(() => {
    setPhase("scanning");
    setScanLines([]);
    setScanProgress(0);
    setCompleted([]);
    setTotalScore(0);
    setElapsed(0);
    setUndoneIdx(null);
    startTimeRef.current = Date.now();

    let i = 0;
    const addLine = () => {
      if (i >= SCAN_LINES.length) {
        setScanProgress(100);
        setTimeout(() => {
          setPhase("issue");
          repairIssue(0);
        }, 600);
        return;
      }
      setScanLines((p) => [...p, SCAN_LINES[i]]);
      setScanProgress(Math.round(((i + 1) / SCAN_LINES.length) * 100));
      i++;
      setTimeout(addLine, i < 9 ? 200 : 280);
    };
    setTimeout(addLine, 300);
  }, [repairIssue]);

  // ── Undo last repair ──────────────────────────────────────────────────────
  const handleUndo = useCallback(() => {
    if (completed.length === 0 || phase !== "complete") return;
    const lastIdx = completed.length - 1;
    const lastRepair = completed[lastIdx];
    setCompleted((p) => p.map((r, i) => i === lastIdx ? { ...r, undone: true } : r));
    setTotalScore((s) => s - lastRepair.issue.scoreGain);
    setUndoneIdx(lastIdx);
    setShowUndo(true);
    setTimeout(() => setShowUndo(false), 4000);
  }, [completed, phase]);

  // ── Helpers ────────────────────────────────────────────────────────────────
  const fmtTime = (s: number) => `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;

  const issue = ISSUES[currentIdx] ?? ISSUES[0];

  const stepStatus = (target: Phase | "issue", sub?: IssueStep): "pending" | "active" | "done" => {
    if (phase === "idle") return "pending";
    const order: Phase[] = ["scanning", "issue", "verifying", "complete"];
    const cur = order.indexOf(phase);
    const tgt = order.indexOf(target as Phase);
    if (tgt < cur) return "done";
    if (tgt > cur) return "pending";
    return "active";
  };

  const activeRepairs = completed.filter((r) => !r.undone);

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">

      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-start gap-4">
          <div className="p-3 rounded-xl bg-primary/10 border border-primary/20">
            <Cpu className="w-6 h-6 text-primary" />
          </div>
          <div>
            <div className="flex items-center gap-3 mb-1">
              <h1 className="text-2xl font-bold tracking-tight">Autonomous Code Repair Engine</h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold border text-primary border-primary/30 bg-primary/10 uppercase tracking-widest">
                DEMO
              </span>
            </div>
            <p className="text-muted-foreground font-mono text-sm">
              AI-powered detection and automatic remediation of security vulnerabilities
            </p>
          </div>
        </div>

        {phase === "idle" ? (
          <button
            onClick={startRepair}
            className="flex items-center gap-2 bg-primary text-primary-foreground hover:bg-primary/90 px-6 py-3 rounded-lg font-bold font-mono tracking-widest shadow-[0_0_25px_rgba(20,184,100,0.4)] hover:shadow-[0_0_35px_rgba(20,184,100,0.6)] transition-all text-sm"
          >
            <Play className="w-4 h-4" />
            START AUTOMATIC CODE REPAIR
          </button>
        ) : phase === "complete" ? (
          <div className="flex items-center gap-2">
            <button
              onClick={handleUndo}
              disabled={completed.filter((r) => !r.undone).length === 0}
              className="flex items-center gap-2 bg-secondary hover:bg-muted border border-border px-4 py-2 rounded-lg font-mono text-sm transition-all disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <RotateCcw className="w-4 h-4" />
              UNDO LAST
            </button>
            <button
              onClick={startRepair}
              className="flex items-center gap-2 bg-primary/20 hover:bg-primary/30 border border-primary/30 text-primary px-4 py-2 rounded-lg font-mono text-sm font-bold transition-all"
            >
              <Play className="w-4 h-4" />
              RUN AGAIN
            </button>
          </div>
        ) : (
          <div className="flex items-center gap-3 text-sm font-mono text-muted-foreground">
            <div className="w-2 h-2 rounded-full bg-primary animate-pulse" />
            REPAIR ENGINE ACTIVE — {fmtTime(elapsed)}
          </div>
        )}
      </div>

      {/* ── Stats Row ───────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          {
            icon: AlertTriangle, label: "Issues Found",
            value: phase === "idle" ? "—" : ISSUES.length,
            color: "text-orange-400", bg: "bg-orange-400/10 border-orange-400/20",
          },
          {
            icon: ShieldCheck, label: "Repaired",
            value: phase === "idle" ? "—" : activeRepairs.length,
            color: "text-emerald-400", bg: "bg-emerald-400/10 border-emerald-400/20",
          },
          {
            icon: TrendingUp, label: "Score Gain",
            value: phase === "idle" ? "—" : (totalScore > 0 ? `+${totalScore}` : "0"),
            color: "text-primary", bg: "bg-primary/10 border-primary/20",
          },
          {
            icon: Clock, label: "Elapsed",
            value: phase === "idle" ? "—" : fmtTime(elapsed),
            color: "text-blue-400", bg: "bg-blue-400/10 border-blue-400/20",
          },
        ].map(({ icon: Icon, label, value, color, bg }) => (
          <div key={label} className={cn("rounded-xl border p-5 flex flex-col gap-2", bg)}>
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-muted-foreground uppercase tracking-widest">{label}</span>
              <Icon className={cn("w-4 h-4 opacity-60", color)} />
            </div>
            <div className={cn("text-2xl font-bold font-mono", color)}>{value}</div>
          </div>
        ))}
      </div>

      {/* ── Main Panel ──────────────────────────────────────────────────────── */}
      {phase !== "idle" && (
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-5">

          {/* Left: Workflow steps */}
          <div className="lg:col-span-2 bg-card border border-border rounded-xl p-5 space-y-1">
            <h3 className="text-xs font-mono text-muted-foreground uppercase tracking-widest mb-4">
              Repair Workflow
            </h3>
            <StepRow icon={Terminal}      label="1. Code Analysis"           status={stepStatus("scanning")} />
            <div className="ml-4 space-y-1 border-l border-border pl-4 py-1">
              {ISSUES.map((iss, i) => {
                const isDone = completed.some((r) => r.issue.id === iss.id);
                const isActive = phase === "issue" && currentIdx === i;
                return (
                  <div key={iss.id} className={cn(
                    "flex items-center gap-2 px-3 py-2 rounded text-xs font-mono transition-all",
                    isDone   ? "text-emerald-400" :
                    isActive ? "text-primary bg-primary/5 border border-primary/20 rounded" :
                               "text-muted-foreground/40"
                  )}>
                    {isDone   ? <CheckCircle2 className="w-3 h-3 flex-shrink-0" /> :
                     isActive ? <div className="w-2 h-2 rounded-full bg-primary animate-pulse flex-shrink-0" /> :
                                <div className="w-2 h-2 rounded-full border border-muted-foreground/20 flex-shrink-0" />}
                    <span className="truncate">{iss.file.split("/").pop()}</span>
                    <SeverityPill s={iss.severity} />
                  </div>
                );
              })}
            </div>
            <StepRow icon={Cpu}           label="2. AI Repair Generation"    status={phase === "issue" ? "active" : stepStatus("issue")} />
            <StepRow icon={Wrench}        label="3. Apply Patches"            status={phase === "issue" && issueStep === "applying" ? "active" : (phase === "verifying" || phase === "complete") ? "done" : "pending"} />
            <StepRow icon={FlaskConical}  label="4. Verification"             status={stepStatus("verifying")} />
            <StepRow icon={ShieldCheck}   label="5. Complete"                 status={stepStatus("complete")} />
          </div>

          {/* Right: Live output */}
          <div className="lg:col-span-3 space-y-4">

            {/* Scanning terminal */}
            {phase === "scanning" && (
              <div className="bg-black/80 border border-border rounded-xl overflow-hidden">
                <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-secondary/30">
                  <Terminal className="w-4 h-4 text-primary" />
                  <span className="font-mono text-xs text-primary font-bold">SCANNER OUTPUT</span>
                  <div className="ml-auto flex items-center gap-2">
                    <div className="h-1.5 w-32 bg-secondary rounded-full overflow-hidden">
                      <div className="h-full bg-primary rounded-full transition-all duration-300" style={{ width: `${scanProgress}%` }} />
                    </div>
                    <span className="font-mono text-xs text-muted-foreground">{scanProgress}%</span>
                  </div>
                </div>
                <div ref={terminalRef} className="h-64 overflow-y-auto p-4 space-y-0.5 text-xs font-mono">
                  {scanLines.map((line, i) => (
                    <div key={i} className={cn(
                      "leading-relaxed",
                      line.includes("⚠") ? "text-red-400 font-bold" : "text-emerald-400/80"
                    )}>
                      {line}
                    </div>
                  ))}
                  {scanProgress < 100 && (
                    <div className="text-primary animate-pulse">█</div>
                  )}
                </div>
              </div>
            )}

            {/* Issue repair panel */}
            {phase === "issue" && (
              <div className="bg-card border border-border rounded-xl overflow-hidden">
                {/* Issue header */}
                <div className="px-5 py-4 border-b border-border bg-secondary/30 flex items-start justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityPill s={issue.severity} />
                      <span className="text-xs font-mono text-muted-foreground">
                        {issue.file}:{issue.line}
                      </span>
                    </div>
                    <h3 className="font-bold text-foreground">{issue.title}</h3>
                    <p className="text-xs text-muted-foreground mt-1">{issue.description}</p>
                  </div>
                  <div className="text-right text-xs font-mono text-muted-foreground whitespace-nowrap">
                    {currentIdx + 1} / {ISSUES.length}
                  </div>
                </div>

                <div className="p-5 space-y-4">
                  {/* Analyzing */}
                  {(issueStep === "analyzing" || issueStep === "generating") && (
                    <div className="flex flex-col items-center justify-center py-10 gap-5">
                      <div className="relative">
                        <div className="w-16 h-16 rounded-full border-2 border-primary/30 flex items-center justify-center">
                          <Cpu className="w-7 h-7 text-primary animate-pulse" />
                        </div>
                        <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-primary animate-spin" />
                      </div>
                      <div className="text-center space-y-1">
                        <p className="font-mono text-sm text-primary font-bold">
                          {issueStep === "analyzing" ? "AI is analyzing the issue…" : "Generating secure replacement code…"}
                        </p>
                        <p className="font-mono text-xs text-muted-foreground">
                          {issueStep === "analyzing"
                            ? `Cross-referencing CWE-${issue.id === 1 ? "798" : issue.id === 2 ? "89" : issue.id === 3 ? "306" : issue.id === 4 ? "209" : "307"} patterns`
                            : "Synthesising idiomatic, tested replacement…"}
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Diff view */}
                  {(issueStep === "diffing" || issueStep === "applying" || issueStep === "done") && (
                    <div>
                      <div className="flex items-center gap-2 mb-3">
                        <GitCompare className="w-4 h-4 text-primary" />
                        <span className="text-xs font-mono text-muted-foreground uppercase tracking-widest">Code Comparison</span>
                      </div>
                      <div className="flex gap-3 flex-col sm:flex-row">
                        <CodeBlock code={issue.beforeCode} label="VULNERABLE (original)" variant="before" />
                        <CodeBlock code={issue.afterCode}  label="SECURE (AI repair)"    variant="after"  />
                      </div>

                      {/* AI explanation */}
                      <div className="mt-3 bg-primary/5 border border-primary/20 rounded-lg p-4">
                        <div className="flex items-center gap-2 mb-2">
                          <Cpu className="w-3.5 h-3.5 text-primary" />
                          <span className="text-xs font-mono text-primary font-bold uppercase tracking-widest">AI Explanation</span>
                        </div>
                        <p className="text-xs text-muted-foreground leading-relaxed font-mono">{issue.explanation}</p>
                      </div>
                    </div>
                  )}

                  {/* Apply steps */}
                  {issueStep === "applying" && (
                    <div className="bg-black/40 border border-border rounded-lg p-4 space-y-2">
                      {APPLY_STEPS.map((step, i) => (
                        <div key={i} className={cn(
                          "flex items-center gap-3 text-xs font-mono transition-all",
                          i < applyStep  ? "text-emerald-400" :
                          i === applyStep ? "text-primary animate-pulse" :
                                           "text-muted-foreground/30"
                        )}>
                          {i < applyStep   ? <CheckCircle2 className="w-3.5 h-3.5" /> :
                           i === applyStep ? <div className="w-3.5 h-3.5 border border-primary rounded-full animate-spin border-t-transparent" /> :
                                             <div className="w-3.5 h-3.5 border border-muted-foreground/20 rounded-full" />}
                          {step}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Verification panel */}
            {phase === "verifying" && (
              <div className="bg-black/80 border border-border rounded-xl overflow-hidden">
                <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-secondary/30">
                  <FlaskConical className="w-4 h-4 text-blue-400" />
                  <span className="font-mono text-xs text-blue-400 font-bold">VERIFICATION SUITE</span>
                  <div className="ml-auto flex items-center gap-2">
                    <div className="h-1.5 w-32 bg-secondary rounded-full overflow-hidden">
                      <div className="h-full bg-blue-400 rounded-full transition-all duration-500" style={{ width: `${verifyProgress}%` }} />
                    </div>
                    <span className="font-mono text-xs text-muted-foreground">{verifyProgress}%</span>
                  </div>
                </div>
                <div ref={terminalRef} className="h-56 overflow-y-auto p-4 space-y-1 text-xs font-mono">
                  {verifyLines.map((line, i) => (
                    <div key={i} className={cn(
                      "flex items-center gap-2",
                      line.includes("passed") || line.includes("Passed") ? "text-emerald-400 font-bold" : "text-blue-400/80"
                    )}>
                      {(line.includes("passed") || line.includes("Passed")) ? "✓" : "›"} {line}
                    </div>
                  ))}
                  {verifyProgress < 100 && <div className="text-blue-400 animate-pulse">█</div>}
                </div>
              </div>
            )}

            {/* Complete banner */}
            {phase === "complete" && (
              <div className="bg-emerald-500/5 border border-emerald-500/30 rounded-xl p-6 flex items-center gap-5">
                <div className="w-14 h-14 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center flex-shrink-0">
                  <ShieldCheck className="w-7 h-7 text-emerald-400" />
                </div>
                <div className="flex-1">
                  <h3 className="text-lg font-bold text-emerald-400 mb-1">All Repairs Complete & Verified</h3>
                  <p className="text-sm text-muted-foreground font-mono">
                    {activeRepairs.length} vulnerabilities patched · Security score improved by +{totalScore} points · All tests passing
                  </p>
                </div>
                <Zap className="w-6 h-6 text-emerald-400 opacity-50 flex-shrink-0" />
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Idle splash ─────────────────────────────────────────────────────── */}
      {phase === "idle" && (
        <div className="bg-card border border-border rounded-xl p-10 flex flex-col items-center text-center gap-6 relative overflow-hidden">
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(20,184,100,0.04),transparent_70%)]" />
          <div className="relative z-10 space-y-4">
            <div className="w-20 h-20 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center mx-auto shadow-[0_0_40px_rgba(20,184,100,0.2)]">
              <Cpu className="w-9 h-9 text-primary" />
            </div>
            <div>
              <h2 className="text-2xl font-bold mb-2">AI-Powered Automatic Remediation</h2>
              <p className="text-muted-foreground max-w-lg mx-auto text-sm leading-relaxed">
                The engine scans your codebase for security vulnerabilities, generates idiomatic secure replacements using AI,
                applies the patches, and verifies with automated tests — all in one click.
              </p>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-2 text-left">
              {[
                { icon: Terminal,    label: "Static Analysis",    detail: "AST-based vulnerability detection" },
                { icon: Cpu,         label: "AI Code Generation", detail: "Context-aware secure replacements" },
                { icon: Wrench,      label: "Auto-Patching",      detail: "Backup, apply, update in one step" },
                { icon: FlaskConical,label: "Verification",       detail: "Automated tests confirm each fix" },
              ].map(({ icon: Icon, label, detail }) => (
                <div key={label} className="bg-secondary/40 border border-border rounded-lg p-4">
                  <Icon className="w-5 h-5 text-primary mb-2" />
                  <p className="font-bold text-sm">{label}</p>
                  <p className="text-xs text-muted-foreground mt-1">{detail}</p>
                </div>
              ))}
            </div>
            <button
              onClick={startRepair}
              className="flex items-center gap-2 bg-primary text-primary-foreground hover:bg-primary/90 px-8 py-3.5 rounded-lg font-bold font-mono tracking-widest shadow-[0_0_30px_rgba(20,184,100,0.4)] hover:shadow-[0_0_40px_rgba(20,184,100,0.6)] transition-all mx-auto"
            >
              <Play className="w-5 h-5" />
              START AUTOMATIC CODE REPAIR
            </button>
          </div>
        </div>
      )}

      {/* ── Repair History ───────────────────────────────────────────────────── */}
      {completed.length > 0 && (
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-border flex items-center gap-3">
            <History className="w-4 h-4 text-primary" />
            <h3 className="font-bold text-sm">Repair History</h3>
            <span className="ml-auto text-xs font-mono text-muted-foreground">
              {activeRepairs.length} active · {completed.filter((r) => r.undone).length} undone
            </span>
          </div>
          <div className="divide-y divide-border">
            {completed.map((repair, i) => (
              <div key={i} className={cn(
                "flex items-center gap-4 px-5 py-4 transition-all",
                repair.undone && "opacity-40 line-through"
              )}>
                <div className={cn(
                  "w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 border",
                  repair.undone
                    ? "bg-gray-500/10 border-gray-500/20"
                    : "bg-emerald-500/10 border-emerald-500/20"
                )}>
                  {repair.undone
                    ? <X className="w-3.5 h-3.5 text-gray-400" />
                    : <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-semibold text-sm truncate">{repair.issue.title}</span>
                    <SeverityPill s={repair.issue.severity} />
                  </div>
                  <div className="flex items-center gap-3 mt-0.5">
                    <span className="text-xs font-mono text-muted-foreground">{repair.issue.file}</span>
                    <span className="text-xs text-muted-foreground">·</span>
                    <span className="text-xs text-muted-foreground font-mono">
                      {repair.timestamp.toLocaleTimeString()}
                    </span>
                  </div>
                </div>
                <div className={cn(
                  "font-mono font-bold text-sm flex-shrink-0",
                  repair.undone ? "text-gray-400" : "text-emerald-400"
                )}>
                  {repair.undone ? "—" : `+${repair.issue.scoreGain} pts`}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Code Changes Timeline ────────────────────────────────────────────── */}
      {phase === "complete" && (
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-border flex items-center gap-3">
            <BarChart3 className="w-4 h-4 text-primary" />
            <h3 className="font-bold text-sm">Score Improvement Timeline</h3>
          </div>
          <div className="p-5">
            <div className="flex items-end gap-2 h-28">
              {(() => {
                const points = [0, ...ISSUES.map((_, i) =>
                  ISSUES.slice(0, i + 1).reduce((s, iss) => s + iss.scoreGain, 0)
                )];
                const max = points[points.length - 1] || 1;
                const labels = ["Start", ...ISSUES.map((iss) => iss.file.split("/").pop()!.replace(".js", ""))];
                return points.map((val, i) => (
                  <div key={i} className="flex-1 flex flex-col items-center gap-1.5">
                    <span className="text-[10px] font-mono text-primary font-bold">
                      {val > 0 ? `+${val}` : ""}
                    </span>
                    <div
                      className="w-full rounded-t-sm transition-all duration-700 bg-primary/70"
                      style={{ height: `${Math.max(4, (val / max) * 80)}px` }}
                    />
                    <span className="text-[9px] font-mono text-muted-foreground text-center truncate w-full">
                      {labels[i]}
                    </span>
                  </div>
                ));
              })()}
            </div>
          </div>
        </div>
      )}

      {/* ── Undo toast ───────────────────────────────────────────────────────── */}
      <div className={cn(
        "fixed bottom-6 right-6 flex items-center gap-3 bg-card border border-border rounded-xl px-5 py-4 shadow-2xl transition-all duration-500 z-50",
        showUndo ? "opacity-100 translate-y-0" : "opacity-0 translate-y-4 pointer-events-none"
      )}>
        <RotateCcw className="w-4 h-4 text-primary" />
        <div>
          <p className="text-sm font-semibold">Repair undone</p>
          <p className="text-xs text-muted-foreground font-mono">Original code restored from backup</p>
        </div>
      </div>
    </div>
  );
}
