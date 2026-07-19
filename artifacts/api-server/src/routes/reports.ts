/**
 * Report routes — generate and retrieve security reports from completed scans.
 */
import { Router, type IRouter } from "express";
import { eq, desc } from "drizzle-orm";
import { db, scansTable, findingsTable, reportsTable } from "@workspace/db";
import {
  CreateReportBody,
  CreateReportResponse,
  ListReportsResponse,
  GetReportResponse,
  GetReportParams,
  DeleteReportParams,
} from "@workspace/api-zod";
import { generateReportSummary } from "../lib/scanner";

const router: IRouter = Router();

// ─── GET /reports ─────────────────────────────────────────────────────────────
router.get("/reports", async (req, res): Promise<void> => {
  const reports = await db
    .select()
    .from(reportsTable)
    .orderBy(desc(reportsTable.createdAt))
    .limit(50);

  const response = reports.map((r) => ({
    ...r,
    createdAt: r.createdAt.toISOString(),
  }));

  res.json(ListReportsResponse.parse(response));
});

// ─── POST /reports ────────────────────────────────────────────────────────────
router.post("/reports", async (req, res): Promise<void> => {
  const parsed = CreateReportBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const { scanId, title } = parsed.data;

  // Fetch the scan
  const scans = await db
    .select()
    .from(scansTable)
    .where(eq(scansTable.id, scanId))
    .limit(1);

  if (scans.length === 0) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }

  const scan = scans[0];

  if (scan.status !== "completed") {
    res.status(400).json({ error: "Report can only be generated for completed scans" });
    return;
  }

  // Fetch findings for this scan
  const findings = await db
    .select()
    .from(findingsTable)
    .where(eq(findingsTable.scanId, scanId));

  const score = scan.securityScore ?? 0;

  // Generate narrative summary and recommendations
  const { summary, recommendations } = generateReportSummary(
    scan.name,
    score,
    findings.map((f) => ({
      title: f.title,
      description: f.description,
      severity: f.severity as "critical" | "high" | "medium" | "low" | "info",
      category: f.category as
        | "hardcoded-secret"
        | "unsafe-pattern"
        | "missing-best-practice"
        | "weak-config"
        | "outdated-dependency",
      recommendation: f.recommendation,
      cweId: f.cweId ?? undefined,
    }))
  );

  const [report] = await db
    .insert(reportsTable)
    .values({
      scanId,
      scanName: scan.name,
      title,
      summary,
      securityScore: score,
      criticalCount: scan.criticalCount,
      highCount: scan.highCount,
      mediumCount: scan.mediumCount,
      lowCount: scan.lowCount,
      totalFindings: scan.totalFindings,
      recommendations,
    })
    .returning();

  const response = {
    ...report,
    createdAt: report.createdAt.toISOString(),
  };

  res.status(201).json(CreateReportResponse.parse(response));
});

// ─── GET /reports/:id ─────────────────────────────────────────────────────────
router.get("/reports/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const parsed = GetReportParams.safeParse({ id: parseInt(raw, 10) });
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid report ID" });
    return;
  }

  const report = await db
    .select()
    .from(reportsTable)
    .where(eq(reportsTable.id, parsed.data.id))
    .limit(1);

  if (report.length === 0) {
    res.status(404).json({ error: "Report not found" });
    return;
  }

  const response = {
    ...report[0],
    createdAt: report[0].createdAt.toISOString(),
  };

  res.json(GetReportResponse.parse(response));
});

// ─── DELETE /reports/:id ──────────────────────────────────────────────────────
router.delete("/reports/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const parsed = DeleteReportParams.safeParse({ id: parseInt(raw, 10) });
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid report ID" });
    return;
  }

  const result = await db
    .delete(reportsTable)
    .where(eq(reportsTable.id, parsed.data.id))
    .returning({ id: reportsTable.id });

  if (result.length === 0) {
    res.status(404).json({ error: "Report not found" });
    return;
  }

  res.status(204).send();
});

export default router;
