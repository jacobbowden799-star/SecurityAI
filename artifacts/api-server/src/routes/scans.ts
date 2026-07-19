/**
 * Scan routes — External Security Audit: create, list, get, delete website scans.
 */
import { Router, type IRouter } from "express";
import { eq, desc, and, lt } from "drizzle-orm";
import { db, scansTable, findingsTable } from "@workspace/db";
import {
  CreateScanBody,
  CreateScanResponse,
  ListScansResponse,
  GetScanResponse,
  GetScanFindingsResponse,
  GetScanParams,
  DeleteScanParams,
} from "@workspace/api-zod";
import { scanWebsite, calculateSecurityScore } from "../lib/website-scanner";

const router: IRouter = Router();

function serialiseScan(s: typeof scansTable.$inferSelect) {
  return {
    ...s,
    createdAt: s.createdAt.toISOString(),
    completedAt: s.completedAt ? s.completedAt.toISOString() : null,
  };
}

function serialiseFinding(f: typeof findingsTable.$inferSelect) {
  return { ...f, createdAt: f.createdAt.toISOString() };
}

// ─── GET /scans ───────────────────────────────────────────────────────────────
router.get("/scans", async (_req, res): Promise<void> => {
  const scans = await db.select().from(scansTable).orderBy(desc(scansTable.createdAt)).limit(50);
  res.json(ListScansResponse.parse(scans.map(serialiseScan)));
});

// ─── POST /scans ──────────────────────────────────────────────────────────────
router.post("/scans", async (req, res): Promise<void> => {
  const parsed = CreateScanBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }

  const { name, targetUrl, scanType } = parsed.data;
  const normUrl = /^https?:\/\//i.test(targetUrl) ? targetUrl : `https://${targetUrl}`;

  // Look up most recent completed scan for same URL (baseline comparison)
  const [baseline] = await db
    .select({ id: scansTable.id, securityScore: scansTable.securityScore })
    .from(scansTable)
    .where(and(eq(scansTable.targetUrl, normUrl), eq(scansTable.status, "completed")))
    .orderBy(desc(scansTable.createdAt))
    .limit(1);

  const [scan] = await db
    .insert(scansTable)
    .values({ name, targetUrl: normUrl, scanType, status: "running" })
    .returning();

  try {
    const { findings, fetchResult } = await scanWebsite(normUrl, scanType as "quick" | "full");

    if (!fetchResult.ok && findings.length === 0) {
      await db.update(scansTable).set({ status: "failed" }).where(eq(scansTable.id, scan.id));
      res.status(400).json({ error: fetchResult.error ?? "Could not reach the URL. Check it is publicly accessible." });
      return;
    }

    const actionableFindings = findings.filter((f) => f.severity !== "info");
    const score = calculateSecurityScore(actionableFindings);
    const criticalCount = findings.filter((f) => f.severity === "critical").length;
    const highCount     = findings.filter((f) => f.severity === "high").length;
    const mediumCount   = findings.filter((f) => f.severity === "medium").length;
    const lowCount      = findings.filter((f) => f.severity === "low").length;

    // Baseline comparison
    const baselineScanId  = baseline?.id ?? null;
    const baselineScore   = baseline?.securityScore ?? null;
    const scoreDelta      = baselineScore !== null ? score - baselineScore : null;

    if (findings.length > 0) {
      await db.insert(findingsTable).values(
        findings.map((f) => ({
          scanId: scan.id,
          title: f.title,
          description: f.description,
          severity: f.severity,
          category: f.category,
          lineNumber: null,
          codeSnippet: f.codeSnippet ?? null,
          recommendation: f.recommendation,
          cweId: f.cweId ?? null,
        }))
      );
    }

    const [updated] = await db
      .update(scansTable)
      .set({
        status: "completed",
        securityScore: score,
        totalFindings: findings.length,
        criticalCount, highCount, mediumCount, lowCount,
        baselineScanId, baselineScore, scoreDelta,
        completedAt: new Date(),
      })
      .where(eq(scansTable.id, scan.id))
      .returning();

    const persistedFindings = await db.select().from(findingsTable).where(eq(findingsTable.scanId, scan.id));

    res.status(201).json(CreateScanResponse.parse({
      scan: serialiseScan(updated),
      findings: persistedFindings.map(serialiseFinding),
    }));
  } catch (err) {
    await db.update(scansTable).set({ status: "failed" }).where(eq(scansTable.id, scan.id));
    req.log.error({ err }, "Scan failed");
    res.status(500).json({ error: "Scan failed unexpectedly" });
  }
});

// ─── GET /scans/:id ───────────────────────────────────────────────────────────
router.get("/scans/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const parsed = GetScanParams.safeParse({ id: parseInt(raw, 10) });
  if (!parsed.success) { res.status(400).json({ error: "Invalid scan ID" }); return; }

  const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, parsed.data.id)).limit(1);
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }

  const findings = await db.select().from(findingsTable).where(eq(findingsTable.scanId, parsed.data.id));

  res.json(GetScanResponse.parse({
    scan: serialiseScan(scan),
    findings: findings.map(serialiseFinding),
  }));
});

// ─── DELETE /scans/:id ────────────────────────────────────────────────────────
router.delete("/scans/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const parsed = DeleteScanParams.safeParse({ id: parseInt(raw, 10) });
  if (!parsed.success) { res.status(400).json({ error: "Invalid scan ID" }); return; }

  const result = await db.delete(scansTable).where(eq(scansTable.id, parsed.data.id)).returning({ id: scansTable.id });
  if (result.length === 0) { res.status(404).json({ error: "Scan not found" }); return; }
  res.status(204).send();
});

// ─── GET /scans/:id/findings ──────────────────────────────────────────────────
router.get("/scans/:id/findings", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const id = parseInt(raw, 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid scan ID" }); return; }

  const [scan] = await db.select({ id: scansTable.id }).from(scansTable).where(eq(scansTable.id, id)).limit(1);
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }

  const findings = await db.select().from(findingsTable).where(eq(findingsTable.scanId, id));
  res.json(GetScanFindingsResponse.parse(findings.map(serialiseFinding)));
});

export default router;
