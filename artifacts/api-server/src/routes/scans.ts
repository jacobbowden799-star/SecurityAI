/**
 * Scan routes — create, list, get, delete security scans.
 * Each scan runs the static code scanner and persists findings.
 */
import { Router, type IRouter } from "express";
import { eq, desc, sql } from "drizzle-orm";
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
import { scanCode, calculateSecurityScore } from "../lib/scanner";

const router: IRouter = Router();

// ─── GET /scans ───────────────────────────────────────────────────────────────
router.get("/scans", async (req, res): Promise<void> => {
  const scans = await db
    .select()
    .from(scansTable)
    .orderBy(desc(scansTable.createdAt))
    .limit(50);

  const response = scans.map((s) => ({
    ...s,
    createdAt: s.createdAt.toISOString(),
    completedAt: s.completedAt ? s.completedAt.toISOString() : null,
  }));

  res.json(ListScansResponse.parse(response));
});

// ─── POST /scans ──────────────────────────────────────────────────────────────
router.post("/scans", async (req, res): Promise<void> => {
  const parsed = CreateScanBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const { name, scanType, code, language } = parsed.data;

  // Insert scan with pending status
  const [scan] = await db
    .insert(scansTable)
    .values({
      name,
      scanType,
      status: "running",
      language: language ?? null,
      codeContent: code ?? null,
    })
    .returning();

  try {
    // Run the security scanner
    const findings = code ? scanCode(code, scanType as "code" | "dependency" | "config") : [];
    const securityScore = calculateSecurityScore(findings);

    // Count by severity
    const criticalCount = findings.filter((f) => f.severity === "critical").length;
    const highCount = findings.filter((f) => f.severity === "high").length;
    const mediumCount = findings.filter((f) => f.severity === "medium").length;
    const lowCount = findings.filter((f) => f.severity === "low").length;

    // Persist findings
    if (findings.length > 0) {
      await db.insert(findingsTable).values(
        findings.map((f) => ({
          scanId: scan.id,
          title: f.title,
          description: f.description,
          severity: f.severity,
          category: f.category,
          lineNumber: f.lineNumber ?? null,
          codeSnippet: f.codeSnippet ?? null,
          recommendation: f.recommendation,
          cweId: f.cweId ?? null,
        }))
      );
    }

    // Update scan to completed
    const [updatedScan] = await db
      .update(scansTable)
      .set({
        status: "completed",
        securityScore,
        totalFindings: findings.length,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        completedAt: new Date(),
      })
      .where(eq(scansTable.id, scan.id))
      .returning();

    const persistedFindings = await db
      .select()
      .from(findingsTable)
      .where(eq(findingsTable.scanId, scan.id));

    const response = {
      scan: {
        ...updatedScan,
        createdAt: updatedScan.createdAt.toISOString(),
        completedAt: updatedScan.completedAt ? updatedScan.completedAt.toISOString() : null,
      },
      findings: persistedFindings.map((f) => ({
        ...f,
        createdAt: f.createdAt.toISOString(),
      })),
    };

    res.status(201).json(CreateScanResponse.parse(response));
  } catch (err) {
    // Mark scan as failed
    await db
      .update(scansTable)
      .set({ status: "failed" })
      .where(eq(scansTable.id, scan.id));

    req.log.error({ err }, "Scan failed");
    res.status(500).json({ error: "Scan execution failed" });
  }
});

// ─── GET /scans/:id ───────────────────────────────────────────────────────────
router.get("/scans/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const parsed = GetScanParams.safeParse({ id: parseInt(raw, 10) });
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid scan ID" });
    return;
  }

  const scan = await db
    .select()
    .from(scansTable)
    .where(eq(scansTable.id, parsed.data.id))
    .limit(1);

  if (scan.length === 0) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }

  const findings = await db
    .select()
    .from(findingsTable)
    .where(eq(findingsTable.scanId, parsed.data.id));

  const response = {
    scan: {
      ...scan[0],
      createdAt: scan[0].createdAt.toISOString(),
      completedAt: scan[0].completedAt ? scan[0].completedAt.toISOString() : null,
    },
    findings: findings.map((f) => ({
      ...f,
      createdAt: f.createdAt.toISOString(),
    })),
  };

  res.json(GetScanResponse.parse(response));
});

// ─── DELETE /scans/:id ────────────────────────────────────────────────────────
router.delete("/scans/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const parsed = DeleteScanParams.safeParse({ id: parseInt(raw, 10) });
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid scan ID" });
    return;
  }

  const result = await db
    .delete(scansTable)
    .where(eq(scansTable.id, parsed.data.id))
    .returning({ id: scansTable.id });

  if (result.length === 0) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }

  res.status(204).send();
});

// ─── GET /scans/:id/findings ──────────────────────────────────────────────────
router.get("/scans/:id/findings", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const id = parseInt(raw, 10);
  if (isNaN(id)) {
    res.status(400).json({ error: "Invalid scan ID" });
    return;
  }

  // Verify scan exists
  const scan = await db
    .select({ id: scansTable.id })
    .from(scansTable)
    .where(eq(scansTable.id, id))
    .limit(1);

  if (scan.length === 0) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }

  const findings = await db
    .select()
    .from(findingsTable)
    .where(eq(findingsTable.scanId, id));

  const response = findings.map((f) => ({
    ...f,
    createdAt: f.createdAt.toISOString(),
  }));

  res.json(GetScanFindingsResponse.parse(response));
});

export default router;
