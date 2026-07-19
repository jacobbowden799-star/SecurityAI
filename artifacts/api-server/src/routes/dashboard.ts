/**
 * Dashboard routes — aggregated stats for the main SecurityAI dashboard.
 */
import { Router, type IRouter } from "express";
import { desc, gte, sql, count } from "drizzle-orm";
import { db, scansTable, findingsTable } from "@workspace/db";
import { GetDashboardSummaryResponse } from "@workspace/api-zod";

const router: IRouter = Router();

// ─── GET /dashboard/summary ───────────────────────────────────────────────────
router.get("/dashboard/summary", async (req, res): Promise<void> => {
  // Total scans
  const [totalResult] = await db
    .select({ count: count() })
    .from(scansTable);
  const totalScans = Number(totalResult?.count ?? 0);

  // Scans this week
  const oneWeekAgo = new Date();
  oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

  const [weekResult] = await db
    .select({ count: count() })
    .from(scansTable)
    .where(gte(scansTable.createdAt, oneWeekAgo));
  const scansThisWeek = Number(weekResult?.count ?? 0);

  // Aggregate finding severity counts across all completed scans
  const [findingCounts] = await db
    .select({
      critical: sql<number>`SUM(${scansTable.criticalCount})`,
      high: sql<number>`SUM(${scansTable.highCount})`,
      medium: sql<number>`SUM(${scansTable.mediumCount})`,
      low: sql<number>`SUM(${scansTable.lowCount})`,
    })
    .from(scansTable)
    .where(sql`${scansTable.status} = 'completed'`);

  const criticalFindings = Number(findingCounts?.critical ?? 0);
  const highFindings = Number(findingCounts?.high ?? 0);
  const mediumFindings = Number(findingCounts?.medium ?? 0);
  const lowFindings = Number(findingCounts?.low ?? 0);

  // Overall security score: average of completed scan scores (or 100 if no scans)
  const [scoreResult] = await db
    .select({
      avgScore: sql<number>`AVG(${scansTable.securityScore})`,
    })
    .from(scansTable)
    .where(sql`${scansTable.status} = 'completed' AND ${scansTable.securityScore} IS NOT NULL`);

  const overallScore = scoreResult?.avgScore != null
    ? Math.round(Number(scoreResult.avgScore))
    : 100;

  // Recent scans (last 5)
  const recentScans = await db
    .select()
    .from(scansTable)
    .orderBy(desc(scansTable.createdAt))
    .limit(5);

  // Findings by category
  const categoryRows = await db
    .select({
      category: findingsTable.category,
      count: count(),
    })
    .from(findingsTable)
    .groupBy(findingsTable.category)
    .orderBy(desc(count()));

  const findingsByCategory = categoryRows.map((r) => ({
    category: r.category,
    count: Number(r.count),
  }));

  const response = {
    overallScore,
    totalScans,
    scansThisWeek,
    criticalFindings,
    highFindings,
    mediumFindings,
    lowFindings,
    recentScans: recentScans.map((s) => ({
      ...s,
      createdAt: s.createdAt.toISOString(),
      completedAt: s.completedAt ? s.completedAt.toISOString() : null,
    })),
    findingsByCategory,
  };

  res.json(GetDashboardSummaryResponse.parse(response));
});

export default router;
