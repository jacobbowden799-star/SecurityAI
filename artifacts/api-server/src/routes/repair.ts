/**
 * POST /api/repair
 *
 * Scans a website URL and returns a structured list of before/after
 * code fix recommendations for each security finding.
 */
import { Router, type IRouter } from "express";
import { z } from "zod";
import { scanWebsite, calculateSecurityScore } from "../lib/website-scanner";
import { generateRepairPlans, getDetectedFramework } from "../lib/repair-codegen";

const router: IRouter = Router();

const RepairBody = z.object({
  targetUrl: z.string().min(3),
});

router.post("/repair", async (req, res): Promise<void> => {
  const parsed = RepairBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "targetUrl is required" });
    return;
  }

  const rawUrl = parsed.data.targetUrl;
  const normUrl = /^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`;

  try {
    const { findings, fetchResult } = await scanWebsite(normUrl, "full");

    if (!fetchResult.ok && findings.length === 0) {
      res.status(400).json({
        error:
          fetchResult.error ??
          "Could not reach that URL. Check it is publicly accessible and try again.",
      });
      return;
    }

    const actionable = findings.filter((f) => f.severity !== "info");
    const score      = calculateSecurityScore(actionable);
    const plans      = generateRepairPlans(findings, fetchResult);
    const framework  = getDetectedFramework(fetchResult);

    res.json({
      targetUrl:   normUrl,
      framework,
      score,
      totalFindings:  findings.length,
      actionableCount: actionable.length,
      repairCount:    plans.length,
      detectedAt:     new Date().toISOString(),
      repairs:        plans,
    });
  } catch (err) {
    req.log.error({ err }, "Repair scan failed");
    res.status(500).json({ error: "Scan failed unexpectedly. Please try again." });
  }
});

export default router;
