import { pgTable, serial, text, integer, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

// ─── Scans ───────────────────────────────────────────────────────────────────
export const scansTable = pgTable("scans", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  scanType: text("scan_type").notNull(), // code | dependency | config
  status: text("status").notNull().default("pending"), // pending | running | completed | failed
  securityScore: integer("security_score"),
  totalFindings: integer("total_findings").notNull().default(0),
  criticalCount: integer("critical_count").notNull().default(0),
  highCount: integer("high_count").notNull().default(0),
  mediumCount: integer("medium_count").notNull().default(0),
  lowCount: integer("low_count").notNull().default(0),
  language: text("language"),
  codeContent: text("code_content"), // the submitted code
  createdAt: timestamp("created_at").defaultNow().notNull(),
  completedAt: timestamp("completed_at"),
});

export const insertScanSchema = createInsertSchema(scansTable).omit({
  id: true,
  createdAt: true,
  completedAt: true,
});

export type InsertScan = z.infer<typeof insertScanSchema>;
export type Scan = typeof scansTable.$inferSelect;

// ─── Findings ─────────────────────────────────────────────────────────────────
export const findingsTable = pgTable("findings", {
  id: serial("id").primaryKey(),
  scanId: integer("scan_id")
    .notNull()
    .references(() => scansTable.id, { onDelete: "cascade" }),
  title: text("title").notNull(),
  description: text("description").notNull(),
  severity: text("severity").notNull(), // critical | high | medium | low | info
  category: text("category").notNull(), // hardcoded-secret | unsafe-pattern | missing-best-practice | weak-config | outdated-dependency
  lineNumber: integer("line_number"),
  codeSnippet: text("code_snippet"),
  recommendation: text("recommendation").notNull(),
  cweId: text("cwe_id"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const insertFindingSchema = createInsertSchema(findingsTable).omit({
  id: true,
  createdAt: true,
});

export type InsertFinding = z.infer<typeof insertFindingSchema>;
export type Finding = typeof findingsTable.$inferSelect;
