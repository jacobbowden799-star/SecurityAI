import { pgTable, serial, text, integer, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { scansTable } from "./scans";

// ─── Reports ─────────────────────────────────────────────────────────────────
export const reportsTable = pgTable("reports", {
  id: serial("id").primaryKey(),
  scanId: integer("scan_id")
    .notNull()
    .references(() => scansTable.id, { onDelete: "cascade" }),
  scanName: text("scan_name").notNull(),
  title: text("title").notNull(),
  summary: text("summary").notNull(),
  securityScore: integer("security_score").notNull(),
  criticalCount: integer("critical_count").notNull().default(0),
  highCount: integer("high_count").notNull().default(0),
  mediumCount: integer("medium_count").notNull().default(0),
  lowCount: integer("low_count").notNull().default(0),
  totalFindings: integer("total_findings").notNull().default(0),
  recommendations: text("recommendations").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const insertReportSchema = createInsertSchema(reportsTable).omit({
  id: true,
  createdAt: true,
});

export type InsertReport = z.infer<typeof insertReportSchema>;
export type Report = typeof reportsTable.$inferSelect;
