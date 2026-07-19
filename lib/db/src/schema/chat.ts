import { pgTable, serial, text, integer, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

// ─── Chat Messages ─────────────────────────────────────────────────────────────
export const chatMessagesTable = pgTable("chat_messages", {
  id: serial("id").primaryKey(),
  role: text("role").notNull(), // user | assistant
  content: text("content").notNull(),
  scanId: integer("scan_id"), // optional reference to a scan for context
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const insertChatMessageSchema = createInsertSchema(chatMessagesTable).omit({
  id: true,
  createdAt: true,
});

export type InsertChatMessage = z.infer<typeof insertChatMessageSchema>;
export type ChatMessage = typeof chatMessagesTable.$inferSelect;
