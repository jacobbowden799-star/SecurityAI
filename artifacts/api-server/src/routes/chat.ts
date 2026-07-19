/**
 * AI chat routes — security assistant conversation history and message handling.
 */
import { Router, type IRouter } from "express";
import { asc } from "drizzle-orm";
import { db, chatMessagesTable } from "@workspace/db";
import {
  SendChatMessageBody,
  SendChatMessageResponse,
  GetChatHistoryResponse,
} from "@workspace/api-zod";
import { generateAssistantResponse } from "../lib/ai-assistant";

const router: IRouter = Router();

// ─── GET /chat/messages ───────────────────────────────────────────────────────
router.get("/chat/messages", async (req, res): Promise<void> => {
  const messages = await db
    .select()
    .from(chatMessagesTable)
    .orderBy(asc(chatMessagesTable.createdAt))
    .limit(200);

  const response = messages.map((m) => ({
    ...m,
    createdAt: m.createdAt.toISOString(),
  }));

  res.json(GetChatHistoryResponse.parse(response));
});

// ─── POST /chat/messages ──────────────────────────────────────────────────────
router.post("/chat/messages", async (req, res): Promise<void> => {
  const parsed = SendChatMessageBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const { content, scanId } = parsed.data;

  // Persist the user message
  await db.insert(chatMessagesTable).values({
    role: "user",
    content,
    scanId: scanId ?? null,
  });

  // Generate the assistant response
  const assistantContent = generateAssistantResponse(content);

  // Persist and return the assistant response
  const [assistantMessage] = await db
    .insert(chatMessagesTable)
    .values({
      role: "assistant",
      content: assistantContent,
      scanId: scanId ?? null,
    })
    .returning();

  const response = {
    ...assistantMessage,
    createdAt: assistantMessage.createdAt.toISOString(),
  };

  res.status(201).json(SendChatMessageResponse.parse(response));
});

// ─── DELETE /chat/messages/clear ──────────────────────────────────────────────
router.delete("/chat/messages/clear", async (req, res): Promise<void> => {
  await db.delete(chatMessagesTable);
  res.status(204).send();
});

export default router;
