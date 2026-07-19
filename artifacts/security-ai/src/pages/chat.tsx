import { useState, useRef, useEffect } from "react";
import { useGetChatHistory, useSendChatMessage, useClearChatHistory, getGetChatHistoryQueryKey } from "@workspace/api-client-react";
import { Bot, User, Send, Trash2, Loader2, AlertCircle } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { cn } from "@/lib/utils";

export default function ChatAssistant() {
  const { data: messages, isLoading } = useGetChatHistory();
  const sendMessage = useSendChatMessage();
  const clearChat = useClearChatHistory();
  const queryClient = useQueryClient();
  
  const [input, setInput] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, sendMessage.isPending]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || sendMessage.isPending) return;

    const content = input;
    setInput("");

    sendMessage.mutate({ data: { content } }, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getGetChatHistoryQueryKey() });
      }
    });
  };

  const handleClear = () => {
    if (confirm("Clear all conversation history?")) {
      clearChat.mutate(undefined, {
        onSuccess: () => {
          queryClient.invalidateQueries({ queryKey: getGetChatHistoryQueryKey() });
        }
      });
    }
  };

  return (
    <div className="h-full flex flex-col p-4 md:p-6 lg:p-8 max-w-5xl mx-auto">
      <div className="flex items-center justify-between mb-6 shrink-0">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-3">
            <Bot className="w-8 h-8 text-primary" />
            Security Intelligence Bot
          </h1>
          <p className="text-muted-foreground font-mono text-sm mt-1">Ask questions about vulnerabilities, mitigations, or scan results</p>
        </div>
        <button 
          onClick={handleClear}
          className="text-muted-foreground hover:text-destructive flex items-center gap-2 text-xs font-mono transition-colors bg-secondary/50 hover:bg-destructive/10 px-3 py-2 rounded border border-transparent hover:border-destructive/30"
        >
          <Trash2 className="w-3.5 h-3.5" /> CLEAR
        </button>
      </div>

      <div className="flex-1 bg-card border border-border rounded-xl overflow-hidden flex flex-col shadow-sm relative">
        {/* Chat Messages */}
        <div className="flex-1 overflow-y-auto p-4 md:p-6 space-y-6">
          {isLoading ? (
             <div className="flex items-center justify-center h-full">
               <Loader2 className="w-8 h-8 text-primary animate-spin" />
             </div>
          ) : messages?.length === 0 ? (
             <div className="flex flex-col items-center justify-center h-full text-center text-muted-foreground space-y-4">
                <div className="w-16 h-16 bg-secondary/50 rounded-full flex items-center justify-center border border-border">
                  <Bot className="w-8 h-8 opacity-50" />
                </div>
                <div>
                  <p className="font-mono mb-2">Systems online. Awaiting inquiry.</p>
                  <div className="flex flex-wrap justify-center gap-2 mt-4 text-xs">
                    <span className="bg-secondary px-3 py-1.5 rounded-full border border-border cursor-pointer hover:border-primary/50 transition-colors" onClick={() => setInput("Explain CWE-79 to me.")}>Explain CWE-79</span>
                    <span className="bg-secondary px-3 py-1.5 rounded-full border border-border cursor-pointer hover:border-primary/50 transition-colors" onClick={() => setInput("How do I fix a SQL injection?")}>Fix SQL Injection</span>
                  </div>
                </div>
             </div>
          ) : (
            <>
              <div className="flex justify-center">
                <span className="text-[10px] font-mono uppercase bg-secondary text-muted-foreground px-2 py-0.5 rounded">Chat session secured</span>
              </div>
              
              {messages?.map((msg, i) => (
                <div key={msg.id || i} className={cn("flex gap-4 max-w-[85%]", msg.role === 'user' ? "ml-auto flex-row-reverse" : "")}>
                  <div className={cn(
                    "w-8 h-8 rounded shrink-0 flex items-center justify-center border mt-1",
                    msg.role === 'user' ? "bg-accent/10 border-accent/20 text-accent" : "bg-primary/10 border-primary/20 text-primary"
                  )}>
                    {msg.role === 'user' ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
                  </div>
                  
                  <div className={cn(
                    "px-4 py-3 rounded-lg text-sm md:text-base whitespace-pre-wrap leading-relaxed shadow-sm",
                    msg.role === 'user' 
                      ? "bg-accent/10 border border-accent/20 text-foreground" 
                      : "bg-secondary border border-border text-foreground/90 font-mono text-[13px]"
                  )}>
                    {/* Basic parsing for code blocks inside the message if it's the bot */}
                    {msg.role === 'assistant' ? (
                       <MessageContent text={msg.content} />
                    ) : (
                      msg.content
                    )}
                  </div>
                </div>
              ))}
              
              {sendMessage.isPending && (
                <div className="flex gap-4 max-w-[85%]">
                  <div className="w-8 h-8 rounded shrink-0 flex items-center justify-center border mt-1 bg-primary/10 border-primary/20 text-primary">
                    <Bot className="w-4 h-4" />
                  </div>
                  <div className="px-4 py-3 rounded-lg bg-secondary border border-border text-primary font-mono text-sm flex items-center gap-2">
                    <span className="w-2 h-2 bg-primary rounded-full animate-bounce" style={{ animationDelay: "0ms" }} />
                    <span className="w-2 h-2 bg-primary rounded-full animate-bounce" style={{ animationDelay: "150ms" }} />
                    <span className="w-2 h-2 bg-primary rounded-full animate-bounce" style={{ animationDelay: "300ms" }} />
                  </div>
                </div>
              )}
            </>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Input Area */}
        <div className="p-4 bg-background border-t border-border">
          <form onSubmit={handleSubmit} className="relative flex items-center">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Query intelligence database..."
              className="w-full bg-secondary border border-border rounded-md pl-4 pr-12 py-3.5 font-mono text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-all placeholder:text-muted-foreground/50"
              disabled={sendMessage.isPending}
            />
            <button
              type="submit"
              disabled={!input.trim() || sendMessage.isPending}
              className="absolute right-2 p-2 text-muted-foreground hover:text-primary disabled:opacity-50 disabled:hover:text-muted-foreground transition-colors"
            >
              <Send className="w-5 h-5" />
            </button>
          </form>
          <div className="mt-2 text-center flex items-center justify-center gap-1.5 text-[10px] text-muted-foreground font-mono">
            <AlertCircle className="w-3 h-3" /> AI may produce inaccurate information. Verify critical security advice.
          </div>
        </div>
      </div>
    </div>
  );
}

// Helper component to roughly parse markdown code blocks
function MessageContent({ text }: { text: string }) {
  if (!text) return null;
  
  // Very basic regex to split by ``` code blocks
  const parts = text.split(/(```[\s\S]*?```)/g);
  
  return (
    <>
      {parts.map((part, index) => {
        if (part.startsWith('```') && part.endsWith('```')) {
          // Extract language (optional) and code
          const match = part.match(/```(\w*)\n?([\s\S]*?)```/);
          const lang = match?.[1] || '';
          const code = match?.[2] || '';
          
          return (
            <div key={index} className="my-3 bg-background border border-border rounded overflow-hidden">
              {lang && (
                <div className="bg-secondary/80 text-[10px] uppercase px-3 py-1 border-b border-border text-muted-foreground font-bold">
                  {lang}
                </div>
              )}
              <pre className="p-3 overflow-x-auto text-green-400">
                <code>{code.trim()}</code>
              </pre>
            </div>
          );
        }
        
        // Handle bold basic markdown **text**
        const boldParts = part.split(/(\*\*[\s\S]*?\*\*)/g);
        return (
          <span key={index}>
            {boldParts.map((bp, i) => {
              if (bp.startsWith('**') && bp.endsWith('**')) {
                return <strong key={i} className="text-primary font-bold">{bp.slice(2, -2)}</strong>;
              }
              return bp;
            })}
          </span>
        );
      })}
    </>
  );
}
