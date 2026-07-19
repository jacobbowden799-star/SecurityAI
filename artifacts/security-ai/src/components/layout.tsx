import { Link, useLocation } from "wouter";
import { Shield, LayoutDashboard, Search, FileText, Bot, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/scans", label: "Scans", icon: Search },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/chat", label: "AI Assistant", icon: Bot },
];

export function Layout({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();

  return (
    <div className="flex h-screen overflow-hidden bg-background text-foreground dark">
      {/* Sidebar */}
      <aside className="w-64 border-r border-border bg-card flex flex-col">
        <div className="p-6 flex items-center gap-3 border-b border-border">
          <div className="h-8 w-8 bg-primary/20 text-primary rounded flex items-center justify-center border border-primary/30 shadow-[0_0_15px_rgba(20,184,100,0.2)]">
            <Shield className="w-5 h-5" />
          </div>
          <h1 className="font-mono font-bold text-xl tracking-tight text-primary">SecurityAI</h1>
        </div>
        
        <nav className="flex-1 py-6 px-4 space-y-1">
          {NAV_ITEMS.map((item) => {
            const isActive = location === item.href || (item.href !== '/' && location.startsWith(item.href));
            const Icon = item.icon;
            
            return (
              <Link key={item.href} href={item.href}>
                <div
                  className={cn(
                    "flex items-center gap-3 px-3 py-2.5 rounded-md cursor-pointer transition-all duration-200 font-medium text-sm",
                    isActive
                      ? "bg-primary/10 text-primary shadow-[inset_2px_0_0_0_hsl(var(--primary))] border border-primary/20"
                      : "text-muted-foreground hover:bg-muted hover:text-foreground border border-transparent"
                  )}
                >
                  <Icon className="w-4 h-4" />
                  {item.label}
                </div>
              </Link>
            );
          })}
        </nav>

        <div className="p-4 m-4 rounded-md bg-secondary/50 border border-border">
          <div className="flex items-center gap-2 text-yellow-500/80 mb-1">
            <AlertTriangle className="w-4 h-4" />
            <span className="text-xs font-mono font-bold">RESTRICTED</span>
          </div>
          <p className="text-[10px] text-muted-foreground leading-relaxed">
            Defensive tool only. Unauthorized scanning of external targets is prohibited and logged.
          </p>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto bg-background selection:bg-primary/30">
        <div className="h-full">
          {children}
        </div>
      </main>
    </div>
  );
}
