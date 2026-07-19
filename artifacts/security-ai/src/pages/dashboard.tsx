import { useGetDashboardSummary, Scan } from "@workspace/api-client-react";
import { BarChart, Bar, XAxis, YAxis, Tooltip as RechartsTooltip, ResponsiveContainer, Cell } from "recharts";
import { Link } from "wouter";
import { Shield, Activity, Search, AlertTriangle, ArrowRight } from "lucide-react";
import { ScoreGauge } from "@/components/score-gauge";
import { SeverityBadge } from "@/components/severity-badge";
import { formatDate } from "@/lib/utils";

export default function Dashboard() {
  const { data: summary, isLoading, isError } = useGetDashboardSummary();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-pulse flex flex-col items-center gap-4">
          <div className="w-12 h-12 rounded-full border-t-2 border-primary animate-spin" />
          <p className="text-muted-foreground font-mono">Fetching telemetry...</p>
        </div>
      </div>
    );
  }

  if (isError || !summary) {
    return (
      <div className="p-8 flex flex-col items-center justify-center h-full text-center">
        <AlertTriangle className="w-12 h-12 text-destructive mb-4" />
        <h2 className="text-xl font-bold mb-2">Telemetry Failure</h2>
        <p className="text-muted-foreground">Could not connect to analysis engine.</p>
      </div>
    );
  }

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight mb-1">Command Center</h1>
          <p className="text-muted-foreground font-mono text-sm">System status and recent threat intel</p>
        </div>
        <Link href="/scans/new">
          <div className="bg-primary text-primary-foreground hover:bg-primary/90 px-4 py-2 rounded-md font-bold font-mono tracking-tight flex items-center gap-2 cursor-pointer shadow-[0_0_15px_rgba(20,184,100,0.3)] transition-all">
            <Search className="w-4 h-4" />
            INITIATE SCAN
          </div>
        </Link>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {/* Score Card */}
        <div className="col-span-1 md:col-span-1 bg-card border border-border rounded-xl p-6 flex flex-col items-center justify-center gap-4 relative overflow-hidden group">
          <div className="absolute inset-0 bg-primary/5 opacity-0 group-hover:opacity-100 transition-opacity" />
          <h3 className="text-sm font-mono text-muted-foreground text-center uppercase tracking-widest w-full">Posture Score</h3>
          <ScoreGauge score={summary.overallScore} size="lg" />
        </div>

        {/* Stats Cards */}
        <div className="col-span-1 md:col-span-3 grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard title="Total Scans" value={summary.totalScans} icon={Activity} />
          <StatCard title="Scans This Week" value={summary.scansThisWeek} icon={Activity} />
          <StatCard 
            title="Critical Threats" 
            value={summary.criticalFindings} 
            icon={Shield} 
            colorClass="text-red-500" 
            bgClass="bg-red-500/10 border-red-500/20" 
          />
          <StatCard 
            title="High Threats" 
            value={summary.highFindings} 
            icon={AlertTriangle} 
            colorClass="text-orange-500" 
            bgClass="bg-orange-500/10 border-orange-500/20" 
          />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Chart */}
        <div className="bg-card border border-border rounded-xl p-6 flex flex-col h-[400px]">
          <h3 className="text-sm font-mono text-muted-foreground uppercase tracking-widest mb-6 border-b border-border pb-4">Findings by Category</h3>
          <div className="flex-1 w-full min-h-0">
            {summary.findingsByCategory.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={summary.findingsByCategory} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                  <XAxis 
                    dataKey="category" 
                    tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 12, fontFamily: 'monospace' }} 
                    axisLine={{ stroke: 'hsl(var(--border))' }}
                    tickLine={{ stroke: 'hsl(var(--border))' }}
                    angle={-45}
                    textAnchor="end"
                  />
                  <YAxis 
                    tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 12, fontFamily: 'monospace' }} 
                    axisLine={{ stroke: 'hsl(var(--border))' }}
                    tickLine={{ stroke: 'hsl(var(--border))' }}
                  />
                  <RechartsTooltip 
                    cursor={{ fill: 'hsl(var(--muted))' }}
                    contentStyle={{ backgroundColor: 'hsl(var(--card))', borderColor: 'hsl(var(--border))', borderRadius: '8px', color: 'hsl(var(--foreground))' }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {summary.findingsByCategory.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill="hsl(var(--primary))" />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
               <div className="flex items-center justify-center h-full text-muted-foreground font-mono text-sm">
                 No category data available
               </div>
            )}
          </div>
        </div>

        {/* Recent Scans */}
        <div className="bg-card border border-border rounded-xl flex flex-col h-[400px]">
          <div className="p-6 border-b border-border flex items-center justify-between">
            <h3 className="text-sm font-mono text-muted-foreground uppercase tracking-widest">Recent Scans</h3>
            <Link href="/scans">
              <div className="text-xs text-primary hover:underline flex items-center gap-1 cursor-pointer font-mono">
                View All <ArrowRight className="w-3 h-3" />
              </div>
            </Link>
          </div>
          <div className="flex-1 overflow-auto p-2">
            {summary.recentScans.length > 0 ? (
              <div className="space-y-1">
                {summary.recentScans.map((scan) => (
                  <Link key={scan.id} href={`/scans/${scan.id}`}>
                    <div className="p-4 hover:bg-muted/50 rounded-lg cursor-pointer transition-colors border border-transparent hover:border-border flex items-center justify-between group">
                      <div>
                        <div className="font-semibold text-foreground group-hover:text-primary transition-colors">{scan.name}</div>
                        <div className="text-xs text-muted-foreground font-mono mt-1 flex gap-2">
                          <span className="uppercase">{scan.scanType}</span> • <span>{formatDate(scan.createdAt)}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className="flex gap-1.5">
                          {scan.criticalCount > 0 && <span className="w-2 h-2 rounded-full bg-red-500 mt-1" title={`${scan.criticalCount} Critical`} />}
                          {scan.highCount > 0 && <span className="w-2 h-2 rounded-full bg-orange-500 mt-1" title={`${scan.highCount} High`} />}
                        </div>
                        <div className="text-right">
                          <ScoreGauge score={scan.securityScore} size="sm" />
                        </div>
                      </div>
                    </div>
                  </Link>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-full text-muted-foreground p-8 text-center space-y-3">
                <Search className="w-8 h-8 opacity-20" />
                <p>No scans recorded yet.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function StatCard({ title, value, icon: Icon, colorClass = "text-primary", bgClass = "bg-primary/10 border-primary/20" }: any) {
  return (
    <div className={`p-4 rounded-xl border ${bgClass} flex flex-col gap-3 justify-between relative overflow-hidden`}>
      <div className="flex justify-between items-start">
        <h4 className="text-xs font-mono text-muted-foreground uppercase tracking-widest z-10">{title}</h4>
        <Icon className={`w-4 h-4 ${colorClass} opacity-50 z-10`} />
      </div>
      <div className={`text-3xl font-bold font-mono tracking-tight z-10 ${colorClass}`}>
        {value}
      </div>
      <div className={`absolute -bottom-4 -right-4 w-16 h-16 rounded-full opacity-10 blur-xl ${bgClass.split(' ')[0]}`} />
    </div>
  );
}
