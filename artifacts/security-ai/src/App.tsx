import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from '@/components/ui/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';
import { Route, Switch, Router as WouterRouter } from 'wouter';
import { Layout } from '@/components/layout';

import Dashboard from '@/pages/dashboard';
import Scans from '@/pages/scans/index';
import NewScan from '@/pages/scans/new';
import ScanDetail from '@/pages/scans/[id]';
import Reports from '@/pages/reports/index';
import ReportDetail from '@/pages/reports/[id]';
import ChatAssistant from '@/pages/chat';
import RepairEngine from '@/pages/repair';
import NotFound from '@/pages/not-found';

const queryClient = new QueryClient();

function Router() {
  return (
    <Layout>
      <Switch>
        <Route path="/" component={Dashboard} />
        <Route path="/scans" component={Scans} />
        <Route path="/scans/new" component={NewScan} />
        <Route path="/scans/:id" component={ScanDetail} />
        <Route path="/reports" component={Reports} />
        <Route path="/reports/:id" component={ReportDetail} />
        <Route path="/chat" component={ChatAssistant} />
        <Route path="/repair" component={RepairEngine} />
        <Route component={NotFound} />
      </Switch>
    </Layout>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, '')}>
          <Router />
        </WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
