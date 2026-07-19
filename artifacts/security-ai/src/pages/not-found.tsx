import { Link } from "wouter";
import { AlertTriangle } from "lucide-react";

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center h-full p-8 text-center space-y-4">
      <AlertTriangle className="w-16 h-16 text-primary mb-4" />
      <h1 className="text-4xl font-bold font-mono tracking-tight text-foreground">404</h1>
      <p className="text-muted-foreground font-mono text-lg max-w-md">
        The requested resource could not be located in the current environment.
      </p>
      <Link href="/">
        <button className="mt-4 bg-primary text-primary-foreground hover:bg-primary/90 px-6 py-2 rounded-md font-bold font-mono tracking-tight transition-all">
          RETURN TO DASHBOARD
        </button>
      </Link>
    </div>
  );
}
