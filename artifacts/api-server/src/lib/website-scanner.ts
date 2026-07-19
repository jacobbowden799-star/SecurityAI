/**
 * SecurityAI Website Scanner
 *
 * Fetches a target URL (that the user owns or has permission to test) and
 * analyses the HTTP response for common security misconfigurations:
 *
 *   - Missing or weak security headers
 *   - HTTPS enforcement / HTTP redirect
 *   - Server information disclosure
 *   - Cookie security flags
 *   - CORS wildcard policy
 *   - Cache-control on sensitive pages
 *
 * This is a PASSIVE, read-only scan. It only makes a normal HTTP GET request
 * — the same request any browser would make. It does not probe, fuzz, or
 * exploit anything.
 */

import https from "https";
import http from "http";
import { URL } from "url";

export interface WebsiteFinding {
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  codeSnippet?: string;   // holds the observed header value for context
  recommendation: string;
  cweId?: string;
}

export interface FetchResult {
  ok: boolean;
  statusCode?: number;
  headers: Record<string, string | string[]>;
  finalUrl: string;         // after any redirects
  redirectedToHttps: boolean;
  error?: string;
}

// ─── HTTP fetcher ─────────────────────────────────────────────────────────────

/**
 * Fetch just the response headers for a URL (no body needed).
 * Follows up to 5 redirects and records whether an HTTP→HTTPS redirect occurred.
 */
export async function fetchHeaders(
  rawUrl: string,
  maxRedirects = 5
): Promise<FetchResult> {
  let url: URL;
  try {
    // Normalise: add https:// if the user forgot the scheme
    const withScheme = /^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`;
    url = new URL(withScheme);
  } catch {
    return { ok: false, headers: {}, finalUrl: rawUrl, redirectedToHttps: false, error: "Invalid URL" };
  }

  let redirectCount = 0;
  let startedOnHttp = url.protocol === "http:";
  let movedToHttps = false;
  let currentUrl = url;

  while (redirectCount <= maxRedirects) {
    const result = await new Promise<{ statusCode: number; headers: Record<string, string | string[]>; location?: string }>((resolve, reject) => {
      const lib = currentUrl.protocol === "https:" ? https : http;
      const req = lib.request(
        {
          hostname: currentUrl.hostname,
          port: currentUrl.port || (currentUrl.protocol === "https:" ? 443 : 80),
          path: currentUrl.pathname + currentUrl.search,
          method: "GET",
          timeout: 10000,
          headers: {
            "User-Agent": "SecurityAI-Scanner/1.0 (defensive security scan)",
            Accept: "*/*",
          },
          // Don't reject self-signed certs — we want to report the cert issue
          // as a finding rather than crashing the scan
          rejectUnauthorized: false,
        },
        (res) => {
          // Drain the response so the socket is freed immediately
          res.resume();
          const hdrs: Record<string, string | string[]> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (v !== undefined) hdrs[k.toLowerCase()] = v;
          }
          resolve({
            statusCode: res.statusCode ?? 0,
            headers: hdrs,
            location: res.headers.location,
          });
        }
      );
      req.on("error", reject);
      req.on("timeout", () => { req.destroy(); reject(new Error("Request timed out")); });
      req.end();
    }).catch((err: Error) => ({ statusCode: 0, headers: {}, location: undefined, _error: err.message }));

    if ("_error" in result) {
      return {
        ok: false,
        headers: {},
        finalUrl: currentUrl.href,
        redirectedToHttps: false,
        error: (result as { _error: string })._error,
      };
    }

    const { statusCode, headers, location } = result as { statusCode: number; headers: Record<string, string | string[]>; location?: string };

    // Follow redirects (301, 302, 307, 308)
    if ([301, 302, 307, 308].includes(statusCode) && location) {
      const nextUrl = new URL(location, currentUrl.href);
      if (startedOnHttp && nextUrl.protocol === "https:") {
        movedToHttps = true;
      }
      currentUrl = nextUrl;
      redirectCount++;
      continue;
    }

    return {
      ok: statusCode >= 200 && statusCode < 500,
      statusCode,
      headers,
      finalUrl: currentUrl.href,
      redirectedToHttps: movedToHttps,
    };
  }

  return {
    ok: false,
    headers: {},
    finalUrl: currentUrl.href,
    redirectedToHttps: false,
    error: "Too many redirects",
  };
}

// ─── Scoring ──────────────────────────────────────────────────────────────────

const DEDUCTIONS: Record<string, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
};

export function calculateSecurityScore(findings: WebsiteFinding[]): number {
  const total = findings.reduce((s, f) => s + (DEDUCTIONS[f.severity] ?? 0), 0);
  return Math.max(0, Math.min(100, 100 - total));
}

// ─── Report summary ───────────────────────────────────────────────────────────

export function generateReportSummary(
  scanName: string,
  score: number,
  findings: WebsiteFinding[]
): { summary: string; recommendations: string } {
  const counts = {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
  };

  let riskLevel = "Low";
  if (score < 40) riskLevel = "Critical";
  else if (score < 60) riskLevel = "High";
  else if (score < 80) riskLevel = "Medium";

  const summary =
    `Website security assessment of "${scanName}" completed with a score of ${score}/100 (${riskLevel} Risk). ` +
    `${findings.length} finding${findings.length !== 1 ? "s" : ""} detected: ` +
    `${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low. ` +
    (counts.critical > 0
      ? "Critical issues must be resolved immediately — they can be exploited without authentication. "
      : "") +
    (score >= 80
      ? "The site demonstrates good baseline security practices with minor improvements recommended."
      : "Security improvements are required. Prioritise critical and high severity items first.");

  const topFindings = findings.filter((f) => f.severity === "critical" || f.severity === "high");
  const recLines = topFindings.slice(0, 5).map((f) => `- ${f.title}: ${f.recommendation}`);
  if (recLines.length === 0) {
    recLines.push(
      "- Continue monitoring security headers as the site evolves.",
      "- Schedule a review whenever new routes or cookies are added.",
      "- Consider integrating automated header checks into your deployment pipeline."
    );
  } else {
    recLines.push(
      "- Integrate automated security header checks into your deployment pipeline.",
      "- Re-scan after applying fixes to confirm the score improves."
    );
  }

  return { summary, recommendations: recLines.join("\n") };
}

// ─── Header checks ────────────────────────────────────────────────────────────

function headerStr(headers: Record<string, string | string[]>, name: string): string | undefined {
  const val = headers[name.toLowerCase()];
  if (!val) return undefined;
  return Array.isArray(val) ? val.join(", ") : val;
}

export function analyseHeaders(
  fetchResult: FetchResult,
  scanType: "quick" | "full"
): WebsiteFinding[] {
  const findings: WebsiteFinding[] = [];
  const h = fetchResult.headers;

  // ── 1. HTTPS ────────────────────────────────────────────────────────────────
  const isHttps = fetchResult.finalUrl.startsWith("https://");
  const originalIsHttp = !isHttps && !fetchResult.redirectedToHttps;

  if (!isHttps && !fetchResult.redirectedToHttps) {
    findings.push({
      title: "Site Not Served Over HTTPS",
      description:
        "The website is served over plain HTTP. All traffic — including login forms, cookies, and API responses — is transmitted in cleartext and can be intercepted or modified by any network observer (man-in-the-middle attack).",
      severity: "critical",
      category: "weak-config",
      codeSnippet: fetchResult.finalUrl,
      recommendation:
        "Obtain a TLS certificate (free via Let's Encrypt / Certbot) and configure your server to serve all content over HTTPS. Redirect all HTTP traffic to HTTPS with a 301 redirect.",
      cweId: "CWE-319",
    });
  } else if (fetchResult.redirectedToHttps) {
    findings.push({
      title: "HTTP Redirects to HTTPS (Good)",
      description: "The site correctly redirects HTTP requests to HTTPS. This is the expected behaviour.",
      severity: "info",
      category: "weak-config",
      codeSnippet: "HTTP → HTTPS redirect observed",
      recommendation: "No action needed. Ensure the redirect is a permanent 301 (not 302) and consider adding HSTS to lock browsers into HTTPS.",
    });
  }

  // ── 2. Strict-Transport-Security (HSTS) ─────────────────────────────────────
  const hsts = headerStr(h, "strict-transport-security");
  if (!hsts && isHttps) {
    findings.push({
      title: "Missing Strict-Transport-Security (HSTS) Header",
      description:
        "HSTS is absent. Without it, browsers may silently downgrade HTTPS connections to HTTP on the first visit, leaving users vulnerable to SSL-stripping attacks even on HTTPS sites.",
      severity: "high",
      category: "missing-security-header",
      recommendation:
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n\nNginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\nExpress: use the helmet middleware.",
      cweId: "CWE-319",
    });
  } else if (hsts) {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0;
    if (maxAge < 15552000) { // less than 180 days
      findings.push({
        title: "HSTS max-age Too Short",
        description: `The Strict-Transport-Security header is present but its max-age (${maxAge}s) is below the recommended minimum of 15,552,000 seconds (180 days). Short max-age values reduce the protection window.`,
        severity: "medium",
        category: "weak-config",
        codeSnippet: hsts,
        recommendation: "Set max-age to at least 31536000 (1 year): Strict-Transport-Security: max-age=31536000; includeSubDomains",
        cweId: "CWE-319",
      });
    }
    if (!hsts.includes("includeSubDomains")) {
      findings.push({
        title: "HSTS Missing includeSubDomains",
        description: "The HSTS policy does not include the includeSubDomains directive, leaving subdomains unprotected from SSL-stripping attacks.",
        severity: "low",
        category: "missing-security-header",
        codeSnippet: hsts,
        recommendation: "Add includeSubDomains to the HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
      });
    }
  }

  // ── 3. Content-Security-Policy ───────────────────────────────────────────────
  const csp = headerStr(h, "content-security-policy");
  if (!csp) {
    findings.push({
      title: "Missing Content-Security-Policy (CSP) Header",
      description:
        "No Content-Security-Policy header is set. CSP is the primary browser-enforced defence against Cross-Site Scripting (XSS) attacks. Without it, injected scripts execute with full page privileges.",
      severity: "high",
      category: "missing-security-header",
      recommendation:
        "Start with a strict CSP and gradually loosen it:\nContent-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:\n\nUse the CSP Evaluator (csp-evaluator.withgoogle.com) to test your policy.",
      cweId: "CWE-79",
    });
  } else {
    // Check for unsafe-inline in script-src
    if (csp.includes("'unsafe-inline'") && csp.includes("script-src")) {
      findings.push({
        title: "CSP Allows unsafe-inline Scripts",
        description:
          "'unsafe-inline' in script-src allows inline <script> tags to execute, which significantly weakens XSS protection. An attacker who can inject HTML can run arbitrary JavaScript.",
        severity: "medium",
        category: "weak-config",
        codeSnippet: csp.length > 100 ? csp.substring(0, 100) + "..." : csp,
        recommendation:
          "Remove 'unsafe-inline' from script-src. Use nonces or hashes instead:\nContent-Security-Policy: script-src 'nonce-{random}'\n\nFor each <script> tag, add the same nonce: <script nonce=\"{random}\">",
        cweId: "CWE-79",
      });
    }
    // Check for wildcard
    if (csp.includes("*") && !csp.includes("'none'")) {
      findings.push({
        title: "CSP Contains Wildcard Source",
        description: "A wildcard (*) in the Content-Security-Policy allows resources to be loaded from any origin, defeating the purpose of the policy.",
        severity: "medium",
        category: "weak-config",
        codeSnippet: csp.length > 100 ? csp.substring(0, 100) + "..." : csp,
        recommendation: "Replace wildcard sources with explicit trusted domains. Use 'self' for same-origin resources.",
        cweId: "CWE-79",
      });
    }
  }

  // ── 4. X-Frame-Options ───────────────────────────────────────────────────────
  const xfo = headerStr(h, "x-frame-options");
  const cspHasFrameAncestors = csp?.includes("frame-ancestors");
  if (!xfo && !cspHasFrameAncestors) {
    findings.push({
      title: "Missing X-Frame-Options / frame-ancestors (Clickjacking)",
      description:
        "Neither X-Frame-Options nor a CSP frame-ancestors directive is set. The page can be embedded in an iframe on any external site, enabling clickjacking attacks where users are tricked into clicking hidden UI elements.",
      severity: "medium",
      category: "missing-security-header",
      recommendation:
        "Add one of:\n  X-Frame-Options: DENY\n  X-Frame-Options: SAMEORIGIN\n  Content-Security-Policy: frame-ancestors 'self'\n\nPrefer the CSP approach for modern browsers.",
      cweId: "CWE-1021",
    });
  }

  // ── 5. X-Content-Type-Options ────────────────────────────────────────────────
  const xcto = headerStr(h, "x-content-type-options");
  if (!xcto) {
    findings.push({
      title: "Missing X-Content-Type-Options Header",
      description:
        "Without X-Content-Type-Options: nosniff, browsers may attempt to MIME-sniff responses and execute content as a different type than declared (e.g., treating a text file as JavaScript).",
      severity: "low",
      category: "missing-security-header",
      recommendation: "Add: X-Content-Type-Options: nosniff\n\nThis is a one-line fix in your server or middleware configuration.",
      cweId: "CWE-116",
    });
  }

  // ── 6. Referrer-Policy ───────────────────────────────────────────────────────
  const rp = headerStr(h, "referrer-policy");
  if (!rp) {
    findings.push({
      title: "Missing Referrer-Policy Header",
      description:
        "Without a Referrer-Policy, browsers may send the full URL (including query strings with sensitive data) to third-party sites via the Referer header when users click outbound links.",
      severity: "low",
      category: "missing-security-header",
      recommendation:
        "Add: Referrer-Policy: strict-origin-when-cross-origin\n\nThis allows same-origin full URLs but only sends the origin for cross-origin requests.",
    });
  }

  // ── 7. Permissions-Policy ────────────────────────────────────────────────────
  const pp = headerStr(h, "permissions-policy");
  if (!pp) {
    findings.push({
      title: "Missing Permissions-Policy Header",
      description:
        "No Permissions-Policy header is set. This header lets you restrict which browser APIs (camera, microphone, geolocation, etc.) third-party scripts and iframes can access.",
      severity: "low",
      category: "missing-security-header",
      recommendation:
        "Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()\n\nDisable all APIs you don't use to reduce the attack surface.",
    });
  }

  // ── 8. Server version disclosure ─────────────────────────────────────────────
  const serverHeader = headerStr(h, "server");
  if (serverHeader) {
    const versionPattern = /[\d.]+/;
    if (versionPattern.test(serverHeader)) {
      findings.push({
        title: "Server Version Disclosed in Header",
        description: `The Server header reveals the web server software and version: "${serverHeader}". Attackers use this to look up known CVEs for that exact version and target unpatched vulnerabilities.`,
        severity: "low",
        category: "information-disclosure",
        codeSnippet: `Server: ${serverHeader}`,
        recommendation:
          "Configure your server to omit or genericise the Server header:\n  Nginx: server_tokens off;\n  Apache: ServerTokens Prod; ServerSignature Off\n  Express: app.disable('x-powered-by')",
        cweId: "CWE-200",
      });
    }
  }

  // ── 9. X-Powered-By disclosure ───────────────────────────────────────────────
  const poweredBy = headerStr(h, "x-powered-by");
  if (poweredBy) {
    findings.push({
      title: "X-Powered-By Header Exposes Technology Stack",
      description: `The X-Powered-By header reveals the framework or runtime: "${poweredBy}". This helps attackers fingerprint the technology stack and search for version-specific exploits.`,
      severity: "low",
      category: "information-disclosure",
      codeSnippet: `X-Powered-By: ${poweredBy}`,
      recommendation:
        "Remove this header:\n  Express: app.disable('x-powered-by')  or  use helmet()\n  PHP: expose_php = Off in php.ini",
      cweId: "CWE-200",
    });
  }

  // ── 10. CORS wildcard (full scan only) ───────────────────────────────────────
  if (scanType === "full") {
    const acao = headerStr(h, "access-control-allow-origin");
    if (acao === "*") {
      findings.push({
        title: "CORS Wildcard Policy (Access-Control-Allow-Origin: *)",
        description:
          "The server allows cross-origin requests from any domain. While acceptable for fully public APIs, this is dangerous for authenticated APIs — it lets any website make credentialed requests on behalf of your logged-in users.",
        severity: "medium",
        category: "weak-config",
        codeSnippet: "Access-Control-Allow-Origin: *",
        recommendation:
          "Restrict CORS to a specific allowlist of trusted origins:\n  Access-Control-Allow-Origin: https://yourdomain.com\n  Vary: Origin\n\nNever combine * with Access-Control-Allow-Credentials: true (browsers block this anyway).",
        cweId: "CWE-942",
      });
    }

    // ── 11. Cache-Control for sensitive pages ─────────────────────────────────
    const cacheControl = headerStr(h, "cache-control");
    if (!cacheControl || (!cacheControl.includes("no-store") && !cacheControl.includes("private"))) {
      findings.push({
        title: "No Cache-Control Policy Set",
        description:
          "No Cache-Control header is present (or it allows caching). If this page contains authenticated content, shared caches (CDNs, proxies) or browser back-button caches may serve sensitive data to the wrong user.",
        severity: "low",
        category: "missing-security-header",
        codeSnippet: cacheControl ? `Cache-Control: ${cacheControl}` : "(header absent)",
        recommendation:
          "For pages serving authenticated or sensitive content add:\n  Cache-Control: no-store, private\n\nFor public pages you can allow caching: Cache-Control: public, max-age=3600",
        cweId: "CWE-524",
      });
    }

    // ── 12. Cookie security ───────────────────────────────────────────────────
    const setCookieRaw = h["set-cookie"];
    if (setCookieRaw) {
      const cookies = Array.isArray(setCookieRaw) ? setCookieRaw : [setCookieRaw];
      for (const cookie of cookies) {
        const lower = cookie.toLowerCase();
        const name = cookie.split("=")[0] ?? "cookie";

        if (!lower.includes("httponly")) {
          findings.push({
            title: `Cookie Missing HttpOnly Flag — ${name}`,
            description:
              `The "${name}" cookie does not have the HttpOnly flag. JavaScript can read this cookie, which means an XSS attack can steal it and hijack the user's session.`,
            severity: "high",
            category: "weak-config",
            codeSnippet: cookie.length > 100 ? cookie.substring(0, 100) + "..." : cookie,
            recommendation:
              "Add HttpOnly to all session and authentication cookies:\n  Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict",
            cweId: "CWE-1004",
          });
        }
        if (!lower.includes("secure") && isHttps) {
          findings.push({
            title: `Cookie Missing Secure Flag — ${name}`,
            description:
              `The "${name}" cookie does not have the Secure flag. Even on an HTTPS site, it can be transmitted over HTTP if the user visits the HTTP version of the page, exposing it to interception.`,
            severity: "medium",
            category: "weak-config",
            codeSnippet: cookie.length > 100 ? cookie.substring(0, 100) + "..." : cookie,
            recommendation:
              "Add Secure to all cookies:\n  Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict",
            cweId: "CWE-614",
          });
        }
        if (!lower.includes("samesite")) {
          findings.push({
            title: `Cookie Missing SameSite Attribute — ${name}`,
            description:
              `The "${name}" cookie has no SameSite attribute. Without it, the cookie is sent on cross-site requests, enabling Cross-Site Request Forgery (CSRF) attacks.`,
            severity: "medium",
            category: "weak-config",
            codeSnippet: cookie.length > 100 ? cookie.substring(0, 100) + "..." : cookie,
            recommendation:
              "Add SameSite=Strict (or Lax for sites needing cross-site GET requests):\n  Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict",
            cweId: "CWE-352",
          });
        }
      }
    }
  }

  // Sort: critical → high → medium → low → info
  const ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => (ORDER[a.severity] ?? 5) - (ORDER[b.severity] ?? 5));

  return findings;
}

// ─── Main entry point ─────────────────────────────────────────────────────────

export async function scanWebsite(
  url: string,
  scanType: "quick" | "full"
): Promise<{ findings: WebsiteFinding[]; fetchResult: FetchResult }> {
  const fetchResult = await fetchHeaders(url);

  if (!fetchResult.ok && !fetchResult.headers) {
    return { findings: [], fetchResult };
  }

  const findings = analyseHeaders(fetchResult, scanType);
  return { findings, fetchResult };
}
