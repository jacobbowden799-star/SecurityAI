/**
 * SecurityAI External Website Auditor
 *
 * Performs a PASSIVE, read-only external security audit of a website.
 * Makes only normal HTTP GET requests — the same requests any browser would make.
 * Does not probe, fuzz, exploit, authenticate, or modify anything.
 *
 * Check categories:
 *  1. HTTPS / TLS validity
 *  2. Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.)
 *  3. Cookie security flags (HttpOnly, Secure, SameSite)
 *  4. Technology fingerprinting from HTTP headers
 *  5. Exposed sensitive files (.git, .env, backup files)
 *  6. Admin panel public exposure
 *  7. robots.txt sensitive path disclosure
 *  8. Error page information disclosure
 *  9. Security policy (security.txt)
 * 10. CORS wildcard policy
 * 11. Cache-control for authenticated pages
 */

import https from "https";
import http from "http";
import { URL } from "url";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface WebsiteFinding {
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  codeSnippet?: string;
  recommendation: string;
  cweId?: string;
}

export interface FetchResult {
  ok: boolean;
  statusCode?: number;
  headers: Record<string, string | string[]>;
  finalUrl: string;
  redirectedToHttps: boolean;
  error?: string;
}

interface PageResult {
  statusCode: number;
  headers: Record<string, string | string[]>;
  body: string;
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

/** Fetch headers following up to 5 redirects, recording HTTP→HTTPS transitions. */
export async function fetchHeaders(rawUrl: string, maxRedirects = 5): Promise<FetchResult> {
  let url: URL;
  try {
    const withScheme = /^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`;
    url = new URL(withScheme);
  } catch {
    return { ok: false, headers: {}, finalUrl: rawUrl, redirectedToHttps: false, error: "Invalid URL" };
  }

  let redirectCount = 0;
  const startedOnHttp = url.protocol === "http:";
  let movedToHttps = false;
  let currentUrl = url;

  while (redirectCount <= maxRedirects) {
    const result = await new Promise<{
      statusCode: number;
      headers: Record<string, string | string[]>;
      location?: string;
      _error?: string;
    }>((resolve) => {
      const lib = currentUrl.protocol === "https:" ? https : http;
      const req = lib.request(
        {
          hostname: currentUrl.hostname,
          port: currentUrl.port || (currentUrl.protocol === "https:" ? 443 : 80),
          path: currentUrl.pathname + currentUrl.search,
          method: "GET",
          timeout: 10000,
          headers: { "User-Agent": "SecurityAI-Auditor/1.0 (defensive security audit)", Accept: "*/*" },
          rejectUnauthorized: false,
        },
        (res) => {
          res.resume();
          const hdrs: Record<string, string | string[]> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (v !== undefined) hdrs[k.toLowerCase()] = v;
          }
          resolve({ statusCode: res.statusCode ?? 0, headers: hdrs, location: res.headers.location });
        }
      );
      req.on("error", (e) => resolve({ statusCode: 0, headers: {}, _error: e.message }));
      req.on("timeout", () => { req.destroy(); resolve({ statusCode: 0, headers: {}, _error: "Request timed out" }); });
      req.end();
    });

    if (result._error) {
      return { ok: false, headers: {}, finalUrl: currentUrl.href, redirectedToHttps: false, error: result._error };
    }

    if ([301, 302, 307, 308].includes(result.statusCode) && result.location) {
      const nextUrl = new URL(result.location, currentUrl.href);
      if (startedOnHttp && nextUrl.protocol === "https:") movedToHttps = true;
      currentUrl = nextUrl;
      redirectCount++;
      continue;
    }

    return {
      ok: result.statusCode >= 200 && result.statusCode < 500,
      statusCode: result.statusCode,
      headers: result.headers,
      finalUrl: currentUrl.href,
      redirectedToHttps: movedToHttps,
    };
  }

  return { ok: false, headers: {}, finalUrl: currentUrl.href, redirectedToHttps: false, error: "Too many redirects" };
}

/** Fetch a specific path on the base URL and return status + first 10KB of body. */
async function fetchPage(baseUrl: string, path: string, timeoutMs = 8000): Promise<PageResult | null> {
  let url: URL;
  try {
    const base = /^https?:\/\//i.test(baseUrl) ? baseUrl : `https://${baseUrl}`;
    url = new URL(path, base);
  } catch {
    return null;
  }

  return new Promise<PageResult | null>((resolve) => {
    const lib = url.protocol === "https:" ? https : http;
    const req = lib.request(
      {
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: url.pathname + url.search,
        method: "GET",
        timeout: timeoutMs,
        headers: { "User-Agent": "SecurityAI-Auditor/1.0 (defensive security audit)", Accept: "*/*" },
        rejectUnauthorized: false,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let bytes = 0;
        res.on("data", (chunk: Buffer) => {
          if (bytes < 12000) { chunks.push(chunk); bytes += chunk.length; }
        });
        res.on("end", () => {
          const hdrs: Record<string, string | string[]> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (v !== undefined) hdrs[k.toLowerCase()] = v;
          }
          resolve({
            statusCode: res.statusCode ?? 0,
            headers: hdrs,
            body: Buffer.concat(chunks).toString("utf8").slice(0, 12000),
          });
        });
        res.on("error", () => resolve(null));
      }
    );
    req.on("error", () => resolve(null));
    req.on("timeout", () => { req.destroy(); resolve(null); });
    req.end();
  });
}

/** Check whether the TLS certificate is valid (separate request with strict verification). */
async function checkSslCert(rawUrl: string): Promise<WebsiteFinding[]> {
  const findings: WebsiteFinding[] = [];
  let url: URL;
  try {
    url = new URL(/^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`);
  } catch { return findings; }

  if (url.protocol !== "https:") return findings; // only relevant for HTTPS

  const certError = await new Promise<string | null>((resolve) => {
    const req = https.request(
      {
        hostname: url.hostname,
        port: url.port || 443,
        path: "/",
        method: "HEAD",
        timeout: 8000,
        rejectUnauthorized: true, // strict — will throw on bad cert
        headers: { "User-Agent": "SecurityAI-Auditor/1.0" },
      },
      () => resolve(null)
    );
    req.on("error", (e: NodeJS.ErrnoException) => resolve(e.code ?? e.message));
    req.on("timeout", () => { req.destroy(); resolve(null); });
    req.end();
  });

  if (certError) {
    if (certError === "CERT_HAS_EXPIRED") {
      findings.push({
        title: "TLS Certificate Has Expired",
        description:
          "The site's TLS/SSL certificate has expired. Browsers will display a full-page security warning to every visitor, causing them to abandon the site. Expired certificates also mean traffic is no longer guaranteed to be encrypted correctly.",
        severity: "critical",
        category: "tls-certificate",
        recommendation:
          "Renew the TLS certificate immediately. If using Let's Encrypt, run: certbot renew\nSet up automatic renewal to prevent this in future: certbot renew --dry-run",
        cweId: "CWE-298",
      });
    } else if (certError === "DEPTH_ZERO_SELF_SIGNED_CERT" || certError === "SELF_SIGNED_CERT_IN_CHAIN") {
      findings.push({
        title: "Self-Signed TLS Certificate Detected",
        description:
          "The site is using a self-signed TLS certificate. Browsers display a security warning to all visitors and the connection is not trusted by any public Certificate Authority. This is unsuitable for production sites.",
        severity: "critical",
        category: "tls-certificate",
        codeSnippet: `Error: ${certError}`,
        recommendation:
          "Replace the self-signed certificate with one from a trusted CA. Let's Encrypt provides free certificates:\ncertbot --nginx -d yourdomain.com\n\nOr use your hosting provider's SSL provisioning.",
        cweId: "CWE-295",
      });
    } else if (certError === "CERT_NOT_YET_VALID") {
      findings.push({
        title: "TLS Certificate Not Yet Valid",
        description:
          "The certificate's validity period has not started yet. This will cause browser security warnings for all visitors.",
        severity: "high",
        category: "tls-certificate",
        recommendation: "Check the certificate issuance date. If recently provisioned, wait a few minutes for DNS propagation. If incorrect, re-issue the certificate.",
        cweId: "CWE-298",
      });
    } else if (certError.includes("HOSTNAME") || certError === "ERR_TLS_CERT_ALTNAME_INVALID") {
      findings.push({
        title: "TLS Certificate Hostname Mismatch",
        description:
          `The certificate is not valid for this domain (${url.hostname}). Browsers will block access with a security error. This often happens when a certificate issued for 'example.com' is used on 'www.example.com' or vice versa.`,
        severity: "critical",
        category: "tls-certificate",
        recommendation:
          "Obtain a certificate that covers this exact domain (including www if applicable). Use a wildcard cert (*.yourdomain.com) to cover all subdomains.",
        cweId: "CWE-297",
      });
    }
  }

  return findings;
}

// ─── Technology fingerprinting ────────────────────────────────────────────────

interface DetectedTech {
  name: string;
  version?: string;
  category: string;
  riskNote: string;
}

function extractTechStack(headers: Record<string, string | string[]>, body?: string): DetectedTech[] {
  const detected: DetectedTech[] = [];
  const h = (name: string) => {
    const v = headers[name.toLowerCase()];
    return v ? (Array.isArray(v) ? v.join(", ") : v) : undefined;
  };

  const server = h("server");
  if (server) {
    const versionMatch = server.match(/([\w\-./]+)\/([\d.]+)/);
    if (versionMatch) {
      detected.push({ name: versionMatch[1], version: versionMatch[2], category: "Web Server", riskNote: "Version number disclosed — attackers can look up CVEs for this exact version." });
    } else {
      detected.push({ name: server, category: "Web Server", riskNote: "Web server software disclosed." });
    }
  }

  const poweredBy = h("x-powered-by");
  if (poweredBy) {
    const versionMatch = poweredBy.match(/([\w\-./]+)(?:\/([\d.]+))?/);
    detected.push({
      name: versionMatch?.[1] ?? poweredBy,
      version: versionMatch?.[2],
      category: "Framework / Runtime",
      riskNote: "Framework version disclosed — known vulnerabilities in this version can be targeted directly.",
    });
  }

  const via = h("via");
  if (via) {
    detected.push({ name: via, category: "Proxy / CDN", riskNote: "Infrastructure details visible — minor disclosure risk." });
  }

  if (h("cf-ray")) {
    detected.push({ name: "Cloudflare", category: "CDN / WAF", riskNote: "Cloudflare detected — generally a positive security indicator (DDoS protection, WAF)." });
  }
  if (h("x-served-by") || h("x-fastly-request-id")) {
    detected.push({ name: "Fastly", category: "CDN", riskNote: "CDN infrastructure disclosed." });
  }
  if (h("x-amz-request-id") || h("x-amz-id-2")) {
    detected.push({ name: "Amazon AWS / S3", category: "Cloud Infrastructure", riskNote: "AWS S3 or CloudFront identified — ensure bucket permissions are not public-read." });
  }

  const generator = h("x-generator");
  if (generator) {
    detected.push({ name: generator, category: "CMS", riskNote: "CMS platform and version disclosed — enables targeted CMS-specific attacks." });
  }
  if (h("x-drupal-cache") || h("x-drupal-dynamic-cache")) {
    detected.push({ name: "Drupal", category: "CMS", riskNote: "Drupal CMS detected — keep core and modules updated." });
  }
  if (h("x-magento-tags") || h("x-magento-cache-debug")) {
    detected.push({ name: "Magento", category: "E-commerce CMS", riskNote: "Magento detected — ensure admin URL is changed from /admin default." });
  }
  if (h("x-shopify-stage") || h("x-shopify-shop-api-call-limit")) {
    detected.push({ name: "Shopify", category: "E-commerce Platform", riskNote: "Shopify-hosted store — platform security is managed by Shopify." });
  }

  // Body-based detection
  if (body) {
    if (body.includes("wp-content") || body.includes("wp-includes") || body.includes("wp-json")) {
      if (!detected.find((t) => t.name.toLowerCase().includes("wordpress"))) {
        detected.push({ name: "WordPress", category: "CMS", riskNote: "WordPress detected from page source — keep core, plugins, and themes updated. Change default admin URL." });
      }
    }
    if (body.includes("Joomla") || body.includes("/components/com_")) {
      detected.push({ name: "Joomla", category: "CMS", riskNote: "Joomla CMS detected — ensure extensions are updated and admin panel is not publicly exposed." });
    }
    if (body.match(/react(?:\.development|\.production|dom)/i) || body.includes("__NEXT_DATA__")) {
      detected.push({ name: body.includes("__NEXT_DATA__") ? "Next.js" : "React", category: "JavaScript Framework", riskNote: "Framework detected from source — minor disclosure, but check for exposed source maps." });
    }
    if (body.includes("ng-version=") || body.includes("angular")) {
      detected.push({ name: "Angular", category: "JavaScript Framework", riskNote: "Framework detected from source." });
    }
  }

  // Deduplicate
  return detected.filter((t, i, arr) => arr.findIndex((x) => x.name === t.name) === i);
}

function checkTechFingerprint(headers: Record<string, string | string[]>, body?: string): WebsiteFinding[] {
  const techs = extractTechStack(headers, body);
  if (techs.length === 0) return [];

  const disclosingTechs = techs.filter((t) => t.riskNote.includes("disclosed") || t.riskNote.includes("Disclosed") || t.riskNote.includes("detected") || t.riskNote.includes("Detected") || t.riskNote.includes("identified"));

  const findings: WebsiteFinding[] = [];

  if (disclosingTechs.length > 0) {
    const stackList = disclosingTechs
      .map((t) => `• ${t.name}${t.version ? ` ${t.version}` : ""} (${t.category})`)
      .join("\n");

    findings.push({
      title: "Technology Stack Fingerprinted",
      description:
        `The following technologies were identified from HTTP response headers and/or page source:\n\n${stackList}\n\nTechnology fingerprinting allows attackers to look up known CVEs, default credentials, and attack techniques specific to these versions.`,
      severity: "low",
      category: "technology-disclosure",
      codeSnippet: disclosingTechs.map((t) => `${t.category}: ${t.name}${t.version ? ` ${t.version}` : ""}`).join(" | "),
      recommendation:
        "Minimise technology disclosure:\n" +
        "  • Nginx: server_tokens off;\n" +
        "  • Apache: ServerTokens Prod; ServerSignature Off\n" +
        "  • Express: app.disable('x-powered-by') or use helmet()\n" +
        "  • WordPress: Remove version from meta generator tag\n" +
        "  • Disable source maps in production builds",
      cweId: "CWE-200",
    });
  }

  // WordPress-specific additional warning
  if (techs.find((t) => t.name === "WordPress")) {
    findings.push({
      title: "WordPress Detected — Check Plugin Security",
      description:
        "WordPress is one of the most targeted CMS platforms due to its widespread use. Outdated plugins and themes are the #1 cause of WordPress compromises. The default login URL (/wp-login.php) is routinely brute-forced.",
      severity: "medium",
      category: "technology-disclosure",
      recommendation:
        "1. Keep WordPress core, all plugins, and themes updated (enable auto-updates).\n" +
        "2. Change the admin login URL using a plugin like WPS Hide Login.\n" +
        "3. Enable two-factor authentication for all admin accounts.\n" +
        "4. Use a Web Application Firewall (Cloudflare, Wordfence, or Sucuri).\n" +
        "5. Remove inactive plugins and themes.",
    });
  }

  return findings;
}

// ─── Exposed sensitive files ──────────────────────────────────────────────────

const SENSITIVE_FILES: Array<{
  path: string;
  name: string;
  severity: "critical" | "high" | "medium";
  description: string;
  recommendation: string;
  cweId?: string;
  bodySignature?: string; // if present, only flag if body contains this string
}> = [
  {
    path: "/.git/HEAD",
    name: "Git Repository Exposed",
    severity: "critical",
    bodySignature: "ref:",
    description:
      "The .git directory is publicly accessible. An attacker can download your entire source code history using tools like git-dumper, including all historical commits. This often exposes:\n• Hardcoded API keys, passwords, and secrets from past commits\n• Application logic and internal architecture\n• Private internal URLs and infrastructure details",
    recommendation:
      "Block access to .git immediately:\n  Nginx: location ~ /\\.git { deny all; return 404; }\n  Apache: RedirectMatch 404 /\\.git\n\nVerify no secrets were ever committed. If they were, rotate ALL credentials immediately even after blocking.",
    cweId: "CWE-538",
  },
  {
    path: "/.env",
    name: "Environment File (.env) Exposed",
    severity: "critical",
    description:
      ".env files contain sensitive configuration: database credentials, API keys, secret tokens, and service passwords. Public exposure of this file gives attackers full access to all connected services.",
    recommendation:
      "Block access to .env files immediately:\n  Nginx: location ~ /\\.env { deny all; return 404; }\n  Apache: <Files .env> Require all denied </Files>\n\nRotate ALL credentials found in the file. Check that .env is listed in .gitignore.",
    cweId: "CWE-538",
  },
  {
    path: "/.env.local",
    name: "Environment File (.env.local) Exposed",
    severity: "critical",
    description: "A local environment override file is publicly accessible. These files typically contain development or production secrets.",
    recommendation: "Block access to all .env* files at the web server level and rotate any exposed credentials immediately.",
    cweId: "CWE-538",
  },
  {
    path: "/config.php",
    name: "PHP Configuration File Exposed",
    severity: "high",
    bodySignature: "<?php",
    description: "A PHP configuration file is accessible. These often contain database credentials, salts, API keys, and other sensitive configuration.",
    recommendation: "Move configuration files outside the web root, or block access via server configuration. Rotate any exposed credentials.",
    cweId: "CWE-538",
  },
  {
    path: "/wp-config.php",
    name: "WordPress Configuration File Exposed",
    severity: "critical",
    description: "The WordPress wp-config.php file, which contains database credentials and secret keys, is publicly accessible. This gives complete access to your WordPress database.",
    recommendation: "Restrict access immediately:\n  Nginx: location = /wp-config.php { deny all; }\nConsider moving wp-config.php one level above the web root. Rotate database credentials and WordPress secret keys.",
    cweId: "CWE-538",
  },
  {
    path: "/.DS_Store",
    name: "macOS Directory Listing File (.DS_Store) Exposed",
    severity: "medium",
    description: ".DS_Store files are created by macOS Finder and contain directory structure metadata. Attackers can use them to reconstruct your website's directory tree and discover hidden files or directories.",
    recommendation: "Block access:\n  Nginx: location = /.DS_Store { deny all; }\nAdd .DS_Store to .gitignore to prevent accidental commits.",
    cweId: "CWE-200",
  },
  {
    path: "/backup.zip",
    name: "Backup Archive May Be Exposed",
    severity: "high",
    description: "A file named backup.zip was found. Publicly accessible backup archives often contain full application source code and database dumps.",
    recommendation: "Remove backup files from the web root immediately. Store backups outside the web-accessible directory or use a secure backup service.",
    cweId: "CWE-538",
  },
];

async function checkExposedSensitiveFiles(baseUrl: string): Promise<WebsiteFinding[]> {
  const findings: WebsiteFinding[] = [];

  const results = await Promise.all(
    SENSITIVE_FILES.map(async (file) => {
      const page = await fetchPage(baseUrl, file.path, 6000);
      if (!page) return null;
      if (page.statusCode !== 200) return null;
      // If body signature required, check it
      if (file.bodySignature && !page.body.includes(file.bodySignature)) return null;
      // Skip if it looks like a redirect / error page in disguise
      if (page.body.toLowerCase().includes("404 not found") || page.body.toLowerCase().includes("not found")) return null;
      return file;
    })
  );

  for (const file of results) {
    if (!file) continue;
    findings.push({
      title: file.name,
      description: file.description,
      severity: file.severity,
      category: "exposed-file",
      codeSnippet: `GET ${file.path} → 200 OK`,
      recommendation: file.recommendation,
      cweId: file.cweId,
    });
  }

  return findings;
}

// ─── Admin panel exposure ─────────────────────────────────────────────────────

const ADMIN_PATHS: Array<{ path: string; name: string }> = [
  { path: "/wp-login.php",    name: "WordPress Login" },
  { path: "/wp-admin/",       name: "WordPress Admin Dashboard" },
  { path: "/admin/",          name: "Admin Panel" },
  { path: "/administrator/",  name: "Joomla Admin Panel" },
  { path: "/phpmyadmin/",     name: "phpMyAdmin" },
  { path: "/pma/",            name: "phpMyAdmin (alternate path)" },
  { path: "/_cpanel/",        name: "cPanel" },
  { path: "/webmail/",        name: "Webmail Interface" },
  { path: "/adminer.php",     name: "Adminer Database Manager" },
  { path: "/laravel-admin/",  name: "Laravel Admin" },
];

async function checkAdminPanels(baseUrl: string): Promise<WebsiteFinding[]> {
  const findings: WebsiteFinding[] = [];

  const results = await Promise.all(
    ADMIN_PATHS.map(async ({ path, name }) => {
      const page = await fetchPage(baseUrl, path, 6000);
      if (!page) return null;
      // Only flag if truly accessible (200) — 401/403/302-to-login are expected
      if (page.statusCode !== 200) return null;
      return { path, name };
    })
  );

  for (const r of results) {
    if (!r) continue;
    findings.push({
      title: `${r.name} Publicly Accessible`,
      description:
        `${r.name} at \`${r.path}\` returns HTTP 200 — it is reachable by anyone on the internet without any prior authentication prompt. Publicly exposed admin interfaces are prime targets for automated credential-stuffing and brute-force attacks.`,
      severity: "high",
      category: "admin-exposure",
      codeSnippet: `GET ${r.path} → 200 OK`,
      recommendation:
        `Restrict access to ${r.name}:\n` +
        `  • Move it to a non-default URL\n` +
        `  • Restrict by IP allowlist at the server/firewall level\n` +
        `  • Enable two-factor authentication\n` +
        `  • Add rate limiting on login attempts`,
      cweId: "CWE-284",
    });
  }

  return findings;
}

// ─── robots.txt analysis ──────────────────────────────────────────────────────

const SENSITIVE_ROBOTS_PATHS = [
  "/admin", "/administrator", "/backend", "/dashboard", "/api", "/private",
  "/config", "/backup", "/database", "/db", "/dev", "/test", "/staging",
  "/internal", "/secret", "/hidden", "/phpMyAdmin", "/wp-admin", "/.git",
];

async function checkRobotsTxt(baseUrl: string): Promise<WebsiteFinding[]> {
  const findings: WebsiteFinding[] = [];
  const page = await fetchPage(baseUrl, "/robots.txt", 6000);
  if (!page || page.statusCode !== 200) return findings;

  const body = page.body;
  if (!body.includes("Disallow:") && !body.includes("Allow:")) return findings;

  // Good: robots.txt exists
  findings.push({
    title: "robots.txt Is Present",
    description:
      "The site has a robots.txt file. This is good practice for SEO, but its contents can inadvertently map out sensitive or private areas of your site to attackers — regardless of the Disallow directive (robots.txt is public and not a security mechanism).",
    severity: "info",
    category: "information-disclosure",
    codeSnippet: body.slice(0, 300),
    recommendation:
      "robots.txt is a hint to search engines, not a security control. Do not rely on it to protect sensitive URLs. Ensure any paths listed in robots.txt are protected by authentication at the application level.",
  });

  // Check for sensitive paths disclosed
  const disallowedPaths: string[] = [];
  for (const line of body.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.startsWith("Disallow:") || trimmed.startsWith("Allow:")) {
      const path = trimmed.split(":")[1]?.trim() ?? "";
      if (path && SENSITIVE_ROBOTS_PATHS.some((s) => path.toLowerCase().includes(s.toLowerCase()))) {
        disallowedPaths.push(path);
      }
    }
  }

  if (disallowedPaths.length > 0) {
    findings.push({
      title: "robots.txt Discloses Sensitive Paths",
      description:
        `robots.txt lists the following paths, which appear to be internal or sensitive areas:\n\n${disallowedPaths.map((p) => `  ${p}`).join("\n")}\n\nWhile Disallow tells search engine crawlers to skip these paths, it also tells attackers exactly where to look. robots.txt is world-readable.`,
      severity: "medium",
      category: "information-disclosure",
      codeSnippet: disallowedPaths.join(", "),
      recommendation:
        "Remove sensitive paths from robots.txt, or accept that their existence is public knowledge. Ensure all sensitive paths require authentication — do not rely on security through obscurity.",
      cweId: "CWE-200",
    });
  }

  return findings;
}

// ─── Error page disclosure ────────────────────────────────────────────────────

const STACK_TRACE_SIGNATURES = [
  "at Object.",
  "at Function.",
  "stack trace",
  "Traceback (most recent call last)",
  "at line ",
  "SQL syntax",
  "mysql_fetch",
  "ORA-",
  "Microsoft OLE DB",
  "ODBC SQL Server Driver",
  "Warning: include(",
  "Fatal error:",
  "Parse error:",
  "undefined method",
  "ActionView::Template::Error",
  "ActiveRecord::",
];

async function checkErrorDisclosure(baseUrl: string): Promise<WebsiteFinding[]> {
  const findings: WebsiteFinding[] = [];

  // Request a path that almost certainly doesn't exist
  const page = await fetchPage(baseUrl, `/__securityai_probe_${Date.now()}__`, 6000);
  if (!page) return findings;

  const body = page.body.toLowerCase();
  const detectedSignatures = STACK_TRACE_SIGNATURES.filter((sig) => body.includes(sig.toLowerCase()));

  if (detectedSignatures.length > 0) {
    findings.push({
      title: "Error Page Leaks Stack Trace / Debugging Information",
      description:
        "The site's error page (404/500) returns stack traces or detailed debugging information. This reveals internal file paths, function names, framework versions, and sometimes database query structure — all of which help attackers plan targeted exploits.",
      severity: "medium",
      category: "information-disclosure",
      codeSnippet: `Signatures found: ${detectedSignatures.slice(0, 3).join(", ")}`,
      recommendation:
        "Disable detailed error output in production:\n" +
        "  • Node.js/Express: use an error handler that returns generic 500 responses in production\n" +
        "  • PHP: display_errors = Off in php.ini; log_errors = On\n" +
        "  • Python/Django: DEBUG = False in settings.py\n" +
        "  • Ruby/Rails: config.consider_all_requests_local = false\n\n" +
        "Log errors server-side for debugging, but never expose them to end users.",
      cweId: "CWE-209",
    });
  }

  return findings;
}

// ─── Security.txt ─────────────────────────────────────────────────────────────

async function checkSecurityTxt(baseUrl: string): Promise<WebsiteFinding[]> {
  const findings: WebsiteFinding[] = [];

  const [wellKnown, root] = await Promise.all([
    fetchPage(baseUrl, "/.well-known/security.txt", 5000),
    fetchPage(baseUrl, "/security.txt", 5000),
  ]);

  const found =
    (wellKnown?.statusCode === 200 && wellKnown.body.includes("Contact:")) ||
    (root?.statusCode === 200 && root.body.includes("Contact:"));

  if (!found) {
    findings.push({
      title: "No security.txt Policy Found",
      description:
        "The site does not have a security.txt file (RFC 9116). Security researchers who discover vulnerabilities have no clear channel to disclose them responsibly, which may result in vulnerabilities being sold or disclosed publicly rather than being reported to you.",
      severity: "info",
      category: "missing-security-header",
      recommendation:
        "Create /.well-known/security.txt with:\n\n" +
        "  Contact: mailto:security@yourdomain.com\n" +
        "  Expires: 2026-12-31T00:00:00.000Z\n" +
        "  Preferred-Languages: en\n\n" +
        "Use the generator at securitytxt.org to build your policy.",
    });
  } else {
    findings.push({
      title: "security.txt Policy Is Present",
      description: "A security.txt file was found. This is good practice — it gives security researchers a clear responsible disclosure channel.",
      severity: "info",
      category: "missing-security-header",
      recommendation: "Keep the Expires date current and ensure the Contact address is monitored. Consider adding a PGP key for encrypted reports.",
    });
  }

  return findings;
}

// ─── Header checks (existing, cleaned up) ────────────────────────────────────

function hStr(headers: Record<string, string | string[]>, name: string): string | undefined {
  const val = headers[name.toLowerCase()];
  if (!val) return undefined;
  return Array.isArray(val) ? val.join(", ") : val;
}

export function analyseHeaders(fetchResult: FetchResult, scanType: "quick" | "full"): WebsiteFinding[] {
  const findings: WebsiteFinding[] = [];
  const h = fetchResult.headers;
  const isHttps = fetchResult.finalUrl.startsWith("https://");

  // 1. HTTPS enforcement
  if (!isHttps && !fetchResult.redirectedToHttps) {
    findings.push({
      title: "Site Not Served Over HTTPS",
      description: "The website is served over plain HTTP. All traffic — including login forms, cookies, and API responses — is transmitted in cleartext and can be intercepted or modified by any network observer (man-in-the-middle).",
      severity: "critical",
      category: "tls-certificate",
      codeSnippet: fetchResult.finalUrl,
      recommendation: "Obtain a TLS certificate (free via Let's Encrypt) and configure your server to serve content over HTTPS. Redirect all HTTP to HTTPS with a 301 redirect and add HSTS.",
      cweId: "CWE-319",
    });
  } else if (fetchResult.redirectedToHttps) {
    findings.push({
      title: "HTTP Correctly Redirects to HTTPS",
      description: "HTTP requests are redirected to HTTPS as expected.",
      severity: "info",
      category: "tls-certificate",
      recommendation: "Ensure the redirect is a permanent 301 (not 302) and add an HSTS header to lock browsers into HTTPS.",
    });
  }

  // 2. HSTS
  const hsts = hStr(h, "strict-transport-security");
  if (!hsts && isHttps) {
    findings.push({
      title: "Missing Strict-Transport-Security (HSTS) Header",
      description: "HSTS is absent. Without it, browsers may silently downgrade HTTPS connections to HTTP on first visit, leaving users vulnerable to SSL-stripping attacks.",
      severity: "high",
      category: "missing-security-header",
      recommendation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n\nNginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\nExpress: use helmet()",
      cweId: "CWE-319",
    });
  } else if (hsts) {
    const maxAge = parseInt(hsts.match(/max-age=(\d+)/i)?.[1] ?? "0");
    if (maxAge < 15552000) {
      findings.push({
        title: "HSTS max-age Too Short",
        description: `The HSTS max-age (${maxAge}s) is below the recommended 180 days (15,552,000s). Reducing the protection window makes SSL-stripping attacks more feasible between visits.`,
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
        description: "The HSTS policy does not include includeSubDomains, leaving subdomains unprotected from SSL-stripping.",
        severity: "low",
        category: "weak-config",
        codeSnippet: hsts,
        recommendation: "Add includeSubDomains: Strict-Transport-Security: max-age=31536000; includeSubDomains",
      });
    }
  }

  // 3. CSP
  const csp = hStr(h, "content-security-policy");
  if (!csp) {
    findings.push({
      title: "Missing Content-Security-Policy (CSP) Header",
      description: "No CSP header is set. CSP is the primary browser-enforced defence against Cross-Site Scripting (XSS). Without it, injected scripts execute with full page privileges.",
      severity: "high",
      category: "missing-security-header",
      recommendation: "Start with a strict CSP:\nContent-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:\n\nUse csp-evaluator.withgoogle.com to test your policy.",
      cweId: "CWE-79",
    });
  } else {
    if (csp.includes("'unsafe-inline'") && csp.match(/script-src[^;]*'unsafe-inline'/)) {
      findings.push({
        title: "CSP Allows unsafe-inline Scripts",
        description: "'unsafe-inline' in script-src allows inline <script> tags to execute, which significantly weakens XSS protection.",
        severity: "medium",
        category: "weak-config",
        codeSnippet: csp.length > 120 ? csp.substring(0, 120) + "…" : csp,
        recommendation: "Remove 'unsafe-inline' from script-src. Use nonces or hashes:\nContent-Security-Policy: script-src 'nonce-{random}'\n<script nonce=\"{random}\">",
        cweId: "CWE-79",
      });
    }
    if (csp.includes("'unsafe-eval'")) {
      findings.push({
        title: "CSP Allows unsafe-eval",
        description: "'unsafe-eval' permits eval() and similar dynamic code execution, creating Remote Code Execution risk if any user data can influence these calls.",
        severity: "medium",
        category: "weak-config",
        codeSnippet: csp.length > 120 ? csp.substring(0, 120) + "…" : csp,
        recommendation: "Remove 'unsafe-eval'. Refactor any code using eval(), new Function(), or setTimeout with strings.",
        cweId: "CWE-95",
      });
    }
  }

  // 4. X-Frame-Options
  const xfo = hStr(h, "x-frame-options");
  const cspHasFrameAncestors = csp?.includes("frame-ancestors");
  if (!xfo && !cspHasFrameAncestors) {
    findings.push({
      title: "Missing Clickjacking Protection (X-Frame-Options)",
      description: "Neither X-Frame-Options nor CSP frame-ancestors is set. The page can be embedded in an iframe on any external site, enabling clickjacking attacks where users are tricked into clicking hidden UI elements.",
      severity: "medium",
      category: "missing-security-header",
      recommendation: "Add: X-Frame-Options: DENY\nor: Content-Security-Policy: frame-ancestors 'self'\n\nPrefer the CSP approach for modern browsers.",
      cweId: "CWE-1021",
    });
  }

  // 5. X-Content-Type-Options
  if (!hStr(h, "x-content-type-options")) {
    findings.push({
      title: "Missing X-Content-Type-Options Header",
      description: "Without nosniff, browsers may MIME-sniff responses and execute content as a different type than declared (e.g., treating a text file as JavaScript).",
      severity: "low",
      category: "missing-security-header",
      recommendation: "Add: X-Content-Type-Options: nosniff",
      cweId: "CWE-116",
    });
  }

  // 6. Referrer-Policy
  if (!hStr(h, "referrer-policy")) {
    findings.push({
      title: "Missing Referrer-Policy Header",
      description: "Without a Referrer-Policy, browsers may send the full URL (including query strings with tokens or IDs) to third-party sites via the Referer header.",
      severity: "low",
      category: "missing-security-header",
      recommendation: "Add: Referrer-Policy: strict-origin-when-cross-origin",
    });
  }

  // 7. Permissions-Policy
  if (!hStr(h, "permissions-policy")) {
    findings.push({
      title: "Missing Permissions-Policy Header",
      description: "No Permissions-Policy restricts which browser APIs (camera, microphone, geolocation) third-party scripts and iframes can access.",
      severity: "low",
      category: "missing-security-header",
      recommendation: "Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
    });
  }

  // 8. Server disclosure
  const server = hStr(h, "server");
  if (server && /[\d.]/.test(server)) {
    findings.push({
      title: "Server Version Disclosed",
      description: `The Server header reveals the exact web server version: "${server}". Attackers use this to look up CVEs for that specific version.`,
      severity: "low",
      category: "technology-disclosure",
      codeSnippet: `Server: ${server}`,
      recommendation: "Nginx: server_tokens off;\nApache: ServerTokens Prod; ServerSignature Off",
      cweId: "CWE-200",
    });
  }

  // 9. X-Powered-By
  const poweredBy = hStr(h, "x-powered-by");
  if (poweredBy) {
    findings.push({
      title: "X-Powered-By Header Exposes Framework",
      description: `X-Powered-By reveals the server-side framework or runtime: "${poweredBy}". Helps attackers fingerprint and target version-specific exploits.`,
      severity: "low",
      category: "technology-disclosure",
      codeSnippet: `X-Powered-By: ${poweredBy}`,
      recommendation: "Express: app.disable('x-powered-by') or use helmet()\nPHP: expose_php = Off in php.ini",
      cweId: "CWE-200",
    });
  }

  // Full-scan-only checks
  if (scanType === "full") {
    // CORS
    const acao = hStr(h, "access-control-allow-origin");
    if (acao === "*") {
      findings.push({
        title: "CORS Wildcard Policy (Access-Control-Allow-Origin: *)",
        description: "The server allows cross-origin requests from any domain. This is dangerous for authenticated APIs — any website can make requests on behalf of your logged-in users.",
        severity: "medium",
        category: "weak-config",
        codeSnippet: "Access-Control-Allow-Origin: *",
        recommendation: "Restrict CORS to trusted origins:\nAccess-Control-Allow-Origin: https://yourdomain.com\nVary: Origin\n\nNever combine * with Access-Control-Allow-Credentials: true.",
        cweId: "CWE-942",
      });
    }

    // Cache-Control
    const cacheControl = hStr(h, "cache-control");
    if (!cacheControl || (!cacheControl.includes("no-store") && !cacheControl.includes("private"))) {
      findings.push({
        title: "No Cache-Control Policy Set",
        description: "No Cache-Control header (or it allows caching). Shared caches or browser back-button caches may serve authenticated content to the wrong user.",
        severity: "low",
        category: "missing-security-header",
        codeSnippet: cacheControl ? `Cache-Control: ${cacheControl}` : "(header absent)",
        recommendation: "For authenticated pages: Cache-Control: no-store, private\nFor public pages: Cache-Control: public, max-age=3600",
        cweId: "CWE-524",
      });
    }

    // Cookie security
    const setCookieRaw = h["set-cookie"];
    if (setCookieRaw) {
      const cookies = Array.isArray(setCookieRaw) ? setCookieRaw : [setCookieRaw];
      for (const cookie of cookies) {
        const lower = cookie.toLowerCase();
        const name = cookie.split("=")[0] ?? "cookie";
        if (!lower.includes("httponly")) {
          findings.push({
            title: `Cookie Missing HttpOnly — ${name}`,
            description: `The "${name}" cookie lacks HttpOnly. JavaScript can read it — an XSS attack can steal it and hijack the session.`,
            severity: "high",
            category: "cookie-security",
            codeSnippet: cookie.length > 100 ? cookie.substring(0, 100) + "…" : cookie,
            recommendation: `Set-Cookie: ${name}=...; HttpOnly; Secure; SameSite=Strict`,
            cweId: "CWE-1004",
          });
        }
        if (!lower.includes("secure") && isHttps) {
          findings.push({
            title: `Cookie Missing Secure Flag — ${name}`,
            description: `"${name}" lacks the Secure flag. Even on HTTPS, it can be transmitted over HTTP if the HTTP version is visited.`,
            severity: "medium",
            category: "cookie-security",
            codeSnippet: cookie.length > 100 ? cookie.substring(0, 100) + "…" : cookie,
            recommendation: `Set-Cookie: ${name}=...; HttpOnly; Secure; SameSite=Strict`,
            cweId: "CWE-614",
          });
        }
        if (!lower.includes("samesite")) {
          findings.push({
            title: `Cookie Missing SameSite — ${name}`,
            description: `"${name}" has no SameSite attribute, enabling Cross-Site Request Forgery (CSRF) attacks.`,
            severity: "medium",
            category: "cookie-security",
            codeSnippet: cookie.length > 100 ? cookie.substring(0, 100) + "…" : cookie,
            recommendation: `Set-Cookie: ${name}=...; HttpOnly; Secure; SameSite=Strict`,
            cweId: "CWE-352",
          });
        }
      }
    }
  }

  const ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => (ORDER[a.severity] ?? 5) - (ORDER[b.severity] ?? 5));
  return findings;
}

// ─── Scoring ──────────────────────────────────────────────────────────────────

const DEDUCTIONS: Record<string, number> = {
  critical: 25,
  high: 12,
  medium: 6,
  low: 2,
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
  findings: { title: string; severity: string; recommendation: string }[]
): { summary: string; recommendations: string } {
  const counts = {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
  };

  let riskLevel = "Low Risk";
  if (score < 40) riskLevel = "Critical Risk";
  else if (score < 60) riskLevel = "High Risk";
  else if (score < 80) riskLevel = "Medium Risk";

  const summary =
    `External security audit of "${scanName}" completed with a score of ${score}/100 (${riskLevel}). ` +
    `${findings.length} finding${findings.length !== 1 ? "s" : ""} detected: ` +
    `${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low. ` +
    (counts.critical > 0 ? "Critical issues require immediate remediation before re-audit. " : "") +
    (score >= 80
      ? "The site demonstrates good baseline security. Address remaining findings to reach a strong security posture."
      : "Significant security improvements are needed. Follow the prioritised recommendations below.");

  const topFindings = findings.filter((f) => f.severity === "critical" || f.severity === "high");
  const recLines = topFindings.slice(0, 6).map((f) => `- ${f.title}: ${f.recommendation.split("\n")[0]}`);
  if (recLines.length === 0) {
    recLines.push(
      "- Continue monitoring as the site evolves.",
      "- Schedule quarterly security audits.",
      "- Integrate automated header checks into your deployment pipeline."
    );
  } else {
    recLines.push("- Re-run the External Audit after applying fixes to verify improvements.");
  }

  return { summary, recommendations: recLines.join("\n") };
}

// ─── Main entry point ─────────────────────────────────────────────────────────

export async function scanWebsite(
  url: string,
  scanType: "quick" | "full"
): Promise<{ findings: WebsiteFinding[]; fetchResult: FetchResult }> {
  const normUrl = /^https?:\/\//i.test(url) ? url : `https://${url}`;

  // Run primary fetch + SSL check in parallel
  const [fetchResult, sslFindings] = await Promise.all([
    fetchHeaders(normUrl),
    scanType === "full" ? checkSslCert(normUrl) : Promise.resolve<WebsiteFinding[]>([]),
  ]);

  if (!fetchResult.ok && Object.keys(fetchResult.headers).length === 0) {
    return { findings: [], fetchResult };
  }

  // Fetch home page body for tech fingerprinting
  const homePage = await fetchPage(normUrl, "/", 8000);

  // Header analysis
  const headerFindings = analyseHeaders(fetchResult, scanType);

  // Tech fingerprinting (both quick and full)
  const techFindings = checkTechFingerprint(fetchResult.headers, homePage?.body);

  // Full-scan-only deep checks — run all in parallel
  let deepFindings: WebsiteFinding[] = [];
  if (scanType === "full") {
    const [exposedFiles, adminPanels, robotsTxt, errorDisclosure, securityTxt] = await Promise.all([
      checkExposedSensitiveFiles(normUrl),
      checkAdminPanels(normUrl),
      checkRobotsTxt(normUrl),
      checkErrorDisclosure(normUrl),
      checkSecurityTxt(normUrl),
    ]);
    deepFindings = [...exposedFiles, ...adminPanels, ...robotsTxt, ...errorDisclosure, ...securityTxt];
  } else {
    // Quick scan still checks security.txt
    deepFindings = await checkSecurityTxt(normUrl);
  }

  const all: WebsiteFinding[] = [...sslFindings, ...headerFindings, ...techFindings, ...deepFindings];

  // Final sort: critical → high → medium → low → info
  const ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  all.sort((a, b) => (ORDER[a.severity] ?? 5) - (ORDER[b.severity] ?? 5));

  return { findings: all, fetchResult };
}
