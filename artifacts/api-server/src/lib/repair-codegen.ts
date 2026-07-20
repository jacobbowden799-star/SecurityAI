/**
 * repair-codegen.ts
 *
 * Maps scanner findings to concrete before/after code fix templates.
 * Detects the server framework from response headers and returns
 * framework-specific snippets wherever possible (Express, Nginx, Apache, PHP).
 */

import type { WebsiteFinding, FetchResult } from "./website-scanner";

// ─── Types ────────────────────────────────────────────────────────────────────

export type Framework = "express" | "nginx" | "apache" | "php" | "django" | "generic";

export interface RepairPlan {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  category: string;
  description: string;
  file: string;
  beforeCode: string;
  afterCode: string;
  explanation: string;
  scoreGain: number;
}

// ─── Framework detection ──────────────────────────────────────────────────────

function h(headers: Record<string, string | string[]>, name: string): string {
  const v = headers[name.toLowerCase()];
  if (!v) return "";
  return Array.isArray(v) ? v.join(", ") : v;
}

export function detectFramework(fetchResult: FetchResult): Framework {
  const server    = h(fetchResult.headers, "server").toLowerCase();
  const poweredBy = h(fetchResult.headers, "x-powered-by").toLowerCase();

  if (server.includes("nginx"))  return "nginx";
  if (server.includes("apache")) return "apache";
  if (poweredBy.includes("express") || poweredBy.includes("node")) return "express";
  if (poweredBy.includes("php"))  return "php";
  if (poweredBy.includes("django") || server.includes("gunicorn") || server.includes("uvicorn")) return "django";

  // Fallback heuristics
  if (server.includes("cloudflare") || server.includes("vercel")) return "nginx"; // show nginx config
  return "express"; // most common default
}

// ─── Score gain by severity ───────────────────────────────────────────────────

const SCORE_GAIN: Record<string, number> = {
  critical: 22,
  high: 12,
  medium: 6,
  low: 2,
};

// ─── Template definitions ─────────────────────────────────────────────────────

type FixTemplate = {
  file: string;
  before: string[];
  after: string[];
  explanation: string;
};

type FrameworkFixes = Partial<Record<Framework, FixTemplate>> & { default: FixTemplate };

// ── 1. HSTS ───────────────────────────────────────────────────────────────────

const HSTS_FIXES: FrameworkFixes = {
  express: {
    file: "server.js",
    before: [
      "const express = require('express');",
      "const app = express();",
      "",
      "// No security headers configured",
      "app.get('/', (req, res) => {",
      "  res.json({ status: 'ok' });",
      "});",
      "",
      "app.listen(3000);",
    ],
    after: [
      "const express = require('express');",
      "const helmet  = require('helmet');",
      "const app = express();",
      "",
      "// helmet sets HSTS + many other security headers automatically",
      "app.use(helmet({",
      "  hsts: {",
      "    maxAge:            31536000,  // 1 year",
      "    includeSubDomains: true,",
      "    preload:           true,",
      "  },",
      "}));",
      "",
      "app.get('/', (req, res) => {",
      "  res.json({ status: 'ok' });",
      "});",
      "",
      "app.listen(3000);",
    ],
    explanation:
      "Without HSTS, a browser visiting your site on HTTP for the first time can be intercepted before it reaches HTTPS (SSL stripping). HSTS tells browsers to always use HTTPS for the next year, even before the first request. The helmet package sets this and 11 other security headers in one line.",
  },
  nginx: {
    file: "nginx.conf",
    before: [
      "server {",
      "  listen 443 ssl;",
      "  server_name example.com;",
      "",
      "  # No HSTS header configured",
      "  location / {",
      "    proxy_pass http://app:3000;",
      "  }",
      "}",
    ],
    after: [
      "server {",
      "  listen 443 ssl;",
      "  server_name example.com;",
      "",
      "  # HSTS — lock browsers into HTTPS for 1 year",
      "  add_header Strict-Transport-Security",
      "    \"max-age=31536000; includeSubDomains; preload\" always;",
      "",
      "  location / {",
      "    proxy_pass http://app:3000;",
      "  }",
      "}",
    ],
    explanation:
      "The HSTS header tells browsers to refuse HTTP connections and always use HTTPS for max-age seconds. 'always' ensures it's sent on error responses too. 'preload' qualifies you for the browser HSTS preload list, providing protection even on first visit.",
  },
  default: {
    file: "server-config",
    before: [
      "# Strict-Transport-Security header is not configured.",
      "# Browsers can be downgraded from HTTPS to HTTP on first visit.",
    ],
    after: [
      "# Add this header to all HTTPS responses:",
      "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    ],
    explanation:
      "HSTS prevents SSL-stripping attacks by telling browsers to always use HTTPS. Set max-age to at least one year and include subdomains to avoid subdomain-based downgrade attacks.",
  },
};

// ── 2. CSP ────────────────────────────────────────────────────────────────────

const CSP_FIXES: FrameworkFixes = {
  express: {
    file: "server.js",
    before: [
      "const express = require('express');",
      "const app = express();",
      "",
      "// No Content-Security-Policy configured",
      "// Injected scripts execute with full page privileges",
      "",
      "app.get('/', (req, res) => {",
      "  res.send('<html>...</html>');",
      "});",
    ],
    after: [
      "const express = require('express');",
      "const helmet  = require('helmet');",
      "const app = express();",
      "",
      "app.use(helmet.contentSecurityPolicy({",
      "  directives: {",
      "    defaultSrc: [\"'self'\"],",
      "    scriptSrc:  [\"'self'\"],          // no inline scripts",
      "    styleSrc:   [\"'self'\", \"'unsafe-inline'\"],",
      "    imgSrc:     [\"'self'\", 'data:', 'https:'],",
      "    fontSrc:    [\"'self'\", 'https:'],",
      "    connectSrc: [\"'self'\"],",
      "    frameSrc:   [\"'none'\"],",
      "    objectSrc:  [\"'none'\"],",
      "  },",
      "}));",
      "",
      "app.get('/', (req, res) => {",
      "  res.send('<html>...</html>');",
      "});",
    ],
    explanation:
      "CSP is the primary browser defence against XSS. Without it, any injected script runs with full privileges. This policy restricts scripts to same-origin only, blocks inline scripts (the main XSS vector), and denies frames entirely. Use csp-evaluator.withgoogle.com to fine-tune your policy.",
  },
  nginx: {
    file: "nginx.conf",
    before: [
      "server {",
      "  listen 443 ssl;",
      "  server_name example.com;",
      "",
      "  # No Content-Security-Policy header",
      "",
      "  location / { proxy_pass http://app:3000; }",
      "}",
    ],
    after: [
      "server {",
      "  listen 443 ssl;",
      "  server_name example.com;",
      "",
      "  add_header Content-Security-Policy",
      "    \"default-src 'self'; script-src 'self';",
      "     style-src 'self' 'unsafe-inline';",
      "     img-src 'self' data: https:;",
      "     frame-ancestors 'none';",
      "     object-src 'none'\" always;",
      "",
      "  location / { proxy_pass http://app:3000; }",
      "}",
    ],
    explanation:
      "CSP tells the browser which origins are allowed to load scripts, styles, and other resources. 'frame-ancestors: none' prevents clickjacking (replaces X-Frame-Options). Start with this strict policy and gradually allow specific trusted CDNs or font providers as needed.",
  },
  default: {
    file: "server-config",
    before: [
      "# Content-Security-Policy header is not configured.",
      "# Injected JavaScript can execute without restriction.",
    ],
    after: [
      "Content-Security-Policy: default-src 'self'; script-src 'self';",
      "  style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;",
      "  frame-ancestors 'none'; object-src 'none'",
    ],
    explanation:
      "CSP is the primary browser-enforced defence against XSS attacks. Add this header to all HTML responses and tighten the policy over time using CSP report-only mode first.",
  },
};

// ── 3. X-Frame-Options / Clickjacking ─────────────────────────────────────────

const CLICKJACKING_FIXES: FrameworkFixes = {
  express: {
    file: "server.js",
    before: [
      "const express = require('express');",
      "const app = express();",
      "",
      "// No clickjacking protection",
      "// Any site can iframe your pages",
      "",
      "app.use(express.static('public'));",
      "app.listen(3000);",
    ],
    after: [
      "const express = require('express');",
      "const helmet  = require('helmet');",
      "const app = express();",
      "",
      "// Prevent your pages from being framed by other sites",
      "app.use(helmet.frameguard({ action: 'deny' }));",
      "",
      "// Or via CSP frame-ancestors (preferred modern approach):",
      "// app.use(helmet.contentSecurityPolicy({",
      "//   directives: { frameAncestors: [\"'none'\"] }",
      "// }));",
      "",
      "app.use(express.static('public'));",
      "app.listen(3000);",
    ],
    explanation:
      "Clickjacking attacks embed your page in an invisible iframe and trick users into clicking hidden elements. The X-Frame-Options: DENY header instructs browsers to refuse to render your page inside any frame. CSP's frame-ancestors directive is the modern equivalent and should be preferred for browsers that support it.",
  },
  nginx: {
    file: "nginx.conf",
    before: [
      "server {",
      "  listen 443 ssl;",
      "  # No clickjacking protection configured",
      "  location / { proxy_pass http://app:3000; }",
      "}",
    ],
    after: [
      "server {",
      "  listen 443 ssl;",
      "  add_header X-Frame-Options     \"DENY\" always;",
      "  add_header Content-Security-Policy \"frame-ancestors 'none'\" always;",
      "  location / { proxy_pass http://app:3000; }",
      "}",
    ],
    explanation:
      "Both X-Frame-Options and CSP frame-ancestors are set for maximum compatibility. Older browsers use X-Frame-Options; modern browsers prefer the CSP directive. The 'always' flag ensures the header is sent on error responses too.",
  },
  default: {
    file: "server-config",
    before: ["# X-Frame-Options header is missing.", "# Pages can be embedded in iframes on any external site."],
    after: [
      "X-Frame-Options: DENY",
      "Content-Security-Policy: frame-ancestors 'none'",
    ],
    explanation: "Prevents your pages from being embedded in iframes by malicious sites. Both headers are set for full browser compatibility.",
  },
};

// ── 4. X-Content-Type-Options ─────────────────────────────────────────────────

const XCTO_FIXES: FrameworkFixes = {
  express: {
    file: "server.js",
    before: [
      "const express = require('express');",
      "const app = express();",
      "",
      "// MIME sniffing protection absent",
      "// Browsers may execute uploaded files as scripts",
      "",
      "app.use(express.static('uploads'));",
    ],
    after: [
      "const express = require('express');",
      "const helmet  = require('helmet');",
      "const app = express();",
      "",
      "// Prevent browsers from MIME-sniffing responses",
      "app.use(helmet.noSniff());   // sets X-Content-Type-Options: nosniff",
      "",
      "app.use(express.static('uploads'));",
    ],
    explanation:
      "Without nosniff, a browser might execute a file uploaded as 'image/jpeg' as JavaScript if its content looks like a script. This is especially dangerous for sites that serve user-uploaded content.",
  },
  nginx: {
    file: "nginx.conf",
    before: [
      "server {",
      "  listen 443 ssl;",
      "  # No X-Content-Type-Options",
      "  location / { proxy_pass http://app:3000; }",
      "}",
    ],
    after: [
      "server {",
      "  listen 443 ssl;",
      "  add_header X-Content-Type-Options \"nosniff\" always;",
      "  location / { proxy_pass http://app:3000; }",
      "}",
    ],
    explanation: "One-line change that prevents browsers from MIME-type sniffing, ensuring files are served and interpreted as their declared content type.",
  },
  default: {
    file: "server-config",
    before: ["# X-Content-Type-Options header is not set.", "# Browsers may MIME-sniff responses and execute them as wrong types."],
    after: ["X-Content-Type-Options: nosniff"],
    explanation: "Prevents browsers from guessing the content type of responses, which can lead to XSS via MIME-type confusion attacks.",
  },
};

// ── 5. Referrer-Policy ────────────────────────────────────────────────────────

const REFERRER_FIXES: FrameworkFixes = {
  express: {
    file: "server.js",
    before: [
      "const express = require('express');",
      "const app = express();",
      "",
      "// No Referrer-Policy — full URLs sent to third parties",
      "// e.g. https://yourapp.com/account?token=abc123",
      "//      leaks to every analytics script and CDN",
    ],
    after: [
      "const express = require('express');",
      "const helmet  = require('helmet');",
      "const app = express();",
      "",
      "// Only send origin (not path or query) to cross-origin requests",
      "app.use(helmet.referrerPolicy({",
      "  policy: 'strict-origin-when-cross-origin',",
      "}));",
    ],
    explanation:
      "Without Referrer-Policy, the browser sends the full URL (including query strings containing tokens, session IDs, or PII) as the Referer header to every third-party resource. 'strict-origin-when-cross-origin' sends only the origin to third parties, preserving analytics while protecting sensitive parameters.",
  },
  nginx: {
    file: "nginx.conf",
    before: [
      "server {",
      "  listen 443 ssl;",
      "  # No Referrer-Policy header",
      "  location / { proxy_pass http://app:3000; }",
      "}",
    ],
    after: [
      "server {",
      "  listen 443 ssl;",
      "  add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
      "  location / { proxy_pass http://app:3000; }",
      "}",
    ],
    explanation: "Controls how much referrer information is sent when navigating away. 'strict-origin-when-cross-origin' protects query-string parameters from leaking to third parties.",
  },
  default: {
    file: "server-config",
    before: ["# Referrer-Policy is not set.", "# Full URLs with query strings are sent to third-party servers."],
    after: ["Referrer-Policy: strict-origin-when-cross-origin"],
    explanation: "Limits the Referer header to the origin only for cross-origin requests, protecting tokens and IDs in URLs from leaking to analytics, CDNs, and external resources.",
  },
};

// ── 6. Permissions-Policy ─────────────────────────────────────────────────────

const PERMISSIONS_FIXES: FrameworkFixes = {
  express: {
    file: "server.js",
    before: [
      "const express = require('express');",
      "const app = express();",
      "",
      "// No Permissions-Policy — third-party scripts can access",
      "// camera, microphone, geolocation, and payment APIs",
    ],
    after: [
      "const express = require('express');",
      "const helmet  = require('helmet');",
      "const app = express();",
      "",
      "app.use(helmet.permittedCrossDomainPolicies());",
      "",
      "// Explicitly disable powerful features",
      "app.use((_req, res, next) => {",
      "  res.setHeader('Permissions-Policy',",
      "    'camera=(), microphone=(), geolocation=(), payment=(), usb=()',",
      "  );",
      "  next();",
      "});",
    ],
    explanation:
      "Permissions-Policy restricts which browser features (camera, microphone, geolocation, payment) can be used by the page and embedded third-party scripts. Disabling unused features reduces the attack surface — a compromised analytics script cannot exfiltrate geolocation data if the feature is denied.",
  },
  nginx: {
    file: "nginx.conf",
    before: [
      "server {",
      "  listen 443 ssl;",
      "  # No Permissions-Policy set",
      "  location / { proxy_pass http://app:3000; }",
      "}",
    ],
    after: [
      "server {",
      "  listen 443 ssl;",
      "  add_header Permissions-Policy",
      "    \"camera=(), microphone=(), geolocation=(), payment=()\" always;",
      "  location / { proxy_pass http://app:3000; }",
      "}",
    ],
    explanation: "Restricts which device APIs can be used in the browser context. () means the feature is denied to everyone including the page itself.",
  },
  default: {
    file: "server-config",
    before: ["# Permissions-Policy header is not set.", "# Third-party scripts can request camera, microphone, and geolocation access."],
    after: ["Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()"],
    explanation: "Restricts access to powerful browser APIs. Disabling unused features prevents malicious third-party scripts from accessing sensitive device hardware.",
  },
};

// ── 7. X-Powered-By removal ───────────────────────────────────────────────────

const POWERED_BY_FIXES: FrameworkFixes = {
  express: {
    file: "server.js",
    before: [
      "const express = require('express');",
      "const app = express();",
      "",
      "// Express adds X-Powered-By: Express by default",
      "// This reveals your framework to attackers",
      "",
      "app.get('/', (req, res) => res.json({ ok: true }));",
      "app.listen(3000);",
    ],
    after: [
      "const express = require('express');",
      "const helmet  = require('helmet');",
      "const app = express();",
      "",
      "// Remove X-Powered-By header entirely",
      "app.disable('x-powered-by');",
      "",
      "// Alternatively, helmet() does this automatically:",
      "// app.use(helmet());",
      "",
      "app.get('/', (req, res) => res.json({ ok: true }));",
      "app.listen(3000);",
    ],
    explanation:
      "Express automatically adds 'X-Powered-By: Express' to every response. This tells attackers your exact framework, enabling them to search for Express-specific CVEs. One line removes it. The helmet package removes it automatically along with many other security improvements.",
  },
  php: {
    file: "php.ini",
    before: [
      "; PHP exposes itself in every response",
      "; Attackers can fingerprint your PHP version",
      "",
      "[PHP]",
      "expose_php = On    ; <-- default value",
    ],
    after: [
      "; Disable PHP version disclosure in X-Powered-By header",
      "",
      "[PHP]",
      "expose_php = Off",
      "",
      "; Restart PHP-FPM after changing php.ini:",
      "; sudo systemctl restart php8.x-fpm",
    ],
    explanation:
      "PHP's expose_php=On causes every response to include 'X-Powered-By: PHP/8.x.x'. Attackers look up known CVEs for the exact PHP version. Setting expose_php=Off removes this header with zero functional impact.",
  },
  nginx: {
    file: "nginx.conf",
    before: [
      "server {",
      "  listen 443 ssl;",
      "  # Server version visible in headers and error pages",
      "  # e.g. Server: nginx/1.24.0",
      "  location / { proxy_pass http://app:3000; }",
      "}",
    ],
    after: [
      "# In the main http {} block:",
      "http {",
      "  server_tokens off;  # hides nginx version from Server header",
      "",
      "  server {",
      "    listen 443 ssl;",
      "    location / { proxy_pass http://app:3000; }",
      "  }",
      "}",
    ],
    explanation: "server_tokens off prevents Nginx from including the version number in the Server response header and error pages, reducing the fingerprinting surface attackers have to work with.",
  },
  default: {
    file: "server-config",
    before: ["# X-Powered-By or Server header reveals framework/version details.", "# Attackers use this for targeted CVE lookups."],
    after: [
      "# Express:    app.disable('x-powered-by')",
      "# PHP:        expose_php = Off (in php.ini)",
      "# Nginx:      server_tokens off; (in http {} block)",
      "# Apache:     ServerTokens Prod (in httpd.conf)",
    ],
    explanation: "Removing framework/server version headers reduces the information available to attackers for fingerprinting and targeted exploits.",
  },
};

// ── 8. CORS wildcard ──────────────────────────────────────────────────────────

const CORS_FIXES: FrameworkFixes = {
  express: {
    file: "server.js",
    before: [
      "const express = require('express');",
      "const cors    = require('cors');",
      "const app = express();",
      "",
      "// Wildcard CORS — any website can make requests",
      "// on behalf of your logged-in users",
      "app.use(cors({ origin: '*' }));",
      "",
      "app.get('/api/me', authRequired, getUserData);",
    ],
    after: [
      "const express = require('express');",
      "const cors    = require('cors');",
      "const app = express();",
      "",
      "// Restrict to specific trusted origins",
      "const ALLOWED_ORIGINS = [",
      "  'https://yourdomain.com',",
      "  'https://www.yourdomain.com',",
      "  process.env.NODE_ENV === 'development' ? 'http://localhost:5173' : null,",
      "].filter(Boolean);",
      "",
      "app.use(cors({",
      "  origin: (origin, cb) => {",
      "    if (!origin || ALLOWED_ORIGINS.includes(origin))",
      "      return cb(null, true);",
      "    cb(new Error(`CORS: origin '${origin}' not allowed`));",
      "  },",
      "  credentials: true,",
      "}));",
      "",
      "app.get('/api/me', authRequired, getUserData);",
    ],
    explanation:
      "CORS wildcard (origin: '*') tells browsers any website may read your API responses. For public APIs this is intentional, but for authenticated APIs it means malicious sites can make requests as your logged-in users and read the results. The fix restricts to known trusted origins and enables credentials mode to support secure cookie-based sessions.",
  },
  nginx: {
    file: "nginx.conf",
    before: [
      "location /api/ {",
      "  # Wildcard CORS",
      "  add_header Access-Control-Allow-Origin *;",
      "  proxy_pass http://app:3000;",
      "}",
    ],
    after: [
      "location /api/ {",
      "  # Allow specific trusted origins only",
      "  set $cors_origin '';",
      "  if ($http_origin ~* '^https://(www\\.)?yourdomain\\.com$') {",
      "    set $cors_origin $http_origin;",
      "  }",
      "  add_header Access-Control-Allow-Origin  $cors_origin always;",
      "  add_header Access-Control-Allow-Credentials true always;",
      "  add_header Vary                          Origin  always;",
      "  proxy_pass http://app:3000;",
      "}",
    ],
    explanation:
      "Nginx's $cors_origin variable is set only when the request origin matches your trusted domains, then reflected back. The Vary: Origin header tells caches that responses differ by origin, preventing a cached wildcard response from being served to untrusted origins.",
  },
  default: {
    file: "server-config",
    before: ["Access-Control-Allow-Origin: *", "# Any origin can read API responses, including authenticated data."],
    after: [
      "Access-Control-Allow-Origin: https://yourdomain.com",
      "Access-Control-Allow-Credentials: true",
      "Vary: Origin",
    ],
    explanation: "Restrict CORS to known trusted origins. Never combine wildcard (*) with credentials:true — that combination is blocked by browsers and indicates a misconfiguration.",
  },
};

// ── 9. HTTPS not enforced ─────────────────────────────────────────────────────

const HTTPS_FIXES: FrameworkFixes = {
  nginx: {
    file: "nginx.conf",
    before: [
      "server {",
      "  listen 80;",
      "  server_name example.com;",
      "",
      "  # No HTTPS redirect — traffic is served in plaintext",
      "  location / {",
      "    proxy_pass http://app:3000;",
      "  }",
      "}",
    ],
    after: [
      "# Redirect all HTTP to HTTPS",
      "server {",
      "  listen 80;",
      "  server_name example.com www.example.com;",
      "  return 301 https://$host$request_uri;",
      "}",
      "",
      "server {",
      "  listen 443 ssl http2;",
      "  server_name example.com www.example.com;",
      "",
      "  ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;",
      "  ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;",
      "",
      "  add_header Strict-Transport-Security",
      "    \"max-age=31536000; includeSubDomains\" always;",
      "",
      "  location / {",
      "    proxy_pass http://app:3000;",
      "  }",
      "}",
    ],
    explanation:
      "The HTTP server block issues a permanent 301 redirect to HTTPS for all requests, including path and query string. The HTTPS block then serves the actual content with a TLS certificate. HSTS is added to lock browsers into HTTPS after the first visit. Obtain a free certificate with: certbot --nginx -d example.com",
  },
  express: {
    file: "server.js",
    before: [
      "const express = require('express');",
      "const app = express();",
      "",
      "// No HTTPS enforcement — serving over plain HTTP",
      "app.get('/', (req, res) => {",
      "  res.send('Welcome');",
      "});",
      "app.listen(3000);",
    ],
    after: [
      "const express = require('express');",
      "const app = express();",
      "",
      "// Redirect HTTP to HTTPS in production",
      "if (process.env.NODE_ENV === 'production') {",
      "  app.use((req, res, next) => {",
      "    if (req.headers['x-forwarded-proto'] !== 'https') {",
      "      return res.redirect(301, 'https://' + req.headers.host + req.url);",
      "    }",
      "    next();",
      "  });",
      "}",
      "",
      "app.get('/', (req, res) => {",
      "  res.send('Welcome');",
      "});",
      "app.listen(3000);",
    ],
    explanation:
      "Behind a reverse proxy (Nginx, AWS ALB, etc.), the Express app sees HTTP even when the client used HTTPS. The x-forwarded-proto header tells Express the original protocol. This redirect ensures all plaintext requests are sent to HTTPS in production.",
  },
  default: {
    file: "server-config",
    before: [
      "# Site is served over plain HTTP.",
      "# All traffic — including cookies and form data — is sent in cleartext.",
    ],
    after: [
      "# 1. Obtain a TLS certificate (free via Let's Encrypt):",
      "#    certbot certonly --standalone -d yourdomain.com",
      "",
      "# 2. Redirect all HTTP traffic to HTTPS:",
      "#    Nginx:  return 301 https://$host$request_uri;",
      "#    Apache: Redirect permanent / https://yourdomain.com/",
    ],
    explanation: "Serving over plain HTTP means passwords, cookies, and API tokens are transmitted in cleartext and can be intercepted by any network observer. Obtain a free TLS certificate from Let's Encrypt and redirect all HTTP to HTTPS.",
  },
};

// ── 10. TLS certificate expired / self-signed ─────────────────────────────────

const TLS_CERT_FIXES: FrameworkFixes = {
  nginx: {
    file: "nginx.conf + certbot",
    before: [
      "# Current state: certificate is expired or self-signed",
      "server {",
      "  listen 443 ssl;",
      "  ssl_certificate     /etc/ssl/certs/self-signed.crt;  # ← expired/invalid",
      "  ssl_certificate_key /etc/ssl/private/self-signed.key;",
      "}",
    ],
    after: [
      "# Step 1 — Install certbot (Let's Encrypt client):",
      "# sudo apt install certbot python3-certbot-nginx",
      "",
      "# Step 2 — Obtain and install a free certificate:",
      "# sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com",
      "",
      "# Step 3 — Enable auto-renewal (certbot installs a cron/systemd timer):",
      "# sudo certbot renew --dry-run",
      "",
      "# Resulting nginx.conf section (certbot fills this in automatically):",
      "server {",
      "  listen 443 ssl;",
      "  ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;",
      "  ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;",
      "  include /etc/letsencrypt/options-ssl-nginx.conf;",
      "}",
    ],
    explanation:
      "An expired or self-signed certificate causes full-page browser security warnings for every visitor, destroying trust. Let's Encrypt provides free, trusted, 90-day certificates that certbot renews automatically before expiry. The entire process takes about 5 minutes.",
  },
  default: {
    file: "server-config",
    before: [
      "# TLS certificate is expired, self-signed, or has a hostname mismatch.",
      "# All visitors see a browser security error.",
    ],
    after: [
      "# Obtain a free trusted certificate from Let's Encrypt:",
      "# certbot --nginx -d yourdomain.com",
      "",
      "# Or for other web servers:",
      "# certbot --apache  -d yourdomain.com",
      "# certbot certonly  --standalone -d yourdomain.com",
      "",
      "# Enable auto-renewal:",
      "# certbot renew --dry-run",
    ],
    explanation:
      "TLS certificate issues make browsers block access for all visitors. Let's Encrypt provides free, auto-renewing certificates. The certbot command-line tool handles installation and renewal automatically.",
  },
};

// ── 11. Exposed .git directory ────────────────────────────────────────────────

const GIT_EXPOSED_FIXES: FrameworkFixes = {
  nginx: {
    file: "nginx.conf",
    before: [
      "server {",
      "  listen 443 ssl;",
      "  root /var/www/html;",
      "",
      "  # No rules blocking .git — entire repo history is accessible",
      "  location / {",
      "    try_files $uri $uri/ =404;",
      "  }",
      "}",
    ],
    after: [
      "server {",
      "  listen 443 ssl;",
      "  root /var/www/html;",
      "",
      "  # Block .git, .env, and other sensitive dot-files",
      "  location ~ /\\. {",
      "    deny all;",
      "    return 404;",
      "  }",
      "",
      "  location / {",
      "    try_files $uri $uri/ =404;",
      "  }",
      "}",
    ],
    explanation:
      "The .git directory contains your entire source code history including every commit ever made. Attackers can download it with git-dumper and extract API keys, passwords, and internal URLs from historical commits — even if they were deleted. Block ALL dot-files at the web server level. You must also rotate any secrets that were ever committed.",
  },
  apache: {
    file: ".htaccess",
    before: [
      "# No .git directory protection",
      "# Default Apache config serves .git files",
      "Options -Indexes",
    ],
    after: [
      "# Block .git and all dot-files",
      "RedirectMatch 404 /\\.git",
      "RedirectMatch 404 /\\.env",
      "",
      "# Or using FilesMatch:",
      "<FilesMatch \"^\\.(git|env|htaccess|DS_Store)$\">",
      "  Require all denied",
      "</FilesMatch>",
    ],
    explanation:
      "Redirecting .git to 404 prevents attackers from downloading your source code history. The 404 response (rather than 403) avoids confirming the file exists. Rotate any secrets that were ever in your git history immediately.",
  },
  default: {
    file: "server-config",
    before: [
      "# .git directory is publicly accessible via HTTP.",
      "# Attackers can download your entire source code history.",
      "# GET /.git/HEAD → 200 OK",
    ],
    after: [
      "# Nginx:  location ~ /\\. { deny all; return 404; }",
      "# Apache: RedirectMatch 404 /\\.git",
      "# Caddy:  @dotfiles { path /.* }; respond @dotfiles 404",
      "",
      "# CRITICAL: Also rotate any secrets ever committed to this repo.",
    ],
    explanation:
      "Your git history is publicly downloadable and likely contains sensitive data from past commits. Block access immediately AND rotate all credentials that ever appeared in any commit.",
  },
};

// ── 12. Exposed .env file ─────────────────────────────────────────────────────

const ENV_EXPOSED_FIXES: FrameworkFixes = {
  nginx: {
    file: "nginx.conf",
    before: [
      "server {",
      "  root /var/www/html;",
      "  # .env file is in web root and publicly readable",
      "  # GET /.env → 200 OK with DB passwords, API keys...",
      "}",
    ],
    after: [
      "server {",
      "  root /var/www/html;",
      "",
      "  # Block ALL dot-files (covers .env, .env.local, .git, etc.)",
      "  location ~ /\\. {",
      "    deny all;",
      "    return 404;",
      "  }",
      "}",
      "",
      "# IMMEDIATE ACTION REQUIRED:",
      "# 1. Block the file (above)",
      "# 2. Rotate ALL credentials visible in the file",
      "# 3. Ensure .env is in .gitignore",
      "# 4. Move secrets to a secrets manager (AWS Secrets Manager, Vault)",
    ],
    explanation:
      "The .env file contains plaintext database credentials, API keys, and secret tokens. Anyone who can access it has complete control over all connected services. Block it at the web server immediately and rotate every credential in the file — attackers may have already downloaded it.",
  },
  default: {
    file: "server-config",
    before: [
      "# .env file is served publicly over HTTP.",
      "# Contains database passwords, API keys, and secret tokens.",
    ],
    after: [
      "# 1. Block access immediately (Nginx example):",
      "#    location ~ /\\. { deny all; return 404; }",
      "",
      "# 2. Rotate ALL credentials from the file NOW",
      "",
      "# 3. Ensure .env is in .gitignore:",
      "#    echo '.env' >> .gitignore",
      "",
      "# 4. Use a secrets manager instead of .env in production",
    ],
    explanation:
      "This is a critical emergency. Your entire credential set is publicly exposed. Block the file, rotate every secret, and audit your logs to see if the file was already accessed.",
  },
};

// ── 13. Error disclosure / stack traces ───────────────────────────────────────

const ERROR_DISCLOSURE_FIXES: FrameworkFixes = {
  express: {
    file: "src/middleware/errorHandler.js",
    before: [
      "// Global error handler — leaks internals to clients",
      "app.use((err, req, res, next) => {",
      "  res.status(err.status || 500).json({",
      "    error:   err.message,",
      "    stack:   err.stack,      // ← full stack trace exposed",
      "    details: err,            // ← entire error object sent",
      "  });",
      "});",
    ],
    after: [
      "const logger = require('./lib/logger');  // pino, winston, etc.",
      "",
      "// Safe error handler — logs internally, never exposes to client",
      "app.use((err, req, res, next) => {",
      "  logger.error({ err, url: req.url, method: req.method }, 'Unhandled error');",
      "",
      "  const isProd = process.env.NODE_ENV === 'production';",
      "  res.status(err.status || 500).json({",
      "    error: isProd ? 'An unexpected error occurred' : err.message,",
      "    // Never include err.stack or err in the response",
      "  });",
      "});",
    ],
    explanation:
      "Stack traces reveal internal file paths, function names, framework versions, and sometimes database query structure. Attackers use this to map your application and find exploitable code paths. In production, always log the full error server-side and return only a generic message to clients.",
  },
  php: {
    file: "php.ini",
    before: [
      "; PHP default — displays errors in the browser",
      "[PHP]",
      "display_errors = On   ; ← stack traces shown to users",
      "log_errors = Off      ; ← no server-side logging",
    ],
    after: [
      "; Production PHP settings — log errors, never display",
      "[PHP]",
      "display_errors  = Off  ; never show errors to users",
      "log_errors      = On   ; always log server-side",
      "error_log       = /var/log/php-errors.log",
      "",
      "; For .htaccess (Apache):",
      "; php_flag display_errors Off",
    ],
    explanation:
      "PHP's display_errors=On is suitable for development only. In production it leaks database query details, file paths, and application logic through error pages. Disable it immediately and ensure errors are logged to a server-side file that you monitor.",
  },
  default: {
    file: "server-config",
    before: [
      "# Error pages return stack traces with:",
      "#   - Internal file paths",
      "#   - Function/method names",
      "#   - Framework/library versions",
      "#   - Sometimes SQL queries",
    ],
    after: [
      "# Express: Return generic 500 in production, full error in development",
      "# PHP:     display_errors = Off in php.ini",
      "# Django:  DEBUG = False in settings.py",
      "# Rails:   config.consider_all_requests_local = false",
      "",
      "# Always log full error details SERVER-SIDE for debugging.",
    ],
    explanation: "Error pages should never reveal implementation details to end users. Log full errors server-side and return a generic message to clients in production.",
  },
};

// ── 14. Cookie security ───────────────────────────────────────────────────────

const COOKIE_FIXES: FrameworkFixes = {
  express: {
    file: "server.js",
    before: [
      "const session = require('express-session');",
      "",
      "// Insecure session cookie — missing security flags",
      "app.use(session({",
      "  secret: process.env.SESSION_SECRET,",
      "  resave: false,",
      "  saveUninitialized: false,",
      "  // No cookie security flags!",
      "}));",
    ],
    after: [
      "const session = require('express-session');",
      "",
      "app.use(session({",
      "  secret: process.env.SESSION_SECRET,",
      "  resave: false,",
      "  saveUninitialized: false,",
      "  cookie: {",
      "    httpOnly: true,             // XSS cannot steal the cookie",
      "    secure:   true,             // only sent over HTTPS",
      "    sameSite: 'strict',         // CSRF protection",
      "    maxAge:   7 * 24 * 60 * 60 * 1000, // 7 days",
      "  },",
      "}));",
    ],
    explanation:
      "HttpOnly prevents JavaScript (including XSS payloads) from reading the cookie. Secure ensures the cookie is never transmitted over HTTP, even if the user visits the HTTP version of your site. SameSite=Strict prevents the cookie from being sent on cross-site requests, blocking CSRF attacks.",
  },
  default: {
    file: "Set-Cookie header",
    before: [
      "# Current Set-Cookie header is missing security flags:",
      "Set-Cookie: session=abc123; Path=/",
      "",
      "# Missing: HttpOnly (XSS can steal it)",
      "# Missing: Secure  (sent over HTTP too)",
      "# Missing: SameSite (CSRF vulnerable)",
    ],
    after: [
      "Set-Cookie: session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict",
      "",
      "# HttpOnly — JavaScript cannot access this cookie",
      "# Secure   — only transmitted over HTTPS connections",
      "# SameSite — not sent on cross-site requests (prevents CSRF)",
    ],
    explanation:
      "Three flags work together to protect session cookies: HttpOnly stops XSS from stealing the cookie; Secure stops it being sent over unencrypted HTTP; SameSite=Strict stops it being sent in CSRF attacks from other sites.",
  },
};

// ── 15. Admin panel exposed ───────────────────────────────────────────────────

const ADMIN_EXPOSED_FIXES: FrameworkFixes = {
  nginx: {
    file: "nginx.conf",
    before: [
      "server {",
      "  listen 443 ssl;",
      "",
      "  # Admin panel returns 200 to everyone",
      "  location /admin/ {",
      "    proxy_pass http://app:3000/admin/;",
      "  }",
      "}",
    ],
    after: [
      "server {",
      "  listen 443 ssl;",
      "",
      "  # Restrict admin to specific IP ranges only",
      "  location /admin/ {",
      "    # Allow only your office/VPN IPs:",
      "    allow 203.0.113.0/24;  # office",
      "    allow 198.51.100.5;    # VPN",
      "    deny  all;",
      "",
      "    proxy_pass http://app:3000/admin/;",
      "  }",
      "}",
    ],
    explanation:
      "Publicly accessible admin panels are targets for credential stuffing and brute-force attacks. Restricting to known IP ranges at the Nginx level means attackers cannot even reach the login page. For a dynamic IP, use a VPN or bastion host. Also enable MFA for all admin accounts and rate-limit login attempts.",
  },
  default: {
    file: "server-config",
    before: [
      "# Admin panel is publicly accessible without authentication.",
      "# Anyone can attempt to log in from anywhere.",
    ],
    after: [
      "# 1. Restrict by IP (Nginx/Apache/Cloudflare)",
      "# 2. Move admin to a non-default URL",
      "# 3. Enable MFA for all admin accounts",
      "# 4. Add rate limiting on login (max 10 attempts per 15min per IP)",
      "# 5. Enable login alerting (email on admin sign-in)",
    ],
    explanation:
      "Exposed admin panels are prime targets for automated attacks. Defence-in-depth: restrict by IP, move the URL, add MFA, and rate-limit attempts.",
  },
};

// ── 16. Server version disclosed ──────────────────────────────────────────────

const SERVER_VERSION_FIXES: FrameworkFixes = {
  nginx: {
    file: "nginx.conf",
    before: [
      "http {",
      "  # server_tokens not configured",
      "  # Every response includes: Server: nginx/1.24.0",
      "  # Attackers can look up CVEs for that exact version",
      "}",
    ],
    after: [
      "http {",
      "  server_tokens off;  # hides version from Server header and error pages",
      "",
      "  # Optionally hide the header entirely with more_clear_headers",
      "  # (requires nginx headers-more module):",
      "  # more_clear_headers Server;",
      "}",
    ],
    explanation:
      "server_tokens off stops Nginx from including its version number in the Server header and in error pages. An attacker who knows your exact Nginx version can search for unpatched CVEs targeting that version. This is a one-line change with no functional impact.",
  },
  apache: {
    file: "httpd.conf",
    before: [
      "# Apache default — full version in headers and error pages",
      "# Server: Apache/2.4.54 (Ubuntu)",
      "",
      "# ServerTokens Full (default)",
    ],
    after: [
      "# Minimise Apache version disclosure",
      "ServerTokens Prod       # shows 'Apache' only, no version",
      "ServerSignature Off     # removes version from error pages",
      "",
      "# Restart Apache after changing:",
      "# sudo systemctl restart apache2",
    ],
    explanation:
      "ServerTokens Prod reduces the Server header to just 'Apache' without a version number. ServerSignature Off removes the version from automatically generated error pages. Together they prevent version-based CVE targeting.",
  },
  default: {
    file: "server-config",
    before: [
      "# Server header reveals exact version:",
      "Server: nginx/1.24.0   (or Apache/2.4.54, etc.)",
    ],
    after: [
      "# Nginx:  server_tokens off;",
      "# Apache: ServerTokens Prod; ServerSignature Off",
      "# Caddy:  hides version automatically",
    ],
    explanation: "Removing version numbers from the Server header prevents attackers from quickly finding known CVEs for your exact software version.",
  },
};

// ── 17. WordPress-specific ────────────────────────────────────────────────────

const WORDPRESS_FIXES: FrameworkFixes = {
  default: {
    file: "functions.php + nginx.conf",
    before: [
      "// WordPress default — many attack surfaces exposed:",
      "// • Default admin URL: /wp-login.php (auto-brute forced)",
      "// • Version in <meta generator>",
      "// • xmlrpc.php enabled (DDoS amplification)",
      "// • File editor enabled in dashboard",
    ],
    after: [
      "// Add to functions.php to harden WordPress:",
      "",
      "// Remove version from meta and RSS",
      "remove_action('wp_head', 'wp_generator');",
      "add_filter('the_generator', '__return_empty_string');",
      "",
      "// Disable file editor (prevents code execution after compromise)",
      "define('DISALLOW_FILE_EDIT', true);",
      "",
      "// Disable xmlrpc if not needed",
      "add_filter('xmlrpc_enabled', '__return_false');",
      "",
      "// Add to nginx.conf — block xmlrpc and restrict wp-login:",
      "// location = /xmlrpc.php { deny all; }",
      "// location = /wp-login.php { limit_req zone=login burst=3; }",
    ],
    explanation:
      "WordPress's default configuration exposes several attack surfaces. Hiding the version prevents targeted attacks. Disabling the file editor prevents an attacker with admin access from immediately executing PHP. Blocking xmlrpc stops DDoS amplification and brute-force attacks via the XML-RPC protocol. Use a plugin like WPS Hide Login to move the admin URL.",
  },
};

// ── 18. HSTS max-age too short ────────────────────────────────────────────────

const HSTS_SHORT_FIXES: FrameworkFixes = {
  express: {
    file: "server.js",
    before: [
      "app.use(helmet.hsts({",
      "  maxAge: 86400,  // 1 day — too short, provides minimal protection",
      "}));",
    ],
    after: [
      "app.use(helmet.hsts({",
      "  maxAge:            31536000,  // 1 year — recommended minimum",
      "  includeSubDomains: true,",
      "  preload:           true,",
      "}));",
    ],
    explanation:
      "An HSTS max-age of less than 180 days provides limited protection. With a short max-age, a user who hasn't visited your site recently can still be downgraded. 31536000 seconds (1 year) is the standard and is required for HSTS preload list submission.",
  },
  nginx: {
    file: "nginx.conf",
    before: [
      "# Short max-age provides minimal HSTS protection",
      "add_header Strict-Transport-Security \"max-age=86400\" always;",
    ],
    after: [
      "# Minimum 1 year for meaningful HSTS protection",
      "add_header Strict-Transport-Security",
      "  \"max-age=31536000; includeSubDomains; preload\" always;",
    ],
    explanation: "Increase HSTS max-age to at least 31536000 (1 year). Short values mean browsers only remember to use HTTPS briefly and are vulnerable to downgrade attacks between visits.",
  },
  default: {
    file: "server-config",
    before: ["Strict-Transport-Security: max-age=86400  # too short"],
    after: [
      "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    ],
    explanation: "Increase max-age to 31536000 (1 year). The current value provides minimal protection against SSL-stripping attacks.",
  },
};

// ── 19. robots.txt sensitive path disclosure ──────────────────────────────────

const ROBOTS_DISCLOSURE_FIXES: FrameworkFixes = {
  default: {
    file: "robots.txt",
    before: [
      "User-agent: *",
      "Disallow: /admin/",
      "Disallow: /api/internal/",
      "Disallow: /backup/",
      "Disallow: /.git/",
      "",
      "# This file is public — it maps out sensitive paths for attackers",
    ],
    after: [
      "User-agent: *",
      "Disallow: /",
      "",
      "# Option 1: Blanket disallow then allow public paths",
      "User-agent: *",
      "Allow: /",
      "",
      "# Remove sensitive paths from robots.txt entirely.",
      "# Instead, protect them with authentication at the application level.",
      "# robots.txt is a hint to crawlers — NOT a security control.",
    ],
    explanation:
      "robots.txt is world-readable and cannot be used to protect sensitive URLs — it just tells search engine crawlers to skip them. But it also tells attackers exactly where your admin panel, API, and backups are. Remove sensitive paths from robots.txt and protect them with proper authentication instead.",
  },
};

// ── 20. No cache-control ──────────────────────────────────────────────────────

const CACHE_CONTROL_FIXES: FrameworkFixes = {
  express: {
    file: "server.js",
    before: [
      "// No cache-control for authenticated routes",
      "// Shared/proxy caches or browser back-button can serve",
      "// another user's account page",
      "app.get('/account', requireAuth, (req, res) => {",
      "  res.json(req.user.profile);",
      "});",
    ],
    after: [
      "// Private cache-control for all authenticated responses",
      "const noCache = (_req, res, next) => {",
      "  res.setHeader('Cache-Control', 'no-store, private');",
      "  next();",
      "};",
      "",
      "app.get('/account', requireAuth, noCache, (req, res) => {",
      "  res.json(req.user.profile);",
      "});",
      "",
      "// Or apply globally to all API routes:",
      "app.use('/api', requireAuth, noCache);",
    ],
    explanation:
      "Without Cache-Control: no-store, authenticated responses may be stored by shared proxies, CDNs, or browser caches. Another user on the same device or network could see a previous user's data via browser back-navigation or shared proxy cache. Set no-store on all authenticated endpoints.",
  },
  nginx: {
    file: "nginx.conf",
    before: [
      "location /api/ {",
      "  proxy_pass http://app:3000;",
      "  # No Cache-Control — responses may be cached",
      "}",
    ],
    after: [
      "location /api/ {",
      "  proxy_pass http://app:3000;",
      "",
      "  # Prevent caching of authenticated API responses",
      "  add_header Cache-Control \"no-store, private\" always;",
      "  add_header Pragma        \"no-cache\"          always;",
      "}",
    ],
    explanation: "Adding no-store to authenticated API routes prevents caches at every layer (browser, CDN, proxy) from storing responses that may contain user-specific data.",
  },
  default: {
    file: "server-config",
    before: ["# Cache-Control is missing or allows caching.", "# Authenticated content may be stored by shared caches."],
    after: [
      "# For authenticated pages/API endpoints:",
      "Cache-Control: no-store, private",
      "",
      "# For public, cacheable content:",
      "Cache-Control: public, max-age=3600, stale-while-revalidate=86400",
    ],
    explanation: "Authenticated responses must be marked no-store to prevent them being served to wrong users from caches. Public content benefits from caching headers for performance.",
  },
};

// ── 21. security.txt missing ──────────────────────────────────────────────────

const SECURITY_TXT_FIXES: FrameworkFixes = {
  default: {
    file: ".well-known/security.txt",
    before: [
      "# File does not exist",
      "# GET /.well-known/security.txt → 404",
      "",
      "# Security researchers who find a vulnerability have no",
      "# way to report it to you — they may disclose publicly instead.",
    ],
    after: [
      "# Create /.well-known/security.txt with:",
      "Contact: mailto:security@yourdomain.com",
      "Expires: 2027-12-31T00:00:00.000Z",
      "Preferred-Languages: en",
      "",
      "# Optional extras:",
      "# Encryption: https://yourdomain.com/pgp-key.txt",
      "# Policy: https://yourdomain.com/security-policy",
      "# Acknowledgments: https://yourdomain.com/hall-of-fame",
    ],
    explanation:
      "Security.txt (RFC 9116) gives security researchers a clear channel to report vulnerabilities responsibly. Without it, researchers who find a vulnerability may disclose it publicly rather than giving you a chance to fix it. Create the file, make sure the email is monitored, and keep the Expires date current.",
  },
};

// ─── Master lookup table ──────────────────────────────────────────────────────

function findTemplate(finding: WebsiteFinding, framework: Framework): FixTemplate | null {
  const title = finding.title.toLowerCase();
  const cat   = finding.category.toLowerCase();

  // Order matters — more specific matches first
  if (title.includes("hsts max-age too short") || title.includes("hsts missing includesubdomains")) return resolveTemplate(HSTS_SHORT_FIXES, framework);
  if (title.includes("strict-transport-security") || title.includes("hsts")) return resolveTemplate(HSTS_FIXES, framework);
  if (title.includes("content-security-policy") || title.includes("csp")) return resolveTemplate(CSP_FIXES, framework);
  if (title.includes("clickjacking") || title.includes("x-frame-options")) return resolveTemplate(CLICKJACKING_FIXES, framework);
  if (title.includes("x-content-type-options")) return resolveTemplate(XCTO_FIXES, framework);
  if (title.includes("referrer-policy")) return resolveTemplate(REFERRER_FIXES, framework);
  if (title.includes("permissions-policy")) return resolveTemplate(PERMISSIONS_FIXES, framework);
  if (title.includes("x-powered-by") || title.includes("server version")) return resolveTemplate(POWERED_BY_FIXES, framework);
  if (title.includes("cors") || title.includes("access-control-allow-origin")) return resolveTemplate(CORS_FIXES, framework);
  if (title.includes("not served over https") || title.includes("plain http")) return resolveTemplate(HTTPS_FIXES, framework);
  if (title.includes("certificate") && (title.includes("expired") || title.includes("self-signed") || title.includes("hostname") || title.includes("not yet valid"))) return resolveTemplate(TLS_CERT_FIXES, framework);
  if (title.includes(".git") || title.includes("git repository")) return resolveTemplate(GIT_EXPOSED_FIXES, framework);
  if (title.includes(".env") || cat.includes("exposed-file")) return resolveTemplate(ENV_EXPOSED_FIXES, framework);
  if (title.includes("stack trace") || title.includes("error page") || title.includes("debugging")) return resolveTemplate(ERROR_DISCLOSURE_FIXES, framework);
  if (cat.includes("cookie") || title.includes("cookie")) return resolveTemplate(COOKIE_FIXES, framework);
  if (title.includes("admin") && (title.includes("accessible") || title.includes("exposed"))) return resolveTemplate(ADMIN_EXPOSED_FIXES, framework);
  if (title.includes("cache-control") || title.includes("no cache")) return resolveTemplate(CACHE_CONTROL_FIXES, framework);
  if (title.includes("robots.txt") && title.includes("sensitive")) return resolveTemplate(ROBOTS_DISCLOSURE_FIXES, framework);
  if (title.includes("security.txt") || title.includes("no security.txt")) return resolveTemplate(SECURITY_TXT_FIXES, framework);
  if (title.includes("wordpress")) return resolveTemplate(WORDPRESS_FIXES, framework);

  return null; // No template for this finding type
}

function resolveTemplate(fixes: FrameworkFixes, framework: Framework): FixTemplate {
  return (fixes[framework] ?? fixes.default) as FixTemplate;
}

// ─── Main export ──────────────────────────────────────────────────────────────

export function generateRepairPlans(
  findings: WebsiteFinding[],
  fetchResult: FetchResult,
): RepairPlan[] {
  const framework = detectFramework(fetchResult);
  const plans: RepairPlan[] = [];
  const seenTitles = new Set<string>();

  // Only include actionable findings
  const actionable = findings.filter((f) => f.severity !== "info");

  for (const finding of actionable) {
    // Skip info-level and deduplicate similar titles
    const dedupeKey = finding.title.replace(/—.*$/, "").trim().toLowerCase();
    if (seenTitles.has(dedupeKey)) continue;

    const template = findTemplate(finding, framework);
    if (!template) continue; // no fix template available

    seenTitles.add(dedupeKey);

    plans.push({
      id:          `repair-${plans.length + 1}`,
      title:       finding.title,
      severity:    finding.severity as "critical" | "high" | "medium" | "low",
      category:    finding.category,
      description: finding.description,
      file:        template.file,
      beforeCode:  template.before.join("\n"),
      afterCode:   template.after.join("\n"),
      explanation: template.explanation,
      scoreGain:   SCORE_GAIN[finding.severity] ?? 2,
    });
  }

  return plans;
}

export function getDetectedFramework(fetchResult: FetchResult): string {
  const fw = detectFramework(fetchResult);
  const labels: Record<Framework, string> = {
    express: "Node.js / Express",
    nginx:   "Nginx",
    apache:  "Apache",
    php:     "PHP",
    django:  "Python / Django",
    generic: "Generic",
  };
  return labels[fw] ?? fw;
}
