/**
 * SecurityAI Assistant
 *
 * Provides rule-based, contextual responses to security questions.
 * This is a knowledge-base assistant that can be extended to call
 * a local or remote LLM when one is available.
 *
 * Design principle: This is a DEFENSIVE tool. All responses guide users
 * toward fixing vulnerabilities in their own code, never toward exploitation.
 */

// ─── Security knowledge base ──────────────────────────────────────────────────

interface KBEntry {
  keywords: string[];
  response: string;
}

const KNOWLEDGE_BASE: KBEntry[] = [
  {
    keywords: ["sql injection", "sqli", "sql query", "parameterized", "prepared statement"],
    response: `**SQL Injection Prevention**

SQL injection occurs when user input is concatenated directly into SQL queries. To prevent it:

1. **Use parameterized queries** (prepared statements) — the database engine treats parameters as data, not SQL syntax:
   \`\`\`python
   # Vulnerable
   cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
   
   # Safe
   cursor.execute("SELECT * FROM users WHERE name = %s", (username,))
   \`\`\`

2. **Use an ORM** (SQLAlchemy, Django ORM, Drizzle, Prisma) — these parameterize queries automatically.

3. **Apply least-privilege** — database accounts used by the app should have only the permissions they need (no DROP, no ALTER).

4. **Validate input** — even with parameterized queries, validate that input is the expected type and format.`,
  },
  {
    keywords: ["xss", "cross-site scripting", "innerhtml", "script injection"],
    response: `**Cross-Site Scripting (XSS) Prevention**

XSS lets attackers inject JavaScript into pages seen by other users. There are three main types: Reflected, Stored, and DOM-based.

**Key mitigations:**

1. **Encode output** — HTML-encode all user-supplied data before rendering it in HTML context:
   \`\`\`javascript
   // Use textContent instead of innerHTML for plain text
   element.textContent = userInput; // Safe
   element.innerHTML = userInput;   // Dangerous
   \`\`\`

2. **Use a framework** — React, Vue, and Angular escape output by default. Use their safe APIs (\`dangerouslySetInnerHTML\` in React is a code smell).

3. **Content Security Policy (CSP)** — set a strict CSP header to restrict which scripts can execute.

4. **Sanitize HTML** — if you must render HTML, use DOMPurify or a server-side sanitizer.

5. **Use \`HttpOnly\` cookies** — this prevents JS from stealing session tokens even if XSS occurs.`,
  },
  {
    keywords: ["hardcoded secret", "api key", "password in code", "credentials"],
    response: `**Removing Hardcoded Secrets**

Hardcoded credentials are one of the most common and dangerous vulnerabilities. Here's how to remediate:

**Immediate steps:**
1. If the secret was ever committed to Git, assume it's compromised — rotate it immediately.
2. Remove the secret from code and commit history (\`git filter-branch\` or BFG Repo Cleaner).

**Proper secret management:**
\`\`\`bash
# Store in environment variable
export DATABASE_URL="postgres://user:pass@host/db"

# Access in code
import os
db_url = os.getenv("DATABASE_URL")  # Python
\`\`\`

**For production, use a secrets manager:**
- **AWS Secrets Manager / Parameter Store**
- **HashiCorp Vault**
- **GCP Secret Manager**
- **Azure Key Vault**

**Prevent future leaks:**
- Add a \`.gitignore\` for \`.env\` files
- Use \`git-secrets\` or \`truffleHog\` as a pre-commit hook
- Add secrets scanning to your CI/CD pipeline`,
  },
  {
    keywords: ["authentication", "auth", "jwt", "session", "login", "password hashing", "bcrypt"],
    response: `**Authentication Security Best Practices**

**Password storage:**
\`\`\`python
import bcrypt

# Hash on registration
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# Verify on login
bcrypt.checkpw(password.encode(), hashed)
\`\`\`
Use bcrypt, scrypt, or Argon2. Never use MD5, SHA-1, or unsalted hashes.

**JWT security:**
- Use a strong, random secret (256+ bits)
- Set short expiration times (\`exp\` claim, e.g., 15 minutes for access tokens)
- Use refresh tokens with rotation
- Validate \`alg\` header — reject \`none\` algorithm
- Store in HttpOnly cookies, not localStorage

**Session management:**
- Regenerate session ID after login (prevents session fixation)
- Use secure, HttpOnly, SameSite cookies
- Implement idle timeout and absolute session limits

**Multi-factor authentication:**
- Add TOTP-based MFA (Google Authenticator, Authy) using a library like \`pyotp\``,
  },
  {
    keywords: ["cors", "cross-origin", "access-control-allow-origin"],
    response: `**CORS Configuration Security**

CORS controls which origins can make cross-origin requests to your API.

**Dangerous configuration:**
\`\`\`python
# Wildcard — allows ALL origins (often unnecessary)
response.headers["Access-Control-Allow-Origin"] = "*"
\`\`\`

**Secure configuration:**
\`\`\`python
ALLOWED_ORIGINS = {"https://myapp.com", "https://admin.myapp.com"}

origin = request.headers.get("Origin")
if origin in ALLOWED_ORIGINS:
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Vary"] = "Origin"
\`\`\`

**Rules:**
- Use wildcard only for truly public, read-only APIs (like a public CDN)
- For authenticated APIs, always use an explicit allowlist
- Include \`Vary: Origin\` to prevent cache poisoning
- Restrict \`Access-Control-Allow-Methods\` to only needed verbs
- Avoid \`Access-Control-Allow-Credentials: true\` with wildcard origins (browsers block this anyway)`,
  },
  {
    keywords: ["csrf", "cross-site request forgery", "csrf token"],
    response: `**CSRF Protection**

CSRF tricks authenticated users into making unwanted requests. Mitigations:

1. **CSRF tokens** — the classic defense:
   \`\`\`python
   # Flask-WTF handles this automatically
   from flask_wtf import CSRFProtect
   csrf = CSRFProtect(app)
   \`\`\`

2. **SameSite cookies** — modern browsers honor this:
   \`\`\`
   Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly
   \`\`\`
   \`SameSite=Strict\` prevents cookies from being sent on cross-site requests entirely.

3. **Custom request headers** — for API endpoints, require a custom header (e.g., \`X-Requested-With\`). CORS prevents cross-site scripts from adding custom headers.

4. **Double-submit cookie** — send a CSRF token both as a cookie and in the request body/header; the server verifies they match.

**Note:** CSRF primarily affects cookie-based authentication. Token-based auth (JWT in Authorization header) is generally not vulnerable to CSRF.`,
  },
  {
    keywords: ["dependency", "package", "npm audit", "vulnerable package", "cve", "outdated"],
    response: `**Dependency Security Management**

**Auditing dependencies:**
\`\`\`bash
# Node.js
npm audit
npm audit fix

# Python
pip install pip-audit
pip-audit

# Or Safety
pip install safety
safety check
\`\`\`

**Best practices:**
1. **Pin versions** — use exact versions in lock files (\`package-lock.json\`, \`requirements.txt\`) for reproducible builds
2. **Regular updates** — review and update dependencies monthly; automate with Dependabot or Renovate
3. **Minimal dependencies** — each dependency is an attack surface; evaluate if it's truly needed
4. **Monitor CVEs** — subscribe to vulnerability alerts for your key dependencies
5. **Software Bill of Materials (SBOM)** — generate a SBOM (\`npm sbom\`, \`syft\`) to know exactly what you're running

**Automate in CI/CD:**
\`\`\`yaml
# GitHub Actions example
- name: Security audit
  run: npm audit --audit-level=high
\`\`\``,
  },
  {
    keywords: ["ssl", "tls", "certificate", "https", "verify", "encryption in transit"],
    response: `**TLS/SSL Security**

**Never disable certificate verification:**
\`\`\`python
# NEVER do this in production
requests.get(url, verify=False)  # Disables cert verification

# Always do this
requests.get(url)  # Verifies by default
\`\`\`

**Use modern TLS:**
- Require TLS 1.2 minimum; prefer TLS 1.3
- Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1
- Use strong cipher suites (AES-GCM, ChaCha20-Poly1305)
- Enable Forward Secrecy (ECDHE key exchange)

**Certificate management:**
- Use certificates from a trusted CA (Let's Encrypt for free certs)
- Monitor expiry and auto-renew (Certbot/ACME)
- Use HSTS to enforce HTTPS: \`Strict-Transport-Security: max-age=31536000; includeSubDomains\`

**Test your TLS configuration:**
- SSL Labs Server Test (ssllabs.com/ssltest)
- testssl.sh for local testing`,
  },
  {
    keywords: ["security header", "csp", "content security policy", "hsts", "x-frame-options"],
    response: `**HTTP Security Headers**

Add these headers to your server responses to harden the application:

\`\`\`
# Content Security Policy — restrict resource sources
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'

# Prevent clickjacking
X-Frame-Options: DENY
# (or use CSP frame-ancestors instead)

# Force HTTPS for 1 year
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

# Prevent MIME sniffing
X-Content-Type-Options: nosniff

# Referrer policy
Referrer-Policy: strict-origin-when-cross-origin

# Permissions Policy (replaces Feature-Policy)
Permissions-Policy: camera=(), microphone=(), geolocation=()
\`\`\`

**Quick win:** Use \`helmet\` in Node.js/Express:
\`\`\`javascript
import helmet from 'helmet';
app.use(helmet());
\`\`\`

Test your headers at: securityheaders.com`,
  },
  {
    keywords: ["rate limit", "brute force", "account lockout", "ddos"],
    response: `**Rate Limiting and Brute Force Protection**

Protect authentication endpoints and APIs from brute force attacks:

**Node.js with express-rate-limit:**
\`\`\`javascript
import rateLimit from 'express-rate-limit';

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per window
  message: 'Too many login attempts, please try again later',
  standardHeaders: true,
});

app.post('/auth/login', authLimiter, loginHandler);
\`\`\`

**Key strategies:**
1. **IP-based rate limiting** — limit requests per IP address
2. **Account lockout** — temporarily lock accounts after N failed attempts (with exponential backoff)
3. **CAPTCHA** — after a threshold of failures, require CAPTCHA
4. **Notification** — alert users of failed login attempts via email

**For APIs:**
- Rate limit by API key, not just IP
- Return \`429 Too Many Requests\` with \`Retry-After\` header
- Use a distributed rate limiter (Redis) if running multiple instances`,
  },
];

// ─── Default fallback responses ────────────────────────────────────────────────

const GENERAL_RESPONSES = [
  `I'm SecurityAI, your defensive security assistant. I can help you understand and remediate security vulnerabilities in your own code.

**Topics I can help with:**
- SQL Injection prevention
- XSS (Cross-Site Scripting) defense
- Hardcoded secrets and credential management
- Authentication security (passwords, JWTs, sessions)
- CORS configuration
- CSRF protection
- Dependency vulnerability management
- TLS/SSL configuration
- HTTP security headers
- Rate limiting and brute force protection

What security topic would you like to explore?`,

  `That's a good security question. To give you the most relevant guidance, could you share more context? For example:
- What programming language or framework are you using?
- Is this about a specific finding from a scan?
- What kind of application is this (web API, frontend, mobile backend)?

You can also ask me about specific vulnerabilities like "How do I fix SQL injection?" or "What are best practices for storing passwords?"`,
];

// ─── Main response function ───────────────────────────────────────────────────

/**
 * Generate a contextual security assistant response.
 * Matches the user message against the knowledge base.
 * Falls back to a general response when no specific topic matches.
 */
export function generateAssistantResponse(
  userMessage: string,
  _scanContext?: string
): string {
  const lower = userMessage.toLowerCase();

  // Try to match a knowledge base entry
  for (const entry of KNOWLEDGE_BASE) {
    if (entry.keywords.some((kw) => lower.includes(kw))) {
      return entry.response;
    }
  }

  // Check for greetings
  if (/^(?:hi|hello|hey|howdy)\b/.test(lower)) {
    return GENERAL_RESPONSES[0];
  }

  // Check for "help" or "what can you do"
  if (/\b(?:help|what can you|capabilities|features)\b/.test(lower)) {
    return GENERAL_RESPONSES[0];
  }

  // Check if asking about a specific finding or code snippet
  if (lower.includes("fix") || lower.includes("remediat") || lower.includes("how to")) {
    return `To give you specific remediation advice, I need a bit more detail about what you're trying to fix. 

Could you tell me:
1. What vulnerability or finding are you addressing?
2. What programming language are you using?

You can also paste a code snippet and describe the issue, and I'll walk you through the fix. Remember, if this came from a SecurityAI scan, click the finding for its specific recommendation.`;
  }

  // Default fallback
  return GENERAL_RESPONSES[1];
}
