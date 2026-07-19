/**
 * SecurityAI Static Code Scanner
 *
 * Performs defensive static analysis on submitted code to detect:
 * - Hardcoded secrets (API keys, passwords, tokens)
 * - Unsafe coding patterns (eval, SQL injection vectors, XSS sinks)
 * - Missing security best practices (no input validation, CORS wildcards, etc.)
 * - Weak configurations (HTTP instead of HTTPS, debug mode, etc.)
 * - Outdated/dangerous dependency patterns
 *
 * This is a pattern-matching scanner. It is NOT a tool for attacking systems.
 */

export interface ScanFinding {
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category:
    | "hardcoded-secret"
    | "unsafe-pattern"
    | "missing-best-practice"
    | "weak-config"
    | "outdated-dependency";
  lineNumber?: number;
  codeSnippet?: string;
  recommendation: string;
  cweId?: string;
}

// ─── Pattern definitions ──────────────────────────────────────────────────────

interface PatternRule {
  id: string;
  pattern: RegExp;
  title: string;
  description: string;
  severity: ScanFinding["severity"];
  category: ScanFinding["category"];
  recommendation: string;
  cweId?: string;
}

const SECRET_PATTERNS: PatternRule[] = [
  {
    id: "hardcoded-password",
    pattern:
      /(?:password|passwd|pwd)\s*[=:]\s*["'](?!\s*["'])[^"'\s]{4,}["']/gi,
    title: "Hardcoded Password Detected",
    description:
      "A hardcoded password was found in the source code. Hardcoded credentials are a critical security risk — they can be extracted from source control or compiled binaries.",
    severity: "critical",
    category: "hardcoded-secret",
    recommendation:
      "Remove the hardcoded password and use environment variables (e.g., os.getenv('DB_PASSWORD')) or a secrets management service such as HashiCorp Vault or AWS Secrets Manager.",
    cweId: "CWE-798",
  },
  {
    id: "hardcoded-api-key",
    pattern:
      /(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?key|secret[_-]?key)\s*[=:]\s*["'][A-Za-z0-9+/=_\-]{8,}["']/gi,
    title: "Hardcoded API Key Detected",
    description:
      "An API key or secret appears to be embedded directly in the code. Hardcoded API keys can be extracted from source repositories and abused by attackers.",
    severity: "critical",
    category: "hardcoded-secret",
    recommendation:
      "Store API keys in environment variables or a secrets manager. Never commit secrets to version control. Consider rotating the exposed key immediately.",
    cweId: "CWE-798",
  },
  {
    id: "aws-access-key",
    pattern: /AKIA[0-9A-Z]{16}/g,
    title: "AWS Access Key ID Exposed",
    description:
      "An AWS Access Key ID pattern was detected. If this is a real key, it provides access to AWS services and must be treated as critically compromised.",
    severity: "critical",
    category: "hardcoded-secret",
    recommendation:
      "Revoke this AWS key immediately in the AWS IAM console. Use IAM roles, environment variables, or AWS Secrets Manager instead of hardcoded credentials.",
    cweId: "CWE-798",
  },
  {
    id: "private-key-pem",
    pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
    title: "Private Key Found in Code",
    description:
      "A PEM-formatted private key was detected in the source code. Private keys provide cryptographic identity and must never be embedded in code or committed to source control.",
    severity: "critical",
    category: "hardcoded-secret",
    recommendation:
      "Remove the private key from the codebase immediately. Store private keys in a secrets manager, hardware security module (HSM), or secure key store. Rotate the key if it was ever committed.",
    cweId: "CWE-321",
  },
  {
    id: "jwt-secret",
    pattern:
      /(?:jwt[_-]?secret|token[_-]?secret|signing[_-]?key)\s*[=:]\s*["'][^"'\s]{8,}["']/gi,
    title: "Hardcoded JWT Secret",
    description:
      "A hardcoded JWT signing secret was detected. If an attacker obtains this value, they can forge arbitrary JWT tokens and bypass authentication.",
    severity: "critical",
    category: "hardcoded-secret",
    recommendation:
      "Generate a cryptographically random JWT secret of at least 256 bits and store it in an environment variable. Rotate it regularly.",
    cweId: "CWE-798",
  },
  {
    id: "database-connection-string",
    pattern:
      /(?:mongodb|postgres|postgresql|mysql|redis|amqp):\/\/[^"'\s<>]+:[^"'\s<>@]+@[^"'\s<>]+/gi,
    title: "Database Connection String with Credentials",
    description:
      "A database connection string containing embedded credentials was found. This exposes the database username and password to anyone who can read the source.",
    severity: "critical",
    category: "hardcoded-secret",
    recommendation:
      "Use environment variables for connection strings (e.g., DATABASE_URL). Never embed credentials in URLs committed to source control.",
    cweId: "CWE-798",
  },
  {
    id: "generic-token",
    pattern: /(?:token|auth_token|bearer)\s*[=:]\s*["'][A-Za-z0-9._\-]{20,}["']/gi,
    title: "Hardcoded Authentication Token",
    description:
      "What appears to be a hardcoded authentication token was found. Tokens embedded in source code can be extracted and used to impersonate users or services.",
    severity: "high",
    category: "hardcoded-secret",
    recommendation:
      "Move this token to an environment variable or secrets management service. Ensure it is excluded from version control via .gitignore.",
    cweId: "CWE-798",
  },
];

const UNSAFE_PATTERN_RULES: PatternRule[] = [
  {
    id: "eval-usage",
    pattern: /\beval\s*\(/g,
    title: "Use of eval() Detected",
    description:
      "eval() executes arbitrary JavaScript from a string at runtime. If any user-controlled data reaches eval(), it results in Remote Code Execution (RCE).",
    severity: "critical",
    category: "unsafe-pattern",
    recommendation:
      "Remove eval() entirely. Use safer alternatives: JSON.parse() for JSON data, Function() constructors sparingly only with fully trusted input, or restructure the code to avoid dynamic execution.",
    cweId: "CWE-95",
  },
  {
    id: "sql-string-concatenation",
    pattern:
      /(?:execute|query|cursor\.execute)\s*\(\s*["'`][^"'`]*["'`]\s*\+|["'`]\s*\+\s*\w+\s*\+\s*["'`][^"'`]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)/gi,
    title: "Potential SQL Injection via String Concatenation",
    description:
      "SQL query appears to be constructed by concatenating strings and variables. This is a classic SQL injection vulnerability — user input embedded directly in SQL gives attackers full database control.",
    severity: "critical",
    category: "unsafe-pattern",
    recommendation:
      "Always use parameterized queries or prepared statements. Never concatenate user input into SQL strings. Use an ORM or query builder that handles parameterization automatically.",
    cweId: "CWE-89",
  },
  {
    id: "innerHTML-assignment",
    pattern: /\.innerHTML\s*=/g,
    title: "innerHTML Assignment — Potential XSS",
    description:
      "Assigning to innerHTML can introduce Cross-Site Scripting (XSS) if any user-supplied content is included. XSS allows attackers to inject malicious scripts into pages viewed by other users.",
    severity: "high",
    category: "unsafe-pattern",
    recommendation:
      "Use textContent instead of innerHTML for plain text. If HTML is required, sanitize it with a library such as DOMPurify before assignment. Consider using a framework's safe rendering primitives.",
    cweId: "CWE-79",
  },
  {
    id: "document-write",
    pattern: /document\.write\s*\(/g,
    title: "document.write() Usage",
    description:
      "document.write() is a legacy method that can introduce XSS and causes performance issues. It rewrites the entire page when called after load.",
    severity: "high",
    category: "unsafe-pattern",
    recommendation:
      "Replace document.write() with DOM manipulation methods (createElement, appendChild, innerHTML with sanitization) or framework rendering.",
    cweId: "CWE-79",
  },
  {
    id: "exec-shell-command",
    pattern:
      /(?:os\.system|subprocess\.call|subprocess\.Popen|exec\s*\(|execSync\s*\(|child_process\.exec)/g,
    title: "Shell Command Execution Detected",
    description:
      "Code executes shell commands. If any part of the command is derived from user input, this is a Command Injection vulnerability allowing attackers to run arbitrary system commands.",
    severity: "high",
    category: "unsafe-pattern",
    recommendation:
      "Avoid shell execution when possible. If necessary, use parameterized subprocess calls (e.g., subprocess.run with a list, not a string). Never interpolate user input into shell commands. Validate and allowlist inputs strictly.",
    cweId: "CWE-78",
  },
  {
    id: "unsafe-deserialization",
    pattern: /pickle\.loads?\s*\(|yaml\.load\s*\([^)]*\)|Marshal\.load\s*\(/g,
    title: "Unsafe Deserialization Detected",
    description:
      "Unsafe deserialization of data from an untrusted source can allow attackers to execute arbitrary code, cause denial of service, or escalate privileges.",
    severity: "critical",
    category: "unsafe-pattern",
    recommendation:
      "Use safe deserializers: yaml.safe_load() instead of yaml.load(), avoid pickle for untrusted data, or use a data format like JSON which does not execute code during parsing.",
    cweId: "CWE-502",
  },
  {
    id: "md5-sha1-weak-hash",
    pattern: /\b(?:md5|sha1|sha-1)\b/gi,
    title: "Weak Cryptographic Hash Function",
    description:
      "MD5 and SHA-1 are cryptographically broken hash functions. They should not be used for security-sensitive purposes such as password hashing, digital signatures, or integrity checks.",
    severity: "medium",
    category: "unsafe-pattern",
    recommendation:
      "Use SHA-256 or SHA-3 for general hashing, bcrypt/scrypt/Argon2 for password hashing, and HMAC-SHA256 for MACs. Never use MD5 or SHA-1 for security purposes.",
    cweId: "CWE-327",
  },
  {
    id: "http-not-https",
    pattern: /http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z0-9.-]+/g,
    title: "Unencrypted HTTP URL",
    description:
      "A non-localhost HTTP URL was found. HTTP transmits data in plaintext, making it vulnerable to man-in-the-middle attacks, eavesdropping, and content injection.",
    severity: "medium",
    category: "unsafe-pattern",
    recommendation:
      "Use HTTPS for all external URLs. Configure HTTP to HTTPS redirects and use HSTS headers. Obtain a TLS certificate via Let's Encrypt or your cloud provider.",
    cweId: "CWE-319",
  },
];

const BEST_PRACTICE_RULES: PatternRule[] = [
  {
    id: "debug-mode-enabled",
    pattern: /(?:DEBUG|debug)\s*[=:]\s*(?:True|true|1|yes)/g,
    title: "Debug Mode Enabled",
    description:
      "Debug mode is enabled. In production, debug mode can expose stack traces, configuration details, and enable development endpoints that should not be publicly accessible.",
    severity: "high",
    category: "missing-best-practice",
    recommendation:
      "Disable debug mode in production. Use environment variables to control this setting (DEBUG=False). Ensure error pages in production show generic messages, not stack traces.",
    cweId: "CWE-489",
  },
  {
    id: "cors-wildcard",
    pattern: /Access-Control-Allow-Origin['":\s]*[*]/g,
    title: "CORS Wildcard Policy",
    description:
      "A wildcard (*) CORS policy was detected. This allows any origin to make cross-origin requests, which undermines Same-Origin Policy protections.",
    severity: "medium",
    category: "missing-best-practice",
    recommendation:
      "Restrict CORS to specific trusted origins. Maintain an explicit allowlist of domains that are permitted to make cross-origin requests to your API.",
    cweId: "CWE-942",
  },
  {
    id: "todo-security",
    pattern: /(?:TODO|FIXME|HACK|XXX)\s*:?\s*(?:security|auth|password|token|secret|vulnerability|fix)/gi,
    title: "Security-Related TODO Comment",
    description:
      "A TODO or FIXME comment referencing a security concern was found. These often indicate known security issues that have not been resolved.",
    severity: "low",
    category: "missing-best-practice",
    recommendation:
      "Address security-related TODOs promptly. Track them in your issue tracker with appropriate priority. Do not ship code to production with known security TODOs.",
    cweId: undefined,
  },
  {
    id: "exception-suppression",
    pattern: /except\s*:\s*pass|catch\s*\(\s*\w*\s*\)\s*\{\s*\}/g,
    title: "Broad Exception Suppression",
    description:
      "All exceptions are being silently caught and ignored. This can hide security errors, authentication failures, or other critical conditions that need to be handled explicitly.",
    severity: "medium",
    category: "missing-best-practice",
    recommendation:
      "Catch specific exception types rather than all exceptions. Log security-relevant errors. Never silently suppress authentication or authorization errors.",
    cweId: "CWE-390",
  },
  {
    id: "no-input-validation",
    pattern: /request\.(?:args|form|json|data|get|post)\[/g,
    title: "Unvalidated Request Input Access",
    description:
      "Request parameters are being accessed without apparent validation. Using user input directly without validation can lead to injection attacks, business logic bypass, or application errors.",
    severity: "medium",
    category: "missing-best-practice",
    recommendation:
      "Validate all input using schema validation (Pydantic, Zod, Joi, etc.). Use strict type checking, length limits, and allowlisting for expected values. Never trust client-supplied data.",
    cweId: "CWE-20",
  },
];

const WEAK_CONFIG_RULES: PatternRule[] = [
  {
    id: "ssl-verification-disabled",
    pattern: /verify\s*[=:]\s*False|ssl_verify\s*[=:]\s*false|rejectUnauthorized\s*:\s*false/gi,
    title: "SSL Certificate Verification Disabled",
    description:
      "SSL/TLS certificate verification is disabled. This defeats the purpose of HTTPS and makes the application vulnerable to man-in-the-middle attacks where an attacker can intercept and modify traffic.",
    severity: "critical",
    category: "weak-config",
    recommendation:
      "Never disable SSL verification in production. If you have certificate issues, fix them properly (valid CA-signed cert, correct hostname). In development, use a local CA instead of disabling verification.",
    cweId: "CWE-295",
  },
  {
    id: "weak-cipher",
    pattern:
      /(?:DES|3DES|RC4|RC2|NULL)\b|SSLv2|SSLv3|TLSv1(?:\.0)?(?:['")\s]|$)/g,
    title: "Weak Cryptographic Algorithm",
    description:
      "A deprecated or weak cryptographic algorithm was referenced. DES, 3DES, RC4, RC2, SSLv2, SSLv3, and TLS 1.0 have known vulnerabilities and should not be used.",
    severity: "high",
    category: "weak-config",
    recommendation:
      "Use AES-256-GCM for symmetric encryption, TLS 1.2 or higher (prefer TLS 1.3), and RSA-2048/ECDSA-256 or stronger for asymmetric operations.",
    cweId: "CWE-326",
  },
  {
    id: "http-only-cookie-missing",
    pattern: /(?:Set-Cookie|set_cookie|response\.cookie)\s*[^;]+(?!HttpOnly|httpOnly|httponly)/gi,
    title: "Cookie Potentially Missing HttpOnly Flag",
    description:
      "A cookie is being set, but the HttpOnly flag may not be present. Without HttpOnly, JavaScript can read session cookies, making them vulnerable to XSS-based session hijacking.",
    severity: "medium",
    category: "weak-config",
    recommendation:
      "Always set the HttpOnly flag on session cookies and other sensitive cookies. Also set the Secure flag to prevent transmission over HTTP, and use SameSite=Strict or Lax.",
    cweId: "CWE-1004",
  },
  {
    id: "short-password-min-length",
    pattern: /(?:min_length|minLength|min_len|minLen)\s*[=:]\s*[1-5](?!\d)/g,
    title: "Weak Password Minimum Length",
    description:
      "A minimum password length of 5 or fewer characters was detected. Short passwords are trivially brute-forceable, especially with modern hardware.",
    severity: "medium",
    category: "weak-config",
    recommendation:
      "Set a minimum password length of at least 12 characters. Consider requiring a mix of character types or using a passphrase approach. NIST SP 800-63B recommends 8+ characters minimum, but 12+ is better practice.",
    cweId: "CWE-521",
  },
  {
    id: "bind-all-interfaces",
    pattern: /(?:host|bind)\s*[=:]\s*["']0\.0\.0\.0["'](?!\s*#\s*intentional)/g,
    title: "Service Bound to All Network Interfaces",
    description:
      "The service is configured to listen on all network interfaces (0.0.0.0). In production, this can expose internal services to external networks if firewall rules are misconfigured.",
    severity: "low",
    category: "weak-config",
    recommendation:
      "In production, bind services to specific network interfaces unless external access is explicitly required. Use a reverse proxy (nginx, Caddy) to handle external traffic and bind the app server to localhost.",
    cweId: "CWE-605",
  },
];

const DEPENDENCY_RULES: PatternRule[] = [
  {
    id: "log4j-usage",
    pattern: /log4j|Log4j/g,
    title: "log4j Dependency Detected",
    description:
      "log4j was detected. Certain versions of log4j (2.0-2.14.1) are affected by Log4Shell (CVE-2021-44228), one of the most severe vulnerabilities in recent history allowing Remote Code Execution.",
    severity: "critical",
    category: "outdated-dependency",
    recommendation:
      "Upgrade to log4j 2.17.1 or later. If upgrading is not immediately possible, apply mitigations: set LOG4J_FORMAT_MSG_NO_LOOKUPS=true or remove the JndiLookup class from the classpath.",
    cweId: "CWE-502",
  },
  {
    id: "python-flask-debug",
    pattern: /app\.run\s*\([^)]*debug\s*=\s*True/g,
    title: "Flask Debug Mode Active in app.run()",
    description:
      "Flask's development server is running with debug=True. This enables the Werkzeug interactive debugger, which allows arbitrary code execution on the server from the browser if reached by an attacker.",
    severity: "critical",
    category: "outdated-dependency",
    recommendation:
      "Never use app.run(debug=True) in production. Use a production WSGI server (Gunicorn, uWSGI) and set FLASK_ENV=production. Debug mode should only be active in local development.",
    cweId: "CWE-94",
  },
  {
    id: "npm-star-version",
    pattern: /"[^"]+"\s*:\s*"\*"/g,
    title: "Wildcard NPM Dependency Version",
    description:
      "A wildcard (*) version was found in package.json. This installs the latest available version, which can introduce breaking changes or pull in vulnerable package versions automatically.",
    severity: "medium",
    category: "outdated-dependency",
    recommendation:
      "Pin dependency versions or use semantic versioning ranges (e.g., ^1.2.3, ~1.2.3). Run npm audit regularly to detect known vulnerabilities and keep dependencies updated.",
    cweId: "CWE-1104",
  },
  {
    id: "requirements-no-versions",
    pattern: /^[a-zA-Z][a-zA-Z0-9_-]+\s*$/gm,
    title: "Python Dependency Without Version Pin",
    description:
      "A Python dependency in requirements.txt has no version pin. Unpinned dependencies can cause non-reproducible builds and may automatically install vulnerable versions.",
    severity: "low",
    category: "outdated-dependency",
    recommendation:
      "Pin all dependencies to specific versions in requirements.txt (e.g., flask==2.3.0). Use pip-compile or pipenv to manage dependency trees. Regularly audit with pip-audit or Safety.",
    cweId: "CWE-1104",
  },
];

const ALL_RULES: PatternRule[] = [
  ...SECRET_PATTERNS,
  ...UNSAFE_PATTERN_RULES,
  ...BEST_PRACTICE_RULES,
  ...WEAK_CONFIG_RULES,
  ...DEPENDENCY_RULES,
];

// ─── Config-specific rules ─────────────────────────────────────────────────────

const CONFIG_RULES: PatternRule[] = [
  {
    id: "aws-region-missing",
    pattern: /aws_access_key_id\s*[=:]/gi,
    title: "AWS Credentials in Config",
    description:
      "AWS credentials found in a configuration file. Configuration files are often committed to source control or have overly permissive file permissions.",
    severity: "critical",
    category: "weak-config",
    recommendation:
      "Use IAM roles, instance profiles, or environment variables for AWS credentials. Never store credentials in config files.",
    cweId: "CWE-798",
  },
  {
    id: "secret-key-default",
    pattern: /SECRET_KEY\s*[=:]\s*["'](?:changeme|secret|mysecret|default|dev)['"]/gi,
    title: "Default or Weak Secret Key",
    description:
      "A predictable or default secret key was detected. Default secret keys are publicly known and provide no security.",
    severity: "critical",
    category: "weak-config",
    recommendation:
      "Generate a cryptographically random secret key using: python -c \"import secrets; print(secrets.token_hex(32))\" and store it in an environment variable.",
    cweId: "CWE-798",
  },
];

// ─── Scoring ───────────────────────────────────────────────────────────────────

/**
 * Calculate a security score (0-100) based on findings.
 * Starts at 100 and deductions are applied per finding weighted by severity.
 */
export function calculateSecurityScore(findings: ScanFinding[]): number {
  const DEDUCTIONS = {
    critical: 25,
    high: 15,
    medium: 8,
    low: 3,
    info: 0,
  };

  let score = 100;
  for (const finding of findings) {
    score -= DEDUCTIONS[finding.severity] ?? 0;
  }

  return Math.max(0, Math.min(100, score));
}

// ─── Main scanner ─────────────────────────────────────────────────────────────

/**
 * Scan source code for security issues.
 * Returns a list of findings sorted by severity (critical first).
 */
export function scanCode(
  code: string,
  scanType: "code" | "dependency" | "config"
): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const lines = code.split("\n");

  // Choose rules based on scan type
  let rules: PatternRule[];
  if (scanType === "config") {
    rules = [...CONFIG_RULES, ...WEAK_CONFIG_RULES, ...SECRET_PATTERNS];
  } else if (scanType === "dependency") {
    rules = [...DEPENDENCY_RULES, ...SECRET_PATTERNS];
  } else {
    rules = ALL_RULES;
  }

  // Track which rule IDs we've already found (to avoid duplicate findings per rule)
  const foundRuleIds = new Set<string>();

  for (const rule of rules) {
    // Reset lastIndex for global regexes
    rule.pattern.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = rule.pattern.exec(code)) !== null) {
      // Find which line number this match is on
      const matchIndex = match.index;
      let lineNumber = 1;
      let charCount = 0;
      for (let i = 0; i < lines.length; i++) {
        charCount += lines[i].length + 1; // +1 for newline
        if (charCount > matchIndex) {
          lineNumber = i + 1;
          break;
        }
      }

      // Extract a small snippet around the match
      const snippetLine = lines[lineNumber - 1] ?? "";
      const snippet = snippetLine.length > 120 ? snippetLine.slice(0, 120) + "..." : snippetLine;

      // Redact any actual secret value from the snippet for safety
      const redactedSnippet = snippet.replace(
        /([=:]\s*["'])[^"']{4,}(["'])/g,
        "$1[REDACTED]$2"
      );

      findings.push({
        title: rule.title,
        description: rule.description,
        severity: rule.severity,
        category: rule.category,
        lineNumber,
        codeSnippet: redactedSnippet.trim() || undefined,
        recommendation: rule.recommendation,
        cweId: rule.cweId,
      });

      // For non-global patterns or after finding one match, break if we only want unique findings per rule
      if (foundRuleIds.has(rule.id)) {
        // Already found this rule, still add but limit to 5 per rule
        const ruleFindings = findings.filter((f) => f.title === rule.title);
        if (ruleFindings.length > 5) break;
      } else {
        foundRuleIds.add(rule.id);
      }

      // Avoid infinite loops on zero-length matches
      if (match[0].length === 0) {
        rule.pattern.lastIndex++;
      }
    }

    // Reset for next iteration
    rule.pattern.lastIndex = 0;
  }

  // Sort: critical > high > medium > low > info
  const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort(
    (a, b) =>
      (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)
  );

  return findings;
}

/**
 * Generate a human-readable report summary for a completed scan.
 */
export function generateReportSummary(
  scanName: string,
  score: number,
  findings: ScanFinding[]
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
    `Security analysis of "${scanName}" completed with a score of ${score}/100 (${riskLevel} Risk). ` +
    `The scan identified ${findings.length} finding${findings.length !== 1 ? "s" : ""}: ` +
    `${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, and ${counts.low} low severity. ` +
    (counts.critical > 0
      ? `Critical issues require immediate attention before this code is deployed to production. `
      : "") +
    (score >= 80
      ? "The codebase demonstrates generally good security practices with minor improvements recommended."
      : "Significant security improvements are required before this code should be considered production-ready.");

  const topFindings = findings.filter(
    (f) => f.severity === "critical" || f.severity === "high"
  );
  const recLines = topFindings.slice(0, 5).map((f) => `- ${f.title}: ${f.recommendation}`);

  if (recLines.length === 0) {
    recLines.push(
      "- Continue applying security best practices as the codebase evolves.",
      "- Integrate automated security scanning into your CI/CD pipeline.",
      "- Conduct periodic security reviews and penetration testing."
    );
  } else {
    recLines.push(
      "- Integrate automated security scanning into your CI/CD pipeline to catch issues early.",
      "- Consider a formal security review for critical or customer-facing components."
    );
  }

  const recommendations = recLines.join("\n");

  return { summary, recommendations };
}
