/**
 * Orix - Code Quality & Security Scanner — Security Analyzer
 * Detects security vulnerabilities across multiple languages and patterns.
 */

'use strict';

const SECURITY_RULES = [
  // ─── SECRETS & CREDENTIALS ────────────────────────────────────────────────
  {
    id: 'SEC001',
    name: 'Hardcoded Password',
    severity: 'error',
    pattern: /(?:password|passwd|pwd)\s*[:=]\s*['\"`][^'\"`\s]{3,}['\"`]/gi,
    message: (match) => `Hardcoded password detected: "${match.trim().slice(0, 60)}". Store credentials in environment variables or a secrets manager.`,
    tags: ['secrets', 'credentials'],
  },
  {
    id: 'SEC002',
    name: 'Hardcoded API Key',
    severity: 'error',
    pattern: /(?:api_?key|apikey|api_?secret|access_?key|auth_?token)\s*[:=]\s*['\"`][A-Za-z0-9_\-\.]{10,}['\"`]/gi,
    message: () => 'Hardcoded API key or secret detected. Use environment variables (process.env.KEY) instead.',
    tags: ['secrets', 'credentials'],
  },
  {
    id: 'SEC003',
    name: 'Hardcoded JWT / Bearer Token',
    severity: 'error',
    pattern: /(?:Bearer\s+|jwt\s*[:=]\s*['\"`]?)ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/gi,
    message: () => 'Hardcoded JWT token detected. Never commit tokens to source code.',
    tags: ['secrets', 'tokens'],
  },
  {
    id: 'SEC004',
    name: 'Private Key in Source',
    severity: 'error',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    message: () => 'Private key material detected in source code. Remove immediately and rotate the key.',
    tags: ['secrets', 'cryptography'],
  },
  {
    id: 'SEC005',
    name: 'AWS Access Key ID',
    severity: 'error',
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    message: (match) => `Potential AWS Access Key ID: "${match}". Revoke and rotate this key immediately.`,
    tags: ['secrets', 'cloud'],
  },
  {
    id: 'SEC006',
    name: 'Generic Secret Assignment',
    severity: 'warning',
    pattern: /(?:secret|token|auth)\s*=\s*['\"`][A-Za-z0-9+/=_\-]{16,}['\"`]/gi,
    message: () => 'Possible hardcoded secret or token. Verify this is not sensitive data — move to env vars if so.',
    tags: ['secrets'],
  },
  {
    id: 'SEC007',
    name: 'GitHub / GitLab Personal Access Token',
    severity: 'error',
    pattern: /(?:gh[pousr]|glpat|ghs|gho)_[A-Za-z0-9_]{36,}/g,
    message: (match) => `Possible GitHub/GitLab token detected: "${match.slice(0, 20)}...". Revoke immediately.`,
    tags: ['secrets', 'tokens'],
  },
  {
    id: 'SEC008',
    name: 'Stripe Secret Key',
    severity: 'error',
    pattern: /sk_(?:live|test)_[A-Za-z0-9]{24,}/g,
    message: () => 'Stripe secret key detected. Move to environment variables immediately.',
    tags: ['secrets', 'payment'],
  },
  {
    id: 'SEC009',
    name: 'Google API Key',
    severity: 'error',
    pattern: /AIza[0-9A-Za-z\\-_]{35}/g,
    message: () => 'Google API key detected in source. Move to environment variables.',
    tags: ['secrets', 'cloud'],
  },

  // ─── CODE INJECTION ───────────────────────────────────────────────────────
  {
    id: 'SEC010',
    name: 'eval() Usage',
    severity: 'error',
    pattern: /\beval\s*\(/g,
    message: () => 'eval() executes arbitrary code and is a critical security risk. Refactor to avoid dynamic code execution.',
    tags: ['injection', 'code-execution'],
  },
  {
    id: 'SEC011',
    name: 'new Function() — Dynamic Code',
    severity: 'error',
    pattern: /new\s+Function\s*\(/g,
    message: () => 'new Function() is equivalent to eval() and poses the same risks. Avoid dynamic code construction.',
    tags: ['injection', 'code-execution'],
  },
  {
    id: 'SEC012',
    name: 'setTimeout/setInterval with String',
    severity: 'warning',
    pattern: /(?:setTimeout|setInterval)\s*\(\s*['\"`]/g,
    message: () => 'Passing a string to setTimeout/setInterval invokes eval() internally. Use a function reference instead.',
    tags: ['injection'],
  },
  {
    id: 'SEC013',
    name: 'Shell Command Injection Risk',
    severity: 'error',
    pattern: /(?:exec|execSync|spawn|spawnSync|system)\s*\(\s*(?:[^'\"`\)]*\+|`[^`]*\$\{)/g,
    message: () => 'Shell command constructed with dynamic input — high risk of command injection. Sanitize all inputs and use parameterized commands.',
    tags: ['injection', 'command-injection'],
  },
  {
    id: 'SEC014',
    name: 'SQL String Concatenation',
    severity: 'error',
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\s+.*\+\s*(?:req\.|request\.|params\.|body\.|query\.|input)/gi,
    message: () => 'SQL query built with string concatenation — SQL injection risk. Use parameterized queries or an ORM.',
    tags: ['injection', 'sql-injection'],
  },
  {
    id: 'SEC015',
    name: 'SQL Injection via Template Literal',
    severity: 'error',
    pattern: /['\"`](?:SELECT|INSERT|UPDATE|DELETE|WHERE)\s[^'\"`]*\$\{/gi,
    message: () => 'SQL query uses template literal interpolation — potential SQL injection. Use prepared statements.',
    tags: ['injection', 'sql-injection'],
  },
  {
    id: 'SEC016',
    name: 'NoSQL Injection Risk',
    severity: 'warning',
    pattern: /\$(?:where|regex|gt|lt|gte|lte|ne|in|nin|elemMatch)\s*:\s*(?:req\.|request\.|params\.|body\.)/gi,
    message: () => 'NoSQL operator built from user input — potential NoSQL injection. Validate and sanitize query operators.',
    tags: ['injection', 'nosql'],
  },
  {
    id: 'SEC017',
    name: 'LDAP Injection Risk',
    severity: 'warning',
    pattern: /ldap(?:Search|Bind|Query)\s*\([^)]*(?:req\.|request\.|input\.)/gi,
    message: () => 'LDAP query built from user input — LDAP injection risk. Use parameterized LDAP queries and escape user input.',
    tags: ['injection', 'ldap'],
  },

  // ─── XSS ──────────────────────────────────────────────────────────────────
  {
    id: 'SEC020',
    name: 'innerHTML Assignment',
    severity: 'error',
    pattern: /\.innerHTML\s*[+]?=/g,
    message: () => 'Direct innerHTML assignment can lead to XSS. Use textContent, innerText, or DOMPurify to sanitize HTML.',
    tags: ['xss'],
  },
  {
    id: 'SEC021',
    name: 'document.write() Usage',
    severity: 'warning',
    pattern: /document\.write\s*\(/g,
    message: () => 'document.write() is deprecated, can cause XSS, and blocks the parser. Use modern DOM methods.',
    tags: ['xss'],
  },
  {
    id: 'SEC022',
    name: 'outerHTML Assignment',
    severity: 'error',
    pattern: /\.outerHTML\s*[+]?=/g,
    message: () => 'outerHTML assignment is vulnerable to XSS. Sanitize HTML content before rendering.',
    tags: ['xss'],
  },
  {
    id: 'SEC023',
    name: 'dangerouslySetInnerHTML (React)',
    severity: 'warning',
    pattern: /dangerouslySetInnerHTML\s*=\s*\{/g,
    message: () => "dangerouslySetInnerHTML bypasses React's XSS protection. Ensure HTML is thoroughly sanitized with DOMPurify.",
    tags: ['xss', 'react'],
  },
  {
    id: 'SEC024',
    name: 'v-html Directive (Vue)',
    severity: 'warning',
    pattern: /v-html\s*=/g,
    message: () => 'v-html renders raw HTML and can cause XSS. Sanitize any user-supplied content.',
    tags: ['xss', 'vue'],
  },
  {
    id: 'SEC025',
    name: 'JavaScript URI in href',
    severity: 'error',
    pattern: /href\s*=\s*['\"`]javascript:/gi,
    message: () => 'javascript: URI in href can execute XSS. Never use javascript: URIs — use event handlers instead.',
    tags: ['xss'],
  },
  {
    id: 'SEC026',
    name: 'postMessage Without Origin Check',
    severity: 'warning',
    pattern: /addEventListener\s*\(\s*['\"`]message['\"`][^)]*\)\s*(?![\s\S]{0,200}event\.origin)/g,
    message: () => 'postMessage listener without origin validation. Always check event.origin before processing cross-origin messages.',
    tags: ['xss', 'postmessage'],
  },

  // ─── INSECURE RANDOM & CRYPTO ─────────────────────────────────────────────
  {
    id: 'SEC030',
    name: 'Math.random() for Security',
    severity: 'warning',
    pattern: /Math\.random\(\)/g,
    message: () => 'Math.random() is not cryptographically secure. Use crypto.getRandomValues() or crypto.randomBytes() for security-sensitive operations.',
    tags: ['cryptography', 'random'],
  },
  {
    id: 'SEC031',
    name: 'Weak Hash — MD5',
    severity: 'error',
    pattern: /\bmd5\b|\bcreateHash\s*\(\s*['\"`]md5['\"`]\s*\)/gi,
    message: () => 'MD5 is cryptographically broken. Use SHA-256 or stronger for any security purpose.',
    tags: ['cryptography', 'hashing'],
  },
  {
    id: 'SEC032',
    name: 'Weak Hash — SHA1',
    severity: 'warning',
    pattern: /\bsha1\b|\bcreateHash\s*\(\s*['\"`]sha1['\"`]\s*\)/gi,
    message: () => 'SHA-1 is deprecated for security use. Upgrade to SHA-256 or SHA-3.',
    tags: ['cryptography', 'hashing'],
  },
  {
    id: 'SEC033',
    name: 'Hardcoded Cryptographic Key/IV',
    severity: 'error',
    pattern: /(?:createCipher(?:iv)?|AES|DES)\s*\([^)]*['\"`][A-Fa-f0-9]{16,}['\"`]/gi,
    message: () => 'Hardcoded cryptographic key or IV detected. Keys must be randomly generated and securely stored.',
    tags: ['cryptography'],
  },
  {
    id: 'SEC034',
    name: 'ECB Mode Encryption',
    severity: 'error',
    pattern: /['\"`]aes-\d+-ecb['\"`]/gi,
    message: () => 'ECB (Electronic Codebook) mode is insecure — identical plaintext blocks produce identical ciphertext. Use AES-GCM or AES-CBC with a random IV.',
    tags: ['cryptography', 'encryption'],
  },
  {
    id: 'SEC035',
    name: 'Insecure bcrypt Rounds',
    severity: 'warning',
    pattern: /bcrypt\s*\.\s*(?:hash|hashSync)\s*\([^,]+,\s*[1-9]\b/g,
    message: () => 'bcrypt rounds value is very low (< 10). Use at least 12 rounds to maintain security as hardware improves.',
    tags: ['cryptography', 'password-hashing'],
  },

  // ─── NETWORK & TRANSPORT ──────────────────────────────────────────────────
  {
    id: 'SEC040',
    name: 'HTTP Instead of HTTPS',
    severity: 'warning',
    pattern: /['\"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^'\"`\s]+['\"`]/g,
    message: () => 'Non-HTTPS URL detected. Use HTTPS to protect data in transit.',
    tags: ['transport', 'network'],
  },
  {
    id: 'SEC041',
    name: 'SSL/TLS Verification Disabled',
    severity: 'error',
    pattern: /(?:rejectUnauthorized|verify)\s*:\s*false/gi,
    message: () => 'SSL/TLS certificate verification is disabled. This exposes the app to man-in-the-middle attacks.',
    tags: ['transport', 'tls'],
  },
  {
    id: 'SEC042',
    name: 'CORS Wildcard Origin',
    severity: 'warning',
    pattern: /(?:Access-Control-Allow-Origin|origin)\s*[:=]\s*['\"`]\*['\"`]/gi,
    message: () => 'CORS wildcard (*) allows any origin. Restrict to specific trusted domains in production.',
    tags: ['cors', 'network'],
  },
  {
    id: 'SEC043',
    name: 'Missing Helmet / Security Headers',
    severity: 'info',
    pattern: /(?:express|app)\s*\(\s*\)(?![\s\S]{0,500}helmet)/g,
    message: () => 'Express app created without Helmet security headers middleware. Add helmet() to set secure HTTP headers.',
    tags: ['headers', 'express'],
  },
  {
    id: 'SEC044',
    name: 'Unvalidated Redirect',
    severity: 'warning',
    pattern: /res\.redirect\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)/gi,
    message: () => 'Redirect target taken from user input — open redirect vulnerability. Validate against an allowlist of trusted URLs.',
    tags: ['redirect', 'open-redirect'],
  },

  // ─── PATH TRAVERSAL & FILE ────────────────────────────────────────────────
  {
    id: 'SEC050',
    name: 'Path Traversal Risk',
    severity: 'error',
    pattern: /(?:readFile|writeFile|readFileSync|writeFileSync|createReadStream)\s*\([^)]*(?:req\.|request\.|params\.|body\.|query\.)/gi,
    message: () => 'File operation uses request-supplied path — path traversal vulnerability. Validate and sanitize file paths.',
    tags: ['path-traversal', 'file'],
  },
  {
    id: 'SEC051',
    name: 'Insecure Temporary File',
    severity: 'warning',
    pattern: /\/tmp\/|os\.tmpdir\(\)/gi,
    message: () => 'Use of /tmp or temp directory. Ensure temp files are created securely (unique names) and cleaned up.',
    tags: ['file', 'tempfile'],
  },
  {
    id: 'SEC052',
    name: 'Untrusted File Upload Without Validation',
    severity: 'error',
    pattern: /(?:multer|formidable|busboy|multiparty)\s*\([^)]*\)(?![\s\S]{0,200}(?:mimetype|fileFilter|limits))/gi,
    message: () => 'File upload handler without visible MIME type validation or size limits. Validate file type, size, and sanitize filenames.',
    tags: ['file-upload', 'validation'],
  },

  // ─── PROTOTYPE & OBJECT ───────────────────────────────────────────────────
  {
    id: 'SEC060',
    name: 'Prototype Pollution Risk',
    severity: 'error',
    pattern: /\[(?:req\.|request\.|params\.|body\.|input\.)[^\]]*\]\s*=/g,
    message: () => 'Dynamic property assignment from user input may allow prototype pollution. Validate keys against an allowlist.',
    tags: ['prototype-pollution'],
  },
  {
    id: 'SEC061',
    name: '__proto__ Access',
    severity: 'error',
    pattern: /__proto__/g,
    message: () => '__proto__ access can enable prototype pollution attacks. Use Object.create(null) and Object.setPrototypeOf() instead.',
    tags: ['prototype-pollution'],
  },
  {
    id: 'SEC062',
    name: 'Object.assign with User Input',
    severity: 'warning',
    pattern: /Object\.assign\s*\(\s*\w+\s*,\s*(?:req\.|request\.|body\.|params\.)/gi,
    message: () => 'Object.assign with user-supplied data may overwrite critical properties or enable prototype pollution. Use a schema-validated subset.',
    tags: ['prototype-pollution', 'mass-assignment'],
  },

  // ─── PYTHON-SPECIFIC ──────────────────────────────────────────────────────
  {
    id: 'SEC070',
    name: 'Python pickle.loads() — Arbitrary Code',
    severity: 'error',
    pattern: /pickle\.loads?\s*\(/g,
    message: () => 'pickle.load() can execute arbitrary code during deserialization. Never unpickle untrusted data.',
    tags: ['deserialization', 'python'],
  },
  {
    id: 'SEC071',
    name: 'Python os.system() Call',
    severity: 'error',
    pattern: /os\.system\s*\(/g,
    message: () => 'os.system() is vulnerable to shell injection. Use subprocess.run() with a list of arguments and shell=False.',
    tags: ['injection', 'python'],
  },
  {
    id: 'SEC072',
    name: 'Python exec() Usage',
    severity: 'error',
    pattern: /\bexec\s*\(/g,
    message: () => 'exec() executes arbitrary Python code. Avoid with any dynamic or user-supplied content.',
    tags: ['injection', 'python'],
  },
  {
    id: 'SEC073',
    name: 'Python yaml.load() Without Loader',
    severity: 'error',
    pattern: /yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader)/g,
    message: () => 'yaml.load() without a Loader can execute arbitrary code. Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).',
    tags: ['deserialization', 'python'],
  },
  {
    id: 'SEC074',
    name: 'Python subprocess with shell=True',
    severity: 'error',
    pattern: /subprocess\.(?:run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True/gi,
    message: () => 'subprocess with shell=True enables shell injection. Pass arguments as a list and use shell=False.',
    tags: ['injection', 'python'],
  },

  // ─── AUTHENTICATION ───────────────────────────────────────────────────────
  {
    id: 'SEC080',
    name: 'Hardcoded Admin Credentials',
    severity: 'error',
    pattern: /(?:username|user|login)\s*[:=]\s*['\"`](?:admin|root|administrator|superuser)['\"`]/gi,
    message: () => 'Default or hardcoded admin username detected. Remove before deploying to production.',
    tags: ['authentication', 'credentials'],
  },
  {
    id: 'SEC081',
    name: 'JWT Algorithm None',
    severity: 'error',
    pattern: /algorithm\s*:\s*['\"`]none['\"`]/gi,
    message: () => 'JWT "none" algorithm disables signature verification — critical authentication bypass vulnerability.',
    tags: ['authentication', 'jwt'],
  },
  {
    id: 'SEC082',
    name: 'Timing Attack — String Comparison',
    severity: 'info',
    pattern: /(?:token|secret|hash|password|hmac)\s*===?\s*(?:req\.|request\.|input\.|provided)/gi,
    message: () => 'Direct string comparison of secrets is vulnerable to timing attacks. Use a constant-time comparison function.',
    tags: ['authentication', 'timing-attack'],
  },
  {
    id: 'SEC083',
    name: 'Missing Rate Limiting on Auth Endpoint',
    severity: 'warning',
    pattern: /(?:router|app)\.post\s*\(\s*['\"`]\/(?:login|signin|auth|token)['\"`]\s*,(?![\s\S]{0,200}(?:rateLimit|rateLimiter|throttle|limiter))/gi,
    message: () => 'Auth endpoint without apparent rate limiting. Brute-force attacks are trivial without rate limits.',
    tags: ['authentication', 'brute-force'],
  },
  {
    id: 'SEC084',
    name: 'Session Secret Hardcoded',
    severity: 'error',
    pattern: /(?:secret|resave|saveUninitialized)\s*:\s*['\"`][^'\"`\s]{6,}['\"`]/gi,
    message: () => 'Session secret appears to be hardcoded. Use a long random secret stored in an environment variable.',
    tags: ['authentication', 'sessions'],
  },

  // ─── MISCELLANEOUS ────────────────────────────────────────────────────────
  {
    id: 'SEC090',
    name: 'Hardcoded IP Address',
    severity: 'info',
    pattern: /['\"`]\b(?:\d{1,3}\.){3}\d{1,3}\b['\"`]/g,
    message: (match) => `Hardcoded IP address: ${match}. Use configuration or DNS names for flexibility.`,
    tags: ['configuration'],
  },
  {
    id: 'SEC091',
    name: 'console.log with Sensitive Data',
    severity: 'warning',
    pattern: /console\.(?:log|info|debug)\s*\([^)]*(?:password|token|secret|key|auth|credential)/gi,
    message: () => 'Sensitive data may be logged to console. Remove before production or use a secure logger with redaction.',
    tags: ['information-disclosure'],
  },
  {
    id: 'SEC092',
    name: 'Deserialization of Untrusted JSON',
    severity: 'error',
    pattern: /JSON\.parse\s*\(\s*(?:req\.|request\.|params\.|body\.|input\.|userInput)/gi,
    message: () => 'Parsing user-supplied JSON without validation — prototype pollution or DoS risk. Validate schema after parsing.',
    tags: ['deserialization'],
  },
  {
    id: 'SEC093',
    name: 'Regular Expression DoS (ReDoS)',
    severity: 'warning',
    pattern: /new RegExp\s*\(\s*(?:req\.|request\.|input\.|params\.|body\.)/gi,
    message: () => 'RegExp built from user input can cause ReDoS attacks. Validate or sanitize inputs before regex construction.',
    tags: ['dos', 'regex'],
  },
  {
    id: 'SEC094',
    name: 'Directory Listing Enabled',
    severity: 'warning',
    pattern: /(?:serveIndex|express\.static|serve-index)\s*\([^)]*\{\s*[^}]*icons\s*:/gi,
    message: () => 'Directory listing may be enabled. This exposes file structure to attackers. Disable unless intentional.',
    tags: ['information-disclosure', 'configuration'],
  },
  {
    id: 'SEC095',
    name: 'Insecure Cookie (missing Secure/HttpOnly)',
    severity: 'warning',
    pattern: /res\.cookie\s*\([^)]+\)(?![\s\S]{0,100}(?:secure|httpOnly|sameSite))/gi,
    message: () => 'Cookie set without Secure, HttpOnly, or SameSite flags. Add { secure: true, httpOnly: true, sameSite: "strict" }.',
    tags: ['cookies', 'session'],
  },
  {
    id: 'SEC096',
    name: 'XML External Entity (XXE) Risk',
    severity: 'error',
    pattern: /(?:DOMParser|SAXParser|XMLParser|parseXML|xml2js)\.parse\s*\([^)]*(?:req\.|request\.|body\.|input\.)/gi,
    message: () => 'XML parsing from user input without XXE protection. Disable external entity processing in your XML parser.',
    tags: ['xxe', 'injection'],
  },
  {
    id: 'SEC097',
    name: 'Unrestricted File Extension in Upload',
    severity: 'error',
    pattern: /(?:originalname|filename)\s*\.split\s*\(['\"`]\.['\"`]\)(?![\s\S]{0,200}(?:whitelist|allowlist|allowed|\.(?:jpg|png|pdf)))/gi,
    message: () => 'File extension extracted without apparent allowlist check. Validate against a strict allowlist of permitted extensions.',
    tags: ['file-upload', 'validation'],
  },
  {
    id: 'SEC098',
    name: 'Missing CSRF Protection',
    severity: 'warning',
    pattern: /(?:router|app)\.post\s*\(\s*['\"`][^'\"`]+['\"`]\s*,(?![\s\S]{0,400}(?:csrf|csurf|csrfToken|_csrf|xsrf))/gi,
    message: () => 'POST route without apparent CSRF protection. Use csurf middleware or SameSite cookies.',
    tags: ['csrf'],
  },
];

function analyzeSecurityIssues(text, filePath) {
  const issues = [];
  const lines = text.split('\n');

  for (const rule of SECURITY_RULES) {
    rule.pattern.lastIndex = 0;
    const patternCopy = new RegExp(rule.pattern.source, rule.pattern.flags);
    let match;

    while ((match = patternCopy.exec(text)) !== null) {
      const position = match.index;
      const lineNumber = text.substring(0, position).split('\n').length - 1;
      const lineText = lines[lineNumber] || '';
      const colStart = position - text.substring(0, position).lastIndexOf('\n') - 1;

      const trimmedLine = lineText.trim();
      if (trimmedLine.startsWith('//') || trimmedLine.startsWith('#') || trimmedLine.startsWith('*')) {
        continue;
      }

      issues.push({
        ruleId: rule.id,
        name: rule.name,
        category: 'security',
        severity: rule.severity,
        message: rule.message(match[0]),
        line: lineNumber,
        column: Math.max(0, colStart),
        endColumn: Math.max(0, colStart) + match[0].length,
        lineText: lineText.trim(),
        tags: rule.tags,
        fix: getFix(rule.id),
      });
    }
  }

  return issues;
}

function getFix(ruleId) {
  const fixes = {
    'SEC001': 'Use process.env.DB_PASSWORD or a secrets manager.',
    'SEC002': 'Move to environment variables: process.env.API_KEY',
    'SEC010': 'Replace eval() with JSON.parse() or a safe parser.',
    'SEC013': 'Use execFile(cmd, [args]) to avoid shell injection.',
    'SEC014': 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = ?", [id])',
    'SEC015': 'Use parameterized queries or a query builder — never interpolate user data into SQL.',
    'SEC020': 'Use element.textContent = value or DOMPurify.sanitize(html)',
    'SEC025': 'Remove javascript: URI; use addEventListener("click", ...) instead.',
    'SEC030': 'Use crypto.getRandomValues(new Uint32Array(1))[0]',
    'SEC031': 'Use crypto.createHash("sha256")',
    'SEC034': 'Use AES-256-GCM: crypto.createCipheriv("aes-256-gcm", key, iv)',
    'SEC040': 'Change to https:// URL',
    'SEC041': 'Remove rejectUnauthorized: false — fix the certificate instead.',
    'SEC050': 'Use path.resolve() + ensure the result starts with your allowed base directory.',
    'SEC070': 'Replace with json.loads() or a safe serialization format.',
    'SEC073': 'Use yaml.safe_load(data) instead.',
    'SEC074': 'Use subprocess.run(["cmd", "arg1"], shell=False)',
    'SEC081': 'Always specify algorithm explicitly: { algorithms: ["HS256"] }',
    'SEC092': 'Validate parsed JSON against a schema (e.g., ajv, joi, zod).',
  };
  return fixes[ruleId] || null;
}

module.exports = { analyzeSecurityIssues, SECURITY_RULES };
