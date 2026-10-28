import fs from 'fs';
import path from 'path';

// Vulnerability detection patterns
const vulnerabilityRules = [
  {
    id: 'HARDCODED_SECRET',
    name: 'Hardcoded Secret',
    severity: 'HIGH',
    patterns: [
      { regex: /(?:api[_-]?key|apikey)\s*[:=]\s*['"][a-zA-Z0-9]{16,}['"]/gi, desc: 'Hardcoded API key' },
      { regex: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]/gi, desc: 'Hardcoded password' },
      { regex: /(?:secret[_-]?key|secretkey)\s*[:=]\s*['"][a-zA-Z0-9]{16,}['"]/gi, desc: 'Hardcoded secret key' },
      { regex: /(?:access[_-]?token|accesstoken)\s*[:=]\s*['"][a-zA-Z0-9]{16,}['"]/gi, desc: 'Hardcoded access token' },
      { regex: /(?:aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*['"][A-Z0-9]{20}['"]/gi, desc: 'AWS Access Key ID' },
      { regex: /(?:aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]/gi, desc: 'AWS Secret Access Key' },
      { regex: /['"]sk[_-]live[_-][a-zA-Z0-9]{24,}['"]/g, desc: 'Stripe secret key' },
      { regex: /['"]ghp_[a-zA-Z0-9]{36,}['"]/g, desc: 'GitHub personal access token' }
    ],
    message: 'Hardcoded secret detected. Move secrets to environment variables.'
  },
  {
    id: 'NOSQL_INJECTION',
    name: 'NoSQL Injection Risk',
    severity: 'HIGH',
    patterns: [
      { regex: /\.\s*find\s*\(\s*\{[^}]*\$where/gi, desc: '$where operator in MongoDB query' },
      { regex: /\.\s*find\s*\(\s*\{[^}]*\$regex\s*:\s*[^/'"]/gi, desc: 'Unsanitized $regex in query' },
      { regex: /\.\s*find\s*\(\s*req\.(body|query|params)/gi, desc: 'Direct user input in MongoDB find()' },
      { regex: /\.\s*findOne\s*\(\s*req\.(body|query|params)/gi, desc: 'Direct user input in MongoDB findOne()' },
      { regex: /\.\s*updateOne\s*\(\s*req\.(body|query|params)/gi, desc: 'Direct user input in MongoDB updateOne()' },
      { regex: /\.\s*deleteOne\s*\(\s*req\.(body|query|params)/gi, desc: 'Direct user input in MongoDB deleteOne()' }
    ],
    message: 'Potential NoSQL injection vulnerability. Sanitize user input before using in database queries.'
  },
  {
    id: 'XSS',
    name: 'Cross-Site Scripting (XSS)',
    severity: 'HIGH',
    patterns: [
      { regex: /\.innerHTML\s*=\s*[^'"]/gi, desc: 'Dynamic innerHTML assignment' },
      { regex: /\.outerHTML\s*=\s*[^'"]/gi, desc: 'Dynamic outerHTML assignment' },
      { regex: /document\.write\s*\(/gi, desc: 'Usage of document.write()' },
      { regex: /document\.writeln\s*\(/gi, desc: 'Usage of document.writeln()' },
      { regex: /\.insertAdjacentHTML\s*\(/gi, desc: 'Usage of insertAdjacentHTML()' },
      { regex: /dangerouslySetInnerHTML/gi, desc: 'React dangerouslySetInnerHTML usage' }
    ],
    message: 'Potential XSS vulnerability. Sanitize user input before rendering in HTML.'
  },
  {
    id: 'PATH_TRAVERSAL',
    name: 'Path Traversal',
    severity: 'HIGH',
    patterns: [
      { regex: /fs\.(readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync)\s*\(\s*req\.(body|query|params)/gi, desc: 'User input directly in file operation' },
      { regex: /fs\.(readFile|readFileSync|writeFile|writeFileSync)\s*\([^)]*\+\s*req\./gi, desc: 'User input concatenated in file path' },
      { regex: /path\.join\s*\([^)]*req\.(body|query|params)/gi, desc: 'User input in path.join()' },
      { regex: /['"][^'"]*\.\.\/[^'"]*['"]/g, desc: 'Path traversal sequence detected' }
    ],
    message: 'Potential path traversal vulnerability. Validate and sanitize file paths.'
  },
  {
    id: 'INSECURE_RANDOM',
    name: 'Insecure Randomness',
    severity: 'MEDIUM',
    patterns: [
      { regex: /Math\.random\s*\(\s*\)/g, desc: 'Math.random() is not cryptographically secure' },
      { regex: /Math\.random\s*\(\s*\).*(?:token|password|secret|key|auth|session)/gi, desc: 'Math.random() used for security-sensitive value' }
    ],
    message: 'Math.random() is not cryptographically secure. Use crypto.randomBytes() or crypto.randomUUID() instead.'
  },
  {
    id: 'SENSITIVE_DATA_LOG',
    name: 'Sensitive Data Logging',
    severity: 'MEDIUM',
    patterns: [
      { regex: /console\.(log|info|debug|warn|error)\s*\([^)]*(?:password|passwd|pwd)[^)]*\)/gi, desc: 'Logging password' },
      { regex: /console\.(log|info|debug|warn|error)\s*\([^)]*(?:token|secret|apikey|api_key)[^)]*\)/gi, desc: 'Logging sensitive token/key' },
      { regex: /console\.(log|info|debug|warn|error)\s*\([^)]*(?:creditcard|credit_card|ssn|social_security)[^)]*\)/gi, desc: 'Logging sensitive personal data' }
    ],
    message: 'Sensitive data may be logged. Remove or mask sensitive information in logs.'
  },
  {
    id: 'SQL_INJECTION',
    name: 'SQL Injection Risk',
    severity: 'HIGH',
    patterns: [
      { regex: /query\s*\(\s*['"`]SELECT.*\+/gi, desc: 'String concatenation in SELECT query' },
      { regex: /query\s*\(\s*['"`]INSERT.*\+/gi, desc: 'String concatenation in INSERT query' },
      { regex: /query\s*\(\s*['"`]UPDATE.*\+/gi, desc: 'String concatenation in UPDATE query' },
      { regex: /query\s*\(\s*['"`]DELETE.*\+/gi, desc: 'String concatenation in DELETE query' },
      { regex: /execute\s*\(\s*['"`].*\$\{/gi, desc: 'Template literal in SQL execute' },
      { regex: /query\s*\(\s*`[^`]*\$\{/gi, desc: 'Template literal in SQL query' }
    ],
    message: 'Potential SQL injection vulnerability. Use parameterized queries instead.'
  },
  {
    id: 'HARDCODED_IP',
    name: 'Hardcoded IP Address',
    severity: 'MEDIUM',
    patterns: [
      { regex: /['"](?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)['"]/g, desc: 'Hardcoded IPv4 address' },
      { regex: /['"](?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\d+['"]/g, desc: 'Hardcoded IP with port' }
    ],
    message: 'Hardcoded IP address found. Use environment variables or configuration files.'
  },
  {
    id: 'INSECURE_FUNCTION',
    name: 'Insecure Function Usage',
    severity: 'HIGH',
    patterns: [
      { regex: /\beval\s*\(/g, desc: 'Usage of eval()' },
      { regex: /\bexec\s*\(/g, desc: 'Usage of exec()' },
      { regex: /\bexecSync\s*\(/g, desc: 'Usage of execSync()' },
      { regex: /\bspawn\s*\([^)]*\$\{/g, desc: 'Unvalidated input in spawn()' },
      { regex: /new\s+Function\s*\(/g, desc: 'Usage of new Function()' },
      { regex: /child_process.*exec/g, desc: 'child_process exec usage' }
    ],
    message: 'Insecure function detected. These functions can execute arbitrary code.'
  },
  {
    id: 'SECURITY_TODO',
    name: 'Security TODO/FIXME',
    severity: 'LOW',
    patterns: [
      { regex: /\/\/\s*TODO:?\s*.*(?:security|auth|password|token|secret|vuln|hack|fix)/gi, desc: 'Security-related TODO comment' },
      { regex: /\/\/\s*FIXME:?\s*.*(?:security|auth|password|token|secret|vuln|hack)/gi, desc: 'Security-related FIXME comment' },
      { regex: /\/\/\s*XXX:?\s*.*(?:security|auth|password|token|secret|vuln|hack)/gi, desc: 'Security-related XXX comment' },
      { regex: /\/\/\s*HACK:?\s*.*/gi, desc: 'HACK comment found' },
      { regex: /\/\*[\s\S]*?(?:security|vulnerability|TODO:?\s*auth)[\s\S]*?\*\//gi, desc: 'Security note in block comment' }
    ],
    message: 'Security-related comment found. Ensure this is addressed before production.'
  },
  {
    id: 'WEAK_CRYPTO',
    name: 'Weak Cryptography',
    severity: 'MEDIUM',
    patterns: [
      { regex: /createHash\s*\(\s*['"]md5['"]\s*\)/gi, desc: 'MD5 hash usage' },
      { regex: /createHash\s*\(\s*['"]sha1['"]\s*\)/gi, desc: 'SHA1 hash usage' },
      { regex: /crypto\.createCipher\s*\(/g, desc: 'Deprecated createCipher usage' },
      { regex: /crypto\.createDecipher\s*\(/g, desc: 'Deprecated createDecipher usage' },
      { regex: /DES|RC4|RC2|Blowfish/gi, desc: 'Weak encryption algorithm' }
    ],
    message: 'Weak cryptographic algorithm detected. Use stronger alternatives like SHA256 or AES-256.'
  }
];

// Get line number from character index
const getLineNumber = (code, index) => {
  return code.substring(0, index).split('\n').length;
};

// Get the actual line content
const getLineContent = (code, lineNumber) => {
  const lines = code.split('\n');
  return lines[lineNumber - 1]?.trim() || '';
};

// Scan code string for vulnerabilities
export const scanCode = (code, filename = 'untitled.js') => {
  const vulnerabilities = [];

  for (const rule of vulnerabilityRules) {
    for (const pattern of rule.patterns) {
      let match;
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      
      while ((match = regex.exec(code)) !== null) {
        const lineNumber = getLineNumber(code, match.index);
        const lineContent = getLineContent(code, lineNumber);
        
        vulnerabilities.push({
          id: rule.id,
          name: rule.name,
          severity: rule.severity,
          description: pattern.desc,
          message: rule.message,
          file: filename,
          line: lineNumber,
          column: match.index - code.lastIndexOf('\n', match.index - 1),
          evidence: lineContent.length > 100 ? lineContent.substring(0, 100) + '...' : lineContent
        });
      }
    }
  }

  // Sort by severity (HIGH > MEDIUM > LOW) then by line number
  const severityOrder = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  vulnerabilities.sort((a, b) => {
    if (severityOrder[a.severity] !== severityOrder[b.severity]) {
      return severityOrder[a.severity] - severityOrder[b.severity];
    }
    return a.line - b.line;
  });

  return vulnerabilities;
};

// Scan a file for vulnerabilities
export const scanFile = (filepath) => {
  if (!fs.existsSync(filepath)) {
    throw new Error(`File not found: ${filepath}`);
  }

  const code = fs.readFileSync(filepath, 'utf-8');
  return scanCode(code, filepath);
};

// Scan a directory recursively
export const scanDirectory = (dirpath, extensions = ['.js', '.mjs', '.cjs', '.ts']) => {
  if (!fs.existsSync(dirpath)) {
    throw new Error(`Directory not found: ${dirpath}`);
  }

  const results = {};

  const scanDir = (currentPath) => {
    const entries = fs.readdirSync(currentPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);

      // Skip node_modules and hidden directories
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name.startsWith('.')) {
          continue;
        }
        scanDir(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (extensions.includes(ext)) {
          const vulnerabilities = scanFile(fullPath);
          if (vulnerabilities.length > 0) {
            results[fullPath] = vulnerabilities;
          }
        }
      }
    }
  };

  scanDir(dirpath);
  return results;
};

export default { scanCode, scanFile, scanDirectory };