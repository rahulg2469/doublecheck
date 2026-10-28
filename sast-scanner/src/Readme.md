# SAST Scanner

A Static Application Security Testing (SAST) scanner for Node.js applications. This scanner detects common security vulnerabilities in JavaScript/Node.js source code.

## Vulnerabilities Detected

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| HARDCODED_SECRET | Hardcoded Secrets | HIGH | API keys, passwords, tokens in source code |
| SQL_INJECTION | SQL Injection Risk | HIGH | String concatenation in SQL queries |
| HARDCODED_IP | Hardcoded IP Address | MEDIUM | IP addresses that should be configurable |
| INSECURE_FUNCTION | Insecure Function Usage | HIGH | Dangerous functions like eval(), exec() |
| SECURITY_TODO | Security TODO/FIXME | LOW | Security-related comments needing attention |
| WEAK_CRYPTO | Weak Cryptography | MEDIUM | MD5, SHA1, or deprecated crypto functions |

## Setup

```bash
# Install dependencies
npm install

# Start the server
node server.js
```

The server will start on port 3000 (or PORT environment variable).

## API Endpoints

### Health Check
```
GET /health
```
Returns server status.

### List Vulnerability Types
```
GET /vulnerabilities
```
Returns all supported vulnerability checks.

### Scan Code Snippet
```
POST /scan/code
Content-Type: application/json

{
  "code": "const password = 'secret123';",
  "filename": "app.js"
}
```

### Scan a File
```
POST /scan/file
Content-Type: application/json

{
  "filepath": "./test-vulnerable.js"
}
```

### Scan a Directory
```
POST /scan/directory
Content-Type: application/json

{
  "dirpath": "./src"
}
```

## Example Response

```json
{
  "success": true,
  "filename": "app.js",
  "scannedAt": "2026-01-15T10:30:00.000Z",
  "summary": {
    "totalVulnerabilities": 3,
    "high": 2,
    "medium": 1,
    "low": 0
  },
  "vulnerabilities": [
    {
      "id": "HARDCODED_SECRET",
      "name": "Hardcoded Secret",
      "severity": "HIGH",
      "description": "Hardcoded password",
      "message": "Hardcoded secret detected. Move secrets to environment variables.",
      "file": "app.js",
      "line": 5,
      "column": 7,
      "evidence": "const password = 'secret123';"
    }
  ]
}
```

## Testing

Use the included `test-vulnerable.js` file to test the scanner:

```bash
# Start the server
node server.js

# In another terminal, scan the test file
curl -X POST http://localhost:3000/scan/file \
  -H "Content-Type: application/json" \
  -d '{"filepath": "./test-vulnerable.js"}'
```

## Project Structure

```
sast-scanner/
├── server.js           # Express server with API endpoints
├── scanner.js          # Core scanning logic
├── package.json        # Dependencies and scripts
├── test-vulnerable.js  # Sample vulnerable code for testing
└── README.md           # This file
```