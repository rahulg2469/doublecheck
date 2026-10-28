import express from 'express';
import cors from 'cors';
import { scanCode, scanFile, scanDirectory } from './scanner.js';

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    service: 'SAST Scanner',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// Scan code directly (pass code as string in request body)
app.post('/scan/code', (req, res) => {
  try {
    const { code, filename = 'untitled.js' } = req.body;
    
    if (!code) {
      return res.status(400).json({ 
        error: 'No code provided',
        message: 'Please provide code in the request body'
      });
    }

    const results = scanCode(code, filename);
    
    res.json({
      success: true,
      filename,
      scannedAt: new Date().toISOString(),
      summary: {
        totalVulnerabilities: results.length,
        high: results.filter(v => v.severity === 'HIGH').length,
        medium: results.filter(v => v.severity === 'MEDIUM').length,
        low: results.filter(v => v.severity === 'LOW').length
      },
      vulnerabilities: results
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Scan failed', 
      message: error.message 
    });
  }
});

// Scan a specific file on the server
app.post('/scan/file', (req, res) => {
  try {
    const { filepath } = req.body;
    
    if (!filepath) {
      return res.status(400).json({ 
        error: 'No filepath provided',
        message: 'Please provide filepath in the request body'
      });
    }

    const results = scanFile(filepath);
    
    res.json({
      success: true,
      filepath,
      scannedAt: new Date().toISOString(),
      summary: {
        totalVulnerabilities: results.length,
        high: results.filter(v => v.severity === 'HIGH').length,
        medium: results.filter(v => v.severity === 'MEDIUM').length,
        low: results.filter(v => v.severity === 'LOW').length
      },
      vulnerabilities: results
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Scan failed', 
      message: error.message 
    });
  }
});

// Scan an entire directory
app.post('/scan/directory', (req, res) => {
  try {
    const { dirpath } = req.body;
    
    if (!dirpath) {
      return res.status(400).json({ 
        error: 'No directory path provided',
        message: 'Please provide dirpath in the request body'
      });
    }

    const results = scanDirectory(dirpath);
    
    const allVulnerabilities = Object.values(results).flat();
    
    res.json({
      success: true,
      dirpath,
      scannedAt: new Date().toISOString(),
      summary: {
        filesScanned: Object.keys(results).length,
        totalVulnerabilities: allVulnerabilities.length,
        high: allVulnerabilities.filter(v => v.severity === 'HIGH').length,
        medium: allVulnerabilities.filter(v => v.severity === 'MEDIUM').length,
        low: allVulnerabilities.filter(v => v.severity === 'LOW').length
      },
      results
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Scan failed', 
      message: error.message 
    });
  }
});

// List supported vulnerability checks
app.get('/vulnerabilities', (req, res) => {
  res.json({
    supported: [
      {
        id: 'HARDCODED_SECRET',
        name: 'Hardcoded Secrets',
        severity: 'HIGH',
        description: 'Detects API keys, passwords, and tokens hardcoded in source code'
      },
      {
        id: 'SQL_INJECTION',
        name: 'SQL Injection Risk',
        severity: 'HIGH',
        description: 'Detects potential SQL injection vulnerabilities from string concatenation'
      },
      {
        id: 'NOSQL_INJECTION',
        name: 'NoSQL Injection Risk',
        severity: 'HIGH',
        description: 'Detects potential NoSQL/MongoDB injection vulnerabilities'
      },
      {
        id: 'XSS',
        name: 'Cross-Site Scripting (XSS)',
        severity: 'HIGH',
        description: 'Detects potential XSS vulnerabilities like innerHTML, document.write'
      },
      {
        id: 'PATH_TRAVERSAL',
        name: 'Path Traversal',
        severity: 'HIGH',
        description: 'Detects potential path traversal vulnerabilities in file operations'
      },
      {
        id: 'HARDCODED_IP',
        name: 'Hardcoded IP Address',
        severity: 'MEDIUM',
        description: 'Detects hardcoded IP addresses that should be configurable'
      },
      {
        id: 'INSECURE_FUNCTION',
        name: 'Insecure Function Usage',
        severity: 'HIGH',
        description: 'Detects usage of dangerous functions like eval() and exec()'
      },
      {
        id: 'INSECURE_RANDOM',
        name: 'Insecure Randomness',
        severity: 'MEDIUM',
        description: 'Detects usage of Math.random() for security-sensitive operations'
      },
      {
        id: 'SENSITIVE_DATA_LOG',
        name: 'Sensitive Data Logging',
        severity: 'MEDIUM',
        description: 'Detects logging of sensitive data like passwords and tokens'
      },
      {
        id: 'SECURITY_TODO',
        name: 'Security TODO/FIXME',
        severity: 'LOW',
        description: 'Detects TODO or FIXME comments related to security'
      },
      {
        id: 'WEAK_CRYPTO',
        name: 'Weak Cryptography',
        severity: 'MEDIUM',
        description: 'Detects usage of weak cryptographic algorithms like MD5 or SHA1'
      }
    ]
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`
  ╔═══════════════════════════════════════════╗
  ║         SAST Scanner Server               ║
  ║         Running on port ${PORT}              ║
  ╚═══════════════════════════════════════════╝
  
  Endpoints:
  - GET  /health          - Health check
  - GET  /vulnerabilities - List supported checks
  - POST /scan/code       - Scan code snippet
  - POST /scan/file       - Scan a file
  - POST /scan/directory  - Scan a directory
  `);
});